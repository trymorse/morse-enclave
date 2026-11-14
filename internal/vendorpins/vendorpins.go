// Package vendorpins keeps the enclave's vendor pins (Phala, NEAR, Tinfoil) current without a rebuild. The
// enclave boots with the pins compiled into it and, while it runs, polls vendor/index.json on the
// statements/images branch of the public pins repository, with no credentials. It walks the index's
// candidates in order and takes the first whose vendor statement verifies offline under the pinned Sigstore
// signer, its Rekor v2 entry cosigned by enough witnesses, was signed within the age limit by a clock the
// host cannot move, and has a sequence above the active set's. Each file the statement digests is then read
// at the statement's pins_commit and must hash to the digest it lists. A candidate refused on the way is
// logged, and with none taken the active set stays. Unsigned data is never parsed.
package vendorpins

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"morse/backend/internal/attestation"
	"morse/backend/internal/pinsbranch"
	"morse/backend/internal/pinsig"
	"morse/backend/internal/sigstore/rekorv2"
	"morse/backend/internal/upstream"
)

// Mode is what the loader does with a release it admits.
type Mode string

const (
	// Off never fetches.
	Off Mode = "off"
	// Log verifies and logs exactly what Enforce would swap, with the difference in pin counts, and swaps nothing.
	Log Mode = "log"
	// Enforce swaps the active set.
	Enforce Mode = "enforce"
)

// ParseMode reads a mode flag or variable. Empty is Log.
func ParseMode(s string) (Mode, error) {
	switch m := Mode(s); m {
	case "":
		return Log, nil
	case Off, Log, Enforce:
		return m, nil
	}
	return "", fmt.Errorf("vendor pins mode %q is not off, log or enforce", s)
}

const (
	vendorDir = "vendor"

	maxStatement = 128 << 10
	maxFile      = 4 << 20
	pollEvery    = 10 * time.Minute
	pollTimeout  = 2 * time.Minute
)

type Kind uint8

const (
	// Failed is a poll that fetched, verified or admitted nothing. The active set stays.
	Failed Kind = iota
	// WouldSwap is Log mode's report of the swap Enforce would make.
	WouldSwap
	// Swapped is the active set replaced.
	Swapped
)

type Event struct {
	Kind Kind
	From attestation.VendorSource
	To   attestation.VendorSource
	// Diff is the change in pin counts from the active set to the new one.
	Diff string
	Err  error
}

type Config struct {
	Mode   Mode
	Client *http.Client
	// GitURL and RawURL override pinsbranch.GitURL and pinsbranch.RawURL. Requests go to those two and
	// follow no redirect.
	GitURL   string
	RawURL   string
	Root     pinsig.TrustRoot
	Identity pinsig.Identity
	// Witnesses count the cosignatures a vendor statement's Rekor v2 entry needs.
	Witnesses rekorv2.WitnessPolicy
	MaxAge    time.Duration
	// Floor is the sequence the image was built at. The embedded files are at or below it, so a statement at
	// or below it cannot be newer than them.
	Floor uint64
	// Now is the trusted time, from a source the host cannot move, such as the NSM attestation document's.
	Now func(context.Context) (time.Time, error)
	// Observe hears every failure, would-be swap and swap.
	Observe func(Event)
	// OnSwap runs after a swap, so the gates verify against the new pins at once.
	OnSwap func()
	// Every overrides the poll interval.
	Every time.Duration
}

type Loader struct {
	Config
	// reported is the newest sequence Log mode has reported, so it says so once.
	reported         atomic.Uint64
	newestUnverified atomic.Uint64
	behindSince      atomic.Int64
}

type Lag struct {
	Newest uint64
	Taken  uint64
	Behind time.Duration
}

func (l *Loader) Lag() (Lag, bool) {
	newest := l.newestUnverified.Load()
	if l.Mode == Off || newest == 0 {
		return Lag{}, false
	}
	lag := Lag{Newest: newest, Taken: l.floor()}
	if since := l.behindSince.Load(); since != 0 && lag.Newest > lag.Taken {
		lag.Behind = time.Since(time.Unix(0, since))
	}
	return lag, true
}

func New(c Config) *Loader {
	if c.Every == 0 {
		c.Every = pollEvery
	}
	return &Loader{Config: c}
}

// Run polls until ctx ends.
func (l *Loader) Run(ctx context.Context) {
	if l.Mode == Off {
		return
	}
	for {
		l.Poll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(l.Every):
		}
	}
}

// Poll walks the index once and acts on the first candidate it admits as the mode says. Polls must not overlap.
func (l *Loader) Poll(ctx context.Context) {
	if l.Mode == Off {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, pollTimeout)
	defer cancel()
	if err := l.once(ctx); err != nil && !errors.Is(err, errNotNewer) {
		l.observe(Event{Kind: Failed, From: attestation.Vendors().Source, Err: err})
	}
}

var (
	errNotNewer = errors.New("vendorpins: no newer statement")
	errNoTime   = errors.New("no trusted time")
)

func (l *Loader) floor() uint64 {
	return max(attestation.Vendors().Source.Sequence, l.Floor, l.reported.Load())
}

func (l *Loader) branch() pinsbranch.Reader {
	return pinsbranch.Reader{Git: l.GitURL, Raw: l.RawURL, Do: func(req *http.Request) (*http.Response, error) { return upstream.Do(l.Client, req) }}
}

// once reads every candidate at the one commit the branch's tip names now, so a statement signed mid-poll
// cannot mix its files with another's. The index lists the highest sequence first, so a candidate no newer
// than the active set ends the walk.
func (l *Loader) once(ctx context.Context) error {
	branch := l.branch()
	commit, err := branch.Tip(ctx)
	if err != nil {
		return err
	}
	candidates, err := branch.Index(ctx, commit, vendorDir)
	if err != nil {
		return err
	}
	var now time.Time
	clock := func() (time.Time, error) {
		if now.IsZero() {
			t, err := l.Now(ctx)
			if err != nil {
				return time.Time{}, fmt.Errorf("%w: %w", errNoTime, err)
			}
			now = t
		}
		return now, nil
	}
	var newest uint64
	defer func() {
		if newest == 0 {
			return
		}
		if newest <= l.floor() {
			l.behindSince.Store(0)
		} else if l.behindSince.Load() == 0 {
			l.behindSince.Store(time.Now().UnixNano())
		}
		l.newestUnverified.Store(newest)
	}()
	for i, c := range candidates {
		seen, err := l.take(ctx, branch, commit, c, clock)
		if i == 0 {
			newest = seen
		}
		if err == nil || errors.Is(err, errNotNewer) || errors.Is(err, errNoTime) {
			return err
		}
		l.observe(Event{Kind: Failed, From: attestation.Vendors().Source, Err: fmt.Errorf("%s: %w", c.Name, err)})
	}
	return nil
}

func (l *Loader) take(ctx context.Context, branch pinsbranch.Reader, commit string, c pinsbranch.Candidate, clock func() (time.Time, error)) (seen uint64, err error) {
	statement, err := branch.File(ctx, commit, c.Statement, maxStatement)
	if err != nil {
		return seen, err
	}
	if unverified, err := pinsig.ParseVendorStatement(statement); err == nil {
		seen = unverified.Sequence
		if seen <= l.floor() {
			return seen, errNotNewer
		}
	}
	bundle, err := branch.File(ctx, commit, c.Bundle, maxStatement)
	if err != nil {
		return seen, err
	}
	st, signed, err := pinsig.VerifyVendor(statement, bundle, l.Root, l.Identity, l.Witnesses)
	if err != nil {
		return seen, err
	}
	now, err := clock()
	if err != nil {
		return seen, err
	}
	// The active sequence must be strictly below the statement's, and Admit's floor is inclusive.
	if err := pinsig.AdmitVendor(st, l.floor()+1, signed, now, l.MaxAge); err != nil {
		return seen, err
	}
	// The files are read at the main commit the signer built from, which VerifyVendor bound to the statement.
	var canonical [len(pinsig.VendorFiles)][]byte
	for i, key := range pinsig.VendorFiles {
		path, err := publicPath(key)
		if err != nil {
			return seen, err
		}
		raw, err := branch.File(ctx, st.PinsCommit, path, maxFile)
		if err != nil {
			return seen, err
		}
		if canonical[i], err = st.CheckFile(key, raw); err != nil {
			return seen, err
		}
	}
	sum := sha256.Sum256(statement)
	// The signer vouched for the JCS bytes, so those are what the pins parse from. The fourth file,
	// phala_model_pins.json, is for the app's models list; nothing here parses it.
	next, err := attestation.ParseVendorSet(canonical[0], canonical[1], canonical[2], attestation.VendorSource{Sequence: st.Sequence, StatementSHA256: hex.EncodeToString(sum[:])})
	if err != nil {
		return seen, err
	}
	from := attestation.Vendors()
	event := Event{From: from.Source, To: next.Source, Diff: diff(from.Counts(), next.Counts())}
	switch l.Mode {
	case Enforce:
		attestation.SwapVendors(next)
		event.Kind = Swapped
		l.observe(event)
		if l.OnSwap != nil {
			l.OnSwap()
		}
	default:
		l.reported.Store(st.Sequence)
		event.Kind = WouldSwap
		l.observe(event)
	}
	return seen, nil
}

// publicPath is where trymorse/morse-pins holds the file a vendor statement lists under key. As its sign.yml
// says, the vendor statement names each file by its path in the private pins repository, v4/<name>, the key
// every reader of the statement (pinsig.VendorFiles and the check in Morse's apps) expects, and morse-pins
// holds that file at its root. A key without the v4/ prefix is refused rather than guessed at.
func publicPath(key string) (string, error) {
	name, ok := strings.CutPrefix(key, "v4/")
	if !ok {
		return "", fmt.Errorf("vendor statement key %q is not v4/<name>", key)
	}
	return name, nil
}

func (l *Loader) observe(e Event) {
	if l.Observe != nil {
		l.Observe(e)
	}
}

func diff(a, b attestation.VendorCounts) string {
	var parts []string
	for _, c := range []struct {
		name     string
		was, now int
	}{
		{"phala_releases", a.PhalaReleases, b.PhalaReleases},
		{"phala_images", a.PhalaImages, b.PhalaImages},
		{"near_composes", a.NearComposes, b.NearComposes},
		{"near_images", a.NearImages, b.NearImages},
		{"tinfoil_releases", a.TinfoilReleases, b.TinfoilReleases},
	} {
		parts = append(parts, fmt.Sprintf("%s %d->%d", c.name, c.was, c.now))
	}
	return strings.Join(parts, ", ")
}
