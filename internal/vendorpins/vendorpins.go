// Package vendorpins keeps the enclave's vendor pins (Phala, NEAR, Tinfoil) current without a rebuild. The
// enclave boots with the pins compiled into it and, while it runs, polls the newest release of the public
// pins repository. A release replaces the active set only when its vendor statement verifies offline under
// the pinned Sigstore signer, Rekor logged it within the age limit by a clock the host cannot move, its
// sequence is above the active set's, and each of the three files hashes to the digest the statement lists.
// Anything less is logged and the active set stays. Unsigned data is never read.
package vendorpins

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"morse/backend/internal/attestation"
	"morse/backend/internal/pinsig"
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
	// ReleasesURL is the public pins repository's releases. Its latest/download/<asset> redirects to
	// download/<tag>/<asset> of the release sign.yml marks latest, and that redirects to GitHub's asset host.
	ReleasesURL = "https://github.com/trymorse/morse-pins/releases"

	statementAsset = "vendor.statement.json"
	bundleAsset    = "vendor.sigstore.json"

	maxAsset    = 4 << 20
	pollEvery   = 10 * time.Minute
	pollTimeout = 2 * time.Minute
)

// The files a release carries beside the statement, by their path in the statement and their asset name. The
// fourth file the statement digests, phala_model_pins.json, is for the app's models list; nothing here reads it.
var used = [...]string{"v4/phala_pins.json", "v4/near_pins.json", "v4/tinfoil_pins.json"}

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
	// BaseURL overrides ReleasesURL.
	BaseURL  string
	Root     pinsig.TrustRoot
	Identity pinsig.Identity
	MaxAge   time.Duration
	// Floor is the sequence the image was built at. The embedded files are at or below it, so a release at or
	// below it cannot be newer than them.
	Floor uint64
	// Now is the trusted time, from a source the host cannot move, such as the NSM attestation document's.
	Now func(context.Context) (time.Time, error)
	// Observe hears every failure, would-be swap and swap.
	Observe func(Event)
	// OnSwap runs after a swap, so the gates verify against the new pins at once.
	OnSwap func()
	// Redirect admits the one redirect a download may follow. Nil admits https to GitHub's release asset hosts.
	Redirect func(*url.URL) bool
	// Every overrides the poll interval.
	Every time.Duration
}

type Loader struct {
	Config
	// reported is the newest sequence Log mode has reported, so it says so once.
	reported uint64
}

func New(c Config) *Loader {
	if c.BaseURL == "" {
		c.BaseURL = ReleasesURL
	}
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

// Poll fetches the newest release once and acts on it as the mode says. Polls must not overlap.
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

var errNotNewer = errors.New("vendorpins: no newer release")

func (l *Loader) floor() uint64 {
	return max(attestation.Vendors().Source.Sequence, l.Floor, l.reported)
}

func (l *Loader) once(ctx context.Context) error {
	// Every asset comes from the one tag latest names now, so a release published mid-poll cannot mix its files
	// with another's.
	release, err := l.latest(ctx)
	if err != nil {
		return err
	}
	statement, err := l.get(ctx, release, statementAsset)
	if err != nil {
		return err
	}
	// Reading the sequence before the signature only decides whether to fetch more: nothing is trusted until it verifies.
	if peek, err := pinsig.ParseVendorStatement(statement); err == nil && peek.Sequence <= l.floor() {
		return errNotNewer
	}
	bundle, err := l.get(ctx, release, bundleAsset)
	if err != nil {
		return err
	}
	st, logged, err := pinsig.VerifyVendor(statement, bundle, l.Root, l.Identity)
	if err != nil {
		return err
	}
	now, err := l.Now(ctx)
	if err != nil {
		return fmt.Errorf("no trusted time: %w", err)
	}
	// The active sequence must be strictly below the release's, and Admit's floor is inclusive.
	if err := pinsig.AdmitVendor(st, l.floor()+1, logged, now, l.MaxAge); err != nil {
		return err
	}
	var canonical [len(used)][]byte
	for i, path := range used {
		raw, err := l.get(ctx, release, path[strings.LastIndex(path, "/")+1:])
		if err != nil {
			return err
		}
		if canonical[i], err = st.CheckFile(path, raw); err != nil {
			return err
		}
	}
	sum := sha256.Sum256(statement)
	// The signer vouched for the JCS bytes, so those are what the pins parse from.
	next, err := attestation.ParseVendorSet(canonical[0], canonical[1], canonical[2], attestation.VendorSource{Sequence: st.Sequence, StatementSHA256: hex.EncodeToString(sum[:])})
	if err != nil {
		return err
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
		l.reported = st.Sequence
		event.Kind = WouldSwap
		l.observe(event)
	}
	return nil
}

func (l *Loader) observe(e Event) {
	if l.Observe != nil {
		l.Observe(e)
	}
}

// assetHosts serve a release's assets, to which github.com redirects its download URLs.
var assetHosts = []string{"objects.githubusercontent.com", "release-assets.githubusercontent.com", "github-releases.githubusercontent.com"}

func githubAsset(u *url.URL) bool {
	return u.Scheme == "https" && slices.Contains(assetHosts, u.Hostname())
}

// latest returns the download URL of the release sign.yml marks latest, read from the redirect GitHub answers
// latest/download with: download/<tag>/ under the same releases URL, and nowhere else.
func (l *Loader) latest(ctx context.Context) (string, error) {
	base := strings.TrimSuffix(l.BaseURL, "/")
	resp, err := l.fetch(ctx, base+"/latest/download/"+statementAsset)
	if err != nil {
		return "", fmt.Errorf("fetch the latest release: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 3 {
		return "", fmt.Errorf("fetch the latest release: %s, not a redirect to its tag", resp.Status)
	}
	to, err := resp.Location()
	if err != nil {
		return "", fmt.Errorf("fetch the latest release: %w", err)
	}
	prefix, suffix := base+"/download/", "/"+statementAsset
	got := to.String()
	tag, ok := strings.CutPrefix(got, prefix)
	if ok {
		tag, ok = strings.CutSuffix(tag, suffix)
	}
	if !ok || tag == "" || strings.ContainsAny(tag, "/?#%") {
		return "", fmt.Errorf("fetch the latest release: redirect %q is not a release under %s", got, base)
	}
	return prefix + tag, nil
}

// get downloads one asset of release through internal/upstream, which follows no redirect. GitHub answers a
// tag's download with a 302 to its asset host, so get follows that one hop itself, to a host the loader admits
// and no other.
func (l *Loader) get(ctx context.Context, release, name string) ([]byte, error) {
	target := release + "/" + name
	resp, err := l.fetch(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", name, err)
	}
	if resp.StatusCode/100 == 3 {
		to, err := resp.Location()
		resp.Body.Close()
		allowed := l.Redirect
		if allowed == nil {
			allowed = githubAsset
		}
		if err != nil || !allowed(to) {
			return nil, fmt.Errorf("fetch %s: redirect %q is not to a host the loader admits", name, resp.Header.Get("Location"))
		}
		if resp, err = l.fetch(ctx, to.String()); err != nil {
			return nil, fmt.Errorf("fetch %s: %w", name, err)
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: %s", name, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAsset+1))
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", name, err)
	}
	if len(body) > maxAsset {
		return nil, fmt.Errorf("fetch %s: more than %d bytes", name, maxAsset)
	}
	return body, nil
}

func (l *Loader) fetch(ctx context.Context, target string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	return upstream.Do(l.Client, req)
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
