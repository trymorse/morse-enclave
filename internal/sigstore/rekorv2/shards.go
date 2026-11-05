package rekorv2

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"time"

	"morse/backend/internal/sigstore/tuf"
)

// Shards are the Rekor v2 logs that a verified trusted_root.json lists,
// by log id. Logs with other keys, Rekor v1's ECDSA log among them, are
// left out, so an entry naming one is refused as UnknownLog.
type Shards struct {
	byID    map[[32]byte]shard
	skipped []error
}

type shard struct {
	origin     string
	key        ed25519.PublicKey
	start, end time.Time
}

// ErrTrustedRoot reports a trusted_root.json whose Rekor v2 logs this
// package cannot read.
var ErrTrustedRoot = errors.New("rekorv2: the trusted root's logs are malformed")

type tlogJSON struct {
	BaseURL       string `json:"baseUrl"`
	HashAlgorithm string `json:"hashAlgorithm"`
	PublicKey     struct {
		RawBytes   []byte `json:"rawBytes"`
		KeyDetails string `json:"keyDetails"`
		ValidFor   struct {
			Start time.Time `json:"start"`
			End   time.Time `json:"end"`
		} `json:"validFor"`
	} `json:"publicKey"`
	LogID struct {
		KeyID []byte `json:"keyId"`
	} `json:"logId"`
}

// ParseShards reads the Ed25519 logs of root. It takes a tuf.TrustedRoot,
// so log keys come only from metadata that TUF verified. A v2 log id is
// its note key's hash, sha256(origin + "\n" + 0x01 + key), which ties the
// id, the origin and the key together.
//
// A log it cannot read is skipped, and Skipped says why, so one bad log
// in Sigstore's root does not stop every other. Skipping only shrinks what
// verifies. It refuses a root with no usable log, and two logs with one id,
// whose windows it could not choose between.
func ParseShards(root tuf.TrustedRoot) (Shards, error) {
	var raw struct {
		Tlogs []json.RawMessage `json:"tlogs"`
	}
	if err := json.Unmarshal(root.JSON(), &raw); err != nil {
		return Shards{}, fmt.Errorf("%w: %v", ErrTrustedRoot, err)
	}
	shards := Shards{byID: map[[32]byte]shard{}}
	for i, entry := range raw.Tlogs {
		var l tlogJSON
		if err := json.Unmarshal(entry, &l); err != nil {
			shards.skipped = append(shards.skipped, fmt.Errorf("rekorv2: tlog %d: %v", i, err))
			continue
		}
		if l.PublicKey.KeyDetails != "PKIX_ED25519" {
			continue
		}
		id, sh, err := parseShard(l)
		if err != nil {
			shards.skipped = append(shards.skipped, fmt.Errorf("rekorv2: tlog %d, %s: %v", i, l.BaseURL, err))
			continue
		}
		if _, dup := shards.byID[id]; dup {
			return Shards{}, fmt.Errorf("%w: two logs have the id of %s", ErrTrustedRoot, sh.origin)
		}
		shards.byID[id] = sh
	}
	if len(shards.byID) == 0 {
		return Shards{}, fmt.Errorf("%w: no usable Ed25519 log: %v", ErrTrustedRoot, errors.Join(shards.skipped...))
	}
	return shards, nil
}

// Skipped returns why ParseShards left out each log it could not read,
// for the host to warn about.
func (s Shards) Skipped() []error { return slices.Clone(s.skipped) }

func parseShard(l tlogJSON) ([32]byte, shard, error) {
	origin, err := originOf(l.BaseURL)
	if err != nil {
		return [32]byte{}, shard{}, err
	}
	pub, err := x509.ParsePKIXPublicKey(l.PublicKey.RawBytes)
	key, ok := pub.(ed25519.PublicKey)
	if err != nil || !ok {
		return [32]byte{}, shard{}, fmt.Errorf("the key is not Ed25519")
	}
	if l.HashAlgorithm != "SHA2_256" || l.PublicKey.ValidFor.Start.IsZero() {
		return [32]byte{}, shard{}, fmt.Errorf("another hash or no validity start")
	}
	id := logKeyID(origin, key)
	if len(l.LogID.KeyID) != 32 || [32]byte(l.LogID.KeyID) != id {
		return [32]byte{}, shard{}, fmt.Errorf("the log id is not the note key hash")
	}
	return id, shard{origin: origin, key: key, start: l.PublicKey.ValidFor.Start, end: l.PublicKey.ValidFor.End}, nil
}

// originOf is the checkpoint origin of a log at baseURL: its host name, as
// sigstore-go's verify.VerifyTlogEntry takes it with url.Hostname. It
// refuses a port, a path and anything else Hostname would drop, so that
// two logs at different URLs never share an origin.
func originOf(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Port() != "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", fmt.Errorf("baseUrl %q is not https and a host name alone", baseURL)
	}
	return u.Hostname(), nil
}

func logKeyID(origin string, key ed25519.PublicKey) [32]byte {
	return sha256.Sum256(append([]byte(origin+"\n\x01"), key...))
}

func (s shard) validAt(t time.Time) bool {
	return !t.Before(s.start) && (s.end.IsZero() || !t.After(s.end))
}

// When is the instant a shard's validFor must contain.
type When struct {
	at        time.Time
	witnessed bool
}

// At is a fixed instant.
func At(t time.Time) When { return When{at: t} }

// Witnessed is the k-th earliest counted cosignature time.
func Witnessed() When { return When{witnessed: true} }

func (s Shards) lookup(id []byte) (shard, *Refusal) {
	if len(id) != 32 {
		return shard{}, refuse(UnknownLog, "the log id is not 32 bytes")
	}
	sh, ok := s.byID[[32]byte(id)]
	if !ok {
		return shard{}, refuse(UnknownLog, "the trusted root lists no Ed25519 log with this id")
	}
	return sh, nil
}

func verifyAt(sh shard, when When, k int, checkpoint func() (Checkpoint, *Refusal)) (Checkpoint, error) {
	if !when.witnessed {
		if r := sh.checkAt(when.at); r != nil {
			return Checkpoint{}, r
		}
	}
	c, r := checkpoint()
	if r != nil {
		return Checkpoint{}, r
	}
	if when.witnessed {
		if r := sh.checkAt(c.cosigners[k-1].Time); r != nil {
			return Checkpoint{}, r
		}
	}
	return c, nil
}

func (s shard) checkAt(t time.Time) *Refusal {
	if t.IsZero() || !s.validAt(t) {
		return refuse(LogNotValidNow, fmt.Sprintf("%s is not valid at %s", s.origin, t.Format(time.RFC3339)))
	}
	return nil
}
