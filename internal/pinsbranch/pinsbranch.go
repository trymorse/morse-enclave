// Package pinsbranch reads signed statements from the statements/images branch of the public
// trymorse/morse-pins repository with no credentials. A read takes the
// branch's tip from the one request git ls-remote makes, then reads every file at that commit from
// raw.githubusercontent.com, so it sees one snapshot that a later push cannot change under it. The files and
// index.json it reads are in the format sign.yml's commit step (trymorse/morse-pins .github/workflows/sign.yml,
// id: commit) writes; this package reads that format and defines none of its own. Nothing it returns is
// trusted: the caller verifies each statement's signature.
package pinsbranch

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	// GitURL answers info/refs?service=git-upload-pack without credentials, and is not part of the
	// rate-limited REST API.
	GitURL = "https://github.com/trymorse/morse-pins.git"
	// RawURL serves <commit>/<path>. A path at a commit never changes, so its 5-minute cache is never stale.
	RawURL = "https://raw.githubusercontent.com/trymorse/morse-pins"
	// Branch is the one branch sign.yml writes.
	Branch = "refs/heads/statements/images"
	// MaxCandidates is how many index entries a reader walks.
	MaxCandidates = 10

	maxRefs  = 4 << 20
	maxIndex = 64 << 10

	entryTime  = "2006-01-02T15:04:05Z"
	entryStamp = "20060102T150405Z"
)

var (
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// Reader reads the branch. Git and Raw override GitURL and RawURL. Do sends a request, which carries no
// Authorization header.
type Reader struct {
	Git string
	Raw string
	Do  func(*http.Request) (*http.Response, error)
}

// Candidate is one entry of an index, with the paths of its statement and bundle at the index's commit.
type Candidate struct {
	Name      string
	Statement string
	Bundle    string
}

// Tip returns the commit Branch points at, from the git smart-HTTP ref advertisement.
func (r Reader) Tip(ctx context.Context) (string, error) {
	git := r.Git
	if git == "" {
		git = GitURL
	}
	body, err := r.get(ctx, git+"/info/refs?service=git-upload-pack", maxRefs)
	if err != nil {
		return "", fmt.Errorf("read the tip of %s: %w", Branch, err)
	}
	lines := bufio.NewReader(bytes.NewReader(body))
	if first, err := readPkt(lines); err != nil || string(first) != "# service=git-upload-pack\n" {
		return "", fmt.Errorf("read the tip of %s: %s does not speak git smart HTTP", Branch, git)
	}
	if flush, err := readPkt(lines); err != nil || flush != nil {
		return "", fmt.Errorf("read the tip of %s: %s sent no flush after its service line", Branch, git)
	}
	for {
		line, err := readPkt(lines)
		if err != nil {
			return "", fmt.Errorf("read the tip of %s: %w", Branch, err)
		}
		if line == nil {
			return "", fmt.Errorf("%s advertises no %s", git, Branch)
		}
		line, _, _ = bytes.Cut(bytes.TrimSuffix(line, []byte("\n")), []byte{0})
		sha, name, ok := strings.Cut(string(line), " ")
		if !ok || !commitPattern.MatchString(sha) {
			return "", fmt.Errorf("read the tip of %s: a ref line reads %q", Branch, line)
		}
		if name == Branch {
			return sha, nil
		}
	}
}

// Index reads <dir>/index.json at commit, the order a reader offers candidates in. The format is the one
// sign.yml's commit step (trymorse/morse-pins .github/workflows/sign.yml, id: commit) writes: a JSON array of
// objects with exactly the keys sequence (an integer of at least 1), time (UTC, as 2026-11-10T07:29:37Z),
// statement (<dir>/<sequence>-<compact time>.statement.json) and bundle (the same stem with .sigstore.json),
// highest sequence first. The paths must be the ones the entry's own sequence and time derive, so no entry
// names a file outside dir or another entry's file. Any malformed entry refuses the whole index, as does an
// empty one. Every entry must be well formed, but only the first MaxCandidates are offered. The index only orders the candidates: the signature over
// each statement decides whether it is trusted.
func (r Reader) Index(ctx context.Context, commit, dir string) ([]Candidate, error) {
	raw, err := r.File(ctx, commit, dir+"/index.json", maxIndex)
	if err != nil {
		return nil, err
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("%s/index.json at %s is not a JSON array: %w", dir, commit, err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%s/index.json at %s lists no statement", dir, commit)
	}
	var candidates []Candidate
	for i, raw := range entries {
		c, err := parseEntry(raw, dir)
		if err != nil {
			return nil, fmt.Errorf("%s/index.json at %s: entry %d: %w", dir, commit, i, err)
		}
		candidates = append(candidates, c)
	}
	return candidates[:min(len(candidates), MaxCandidates)], nil
}

func parseEntry(raw json.RawMessage, dir string) (Candidate, error) {
	var e struct {
		Sequence  *uint64 `json:"sequence"`
		Time      *string `json:"time"`
		Statement *string `json:"statement"`
		Bundle    *string `json:"bundle"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return Candidate{}, fmt.Errorf("is not an object of sequence, time, statement and bundle: %w", err)
	}
	if e.Sequence == nil || e.Time == nil || e.Statement == nil || e.Bundle == nil {
		return Candidate{}, errors.New("lacks one of sequence, time, statement and bundle")
	}
	if *e.Sequence < 1 {
		return Candidate{}, errors.New("has a sequence below 1")
	}
	at, err := time.Parse(time.RFC3339, *e.Time)
	if err != nil || at.Format(entryTime) != *e.Time {
		return Candidate{}, fmt.Errorf("has the time %q, not UTC as YYYY-MM-DDTHH:MM:SSZ", *e.Time)
	}
	stem := fmt.Sprintf("%s/%d-%s", dir, *e.Sequence, at.Format(entryStamp))
	if *e.Statement != stem+".statement.json" || *e.Bundle != stem+".sigstore.json" {
		return Candidate{}, fmt.Errorf("names %q and %q, not %s.statement.json and %s.sigstore.json", *e.Statement, *e.Bundle, stem, stem)
	}
	return Candidate{Name: path.Base(*e.Statement), Statement: *e.Statement, Bundle: *e.Bundle}, nil
}

// File reads path at commit from the raw host, up to limit bytes.
func (r Reader) File(ctx context.Context, commit, path string, limit int64) ([]byte, error) {
	if !commitPattern.MatchString(commit) {
		return nil, fmt.Errorf("read %s: %q is not a commit", path, commit)
	}
	base := r.Raw
	if base == "" {
		base = RawURL
	}
	body, err := r.get(ctx, base+"/"+commit+"/"+path, limit)
	if err != nil {
		return nil, fmt.Errorf("read %s at %s: %w", path, commit, err)
	}
	return body, nil
}

func (r Reader) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%s answered more than %d bytes", url, limit)
	}
	return body, nil
}

func readPkt(r *bufio.Reader) ([]byte, error) {
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return nil, errors.New("the ref advertisement ends before its flush")
	}
	n, err := strconv.ParseUint(string(size[:]), 16, 16)
	if err != nil || (n > 0 && n < 4) {
		return nil, fmt.Errorf("a pkt-line length reads %q", size)
	}
	if n == 0 {
		return nil, nil
	}
	line := make([]byte, n-4)
	if _, err := io.ReadFull(r, line); err != nil {
		return nil, errors.New("the ref advertisement ends inside a pkt-line")
	}
	return line, nil
}
