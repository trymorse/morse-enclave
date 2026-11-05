package rekorv2

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/mod/sumdb/tlog"
)

// Fetch reads one path under a shard's base URL, such as "checkpoint" or
// "tile/0/x001/234.p/5". The host supplies it over its own HTTP client.
type Fetch func(ctx context.Context, path string) ([]byte, error)

const tileHeight = 8

// Reprove returns entry with its inclusion proof rebuilt against note,
// a newer checkpoint of the same shard, from the shard's hash tiles. It
// checks no signature: whether the note has enough witnesses is for the
// verifier to say. Every tile it reads is checked against the note's root
// hash, and it checks the new proof before it returns it.
func Reprove(ctx context.Context, fetch Fetch, entry []byte, note string) ([]byte, error) {
	e, err := parseEntry(entry)
	if err != nil {
		return nil, fmt.Errorf("rekorv2: the entry: %v", err)
	}
	text, _, err := parseNote(note)
	if err != nil {
		return nil, fmt.Errorf("rekorv2: the checkpoint: %v", err)
	}
	ct, err := parseCheckpointText(text)
	if err != nil {
		return nil, fmt.Errorf("rekorv2: the checkpoint: %v", err)
	}
	index := uint64(e.LogIndex)
	if index >= ct.size || ct.size >= 1<<62 {
		return nil, fmt.Errorf("rekorv2: a tree of size %d does not hold index %d", ct.size, index)
	}
	tiles := tileReader{ctx: ctx, fetch: fetch}
	proof, err := tlog.ProveRecord(int64(ct.size), int64(index), tlog.TileHashReader(tlog.Tree{N: int64(ct.size), Hash: tlog.Hash(ct.root)}, tiles))
	if err != nil {
		return nil, fmt.Errorf("rekorv2: building the proof from tiles: %v", err)
	}
	hashes := make([][32]byte, len(proof))
	for i, h := range proof {
		hashes[i] = [32]byte(h)
	}
	root, err := rootFromProof(index, ct.size, leafHash(e.CanonicalizedBody), hashes)
	if err != nil || root != ct.root {
		return nil, fmt.Errorf("rekorv2: the rebuilt proof does not reach the checkpoint's root")
	}
	e.InclusionProof.LogIndex = e.LogIndex
	e.InclusionProof.TreeSize = protoUint(ct.size)
	e.InclusionProof.RootHash = ct.root[:]
	e.InclusionProof.Hashes = make([][]byte, len(hashes))
	for i := range hashes {
		e.InclusionProof.Hashes[i] = hashes[i][:]
	}
	e.InclusionProof.Checkpoint.Envelope = note
	return json.Marshal(e)
}

// tileReader serves x/mod's tlog from a C2SP tlog-tiles log, whose tile
// paths are x/mod's without the height.
type tileReader struct {
	ctx   context.Context
	fetch Fetch
}

func (tileReader) Height() int { return tileHeight }

func (r tileReader) ReadTiles(tiles []tlog.Tile) ([][]byte, error) {
	out := make([][]byte, len(tiles))
	for i, t := range tiles {
		data, err := r.read(t)
		if err != nil {
			return nil, err
		}
		out[i] = data
	}
	return out, nil
}

// read fetches t, and when a partial tile is gone because the log has
// since filled it, the full tile's prefix.
func (r tileReader) read(t tlog.Tile) ([]byte, error) {
	data, err := r.fetch(r.ctx, tilePath(t))
	if err == nil || t.W == 1<<tileHeight {
		return data, err
	}
	full := t
	full.W = 1 << tileHeight
	data, fullErr := r.fetch(r.ctx, tilePath(full))
	if fullErr != nil || len(data) < t.W*tlog.HashSize {
		return nil, err
	}
	return data[:t.W*tlog.HashSize], nil
}

func (tileReader) SaveTiles([]tlog.Tile, [][]byte) {}

func tilePath(t tlog.Tile) string {
	return "tile/" + strings.TrimPrefix(t.Path(), fmt.Sprintf("tile/%d/", tileHeight))
}
