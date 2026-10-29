package e2ee

import (
	"bytes"
	"regexp"
)

const padCommentPrefix = ": wm-pad "

var padLine = regexp.MustCompile(`^: wm-pad [A-Za-z0-9]{16,64}\n$`)

func PadComment(filler string) []byte {
	return append(append([]byte(padCommentPrefix), filler...), '\n')
}

func StripPadComments(wire []byte) []byte {
	out := make([]byte, 0, len(wire))
	for len(wire) > 0 {
		end := bytes.IndexByte(wire, '\n')
		if end < 0 {
			return append(out, wire...)
		}
		line := wire[:end+1]
		if !padLine.Match(line) {
			out = append(out, line...)
		}
		wire = wire[end+1:]
	}
	return out
}
