package sse

import (
	"bufio"
	"bytes"
	"errors"
	"io"

	"morse/backend/internal/capped"
)

var (
	ErrTruncated = errors.New("sse: the stream ended before its terminal event")
	ErrTooLarge  = errors.New("sse: an event exceeds the size limit")
	errDone      = errors.New("sse: the terminal event")
)

type Oversize uint8

const (
	Refuse Oversize = iota
	Clip
)

var dataField = []byte("data:")

const fieldPrefix = len("data: ")

// A Frame is a run of the stream as it came. While no event is open it is one line, a comment or a blank; a
// data line opens an event, which then runs through the blank line that ends it or the end of the stream.
type Frame struct {
	Raw  []byte
	Data []byte // the event's data lines joined by newline; nil for a frame without one
	// Opaque reports that Raw holds what Data does not show: a field other than data, or a CR inside a line,
	// which a client's parser ends the line at and this reader does not.
	Opaque bool
}

// Frames hands each frame to each and reads on until the stream ends or each refuses. Under Refuse a frame
// past limit ends the stream with ErrTooLarge before any of it is handed over; under Clip its Raw and Data are
// cut just past the limit. The frame is each's only until it returns.
func Frames(r io.Reader, limit int, oversize Oversize, each func(Frame) error) error {
	return frames(r, limit, oversize, true, each)
}

func frames(r io.Reader, limit int, oversize Oversize, raw bool, each func(Frame) error) error {
	lines := bufio.NewReaderSize(r, 64<<10)
	var f Frame
	var line []byte
	data := []byte{}
	pending := false
	for {
		read := 0
		var err error
		for {
			var piece []byte
			piece, err = lines.ReadSlice('\n')
			read += len(piece)
			line = capped.Append(line, piece, limit+fieldPrefix)
			if raw {
				if f.Raw = capped.Append(f.Raw, piece, limit); len(f.Raw) > limit && oversize == Refuse {
					return ErrTooLarge
				}
			}
			if err != bufio.ErrBufferFull {
				break
			}
		}
		if err != nil && err != io.EOF {
			return err
		}
		if read > 0 {
			line = bytes.TrimSuffix(bytes.TrimSuffix(line, []byte("\n")), []byte("\r"))
			value, isData := bytes.CutPrefix(line, dataField)
			blank := len(line) == 0
			if bytes.IndexByte(line, '\r') >= 0 || !blank && !isData && line[0] != ':' {
				f.Opaque = true
			}
			if isData {
				if pending {
					data = append(data, '\n')
				}
				value, _ = bytes.CutPrefix(value, []byte(" "))
				data, pending = capped.Append(data, value, limit), true
				if !raw && len(data) > limit && oversize == Refuse {
					return ErrTooLarge
				}
				f.Data = data
			}
			line = line[:0]
			if !pending || blank {
				if err := each(f); err != nil {
					return err
				}
				f, data, pending = Frame{Raw: f.Raw[:0]}, data[:0], false
			}
		}
		if err == io.EOF {
			break
		}
	}
	if pending {
		return each(f)
	}
	return nil
}

func Each(r io.Reader, limit int, oversize Oversize, each func(data []byte) (done bool, err error)) error {
	err := frames(r, limit, oversize, false, func(f Frame) error {
		if f.Data == nil {
			return nil
		}
		done, err := each(f.Data)
		if done && err == nil {
			return errDone
		}
		return err
	})
	switch err {
	case nil:
		return ErrTruncated
	case errDone:
		return nil
	}
	return err
}
