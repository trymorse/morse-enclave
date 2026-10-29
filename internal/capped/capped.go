package capped

import (
	"errors"
	"io"
)

var ErrTooLarge = errors.New("capped: body exceeds the size limit")

func ReadAll(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, ErrTooLarge
	}
	return body, nil
}

func Append(buf, more []byte, limit int) []byte {
	return append(buf, more[:min(len(more), max(0, limit+1-len(buf)))]...)
}
