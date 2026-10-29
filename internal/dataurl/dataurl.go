package dataurl

import (
	"errors"
	"strings"

	"morse/backend/internal/apierr"
)

type URL struct {
	MediaType string
	Base64    string
}

func (u URL) String() string { return "data:" + u.MediaType + ";base64," + u.Base64 }

var errNotBase64 = errors.New("dataurl: data URL does not carry base64 media")

func Parse(url string) (URL, error) {
	const scheme = "data:"
	if len(url) < len(scheme) || !strings.EqualFold(url[:len(scheme)], scheme) {
		return URL{}, apierr.ErrRemoteMedia
	}
	header, payload, ok := strings.Cut(url[len(scheme):], ",")
	mediaType, encoding, _ := strings.Cut(header, ";")
	if !ok || !strings.EqualFold(encoding, "base64") || payload == "" {
		return URL{}, errNotBase64
	}
	return URL{MediaType: strings.ToLower(mediaType), Base64: payload}, nil
}
