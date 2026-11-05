package measure

import (
	"errors"

	"morse/backend/internal/apierr"
	"morse/backend/internal/enum"
)

type RefusalCode uint8

const (
	NoRefusal RefusalCode = iota
	RefusedContentFilter
	RefusedContextLength
	RefusedInvalidRequest
	RefusedTooLarge
	RefusedRemoteMedia
	RefusedInvalidParameter
	RefusedUpstreamBusy
	RefusedUpstreamError
	RefusedUpstreamUnavailable
	RefusedUpstreamRefused
	RefusedUnattested
	RefusedRetention
	RefusedOther
)

var refusalCodeNames = enum.Names[RefusalCode]{
	RefusedContentFilter:       "content_filter",
	RefusedContextLength:       "context_length_exceeded",
	RefusedInvalidRequest:      "invalid_request",
	RefusedTooLarge:            "request_too_large",
	RefusedRemoteMedia:         "remote_media",
	RefusedInvalidParameter:    "invalid_parameter",
	RefusedUpstreamBusy:        "upstream_busy",
	RefusedUpstreamError:       "upstream_error",
	RefusedUpstreamUnavailable: "upstream_unavailable",
	RefusedUpstreamRefused:     "upstream_refused",
	RefusedUnattested:          "upstream_unattested",
	RefusedRetention:           "upstream_retention",
	RefusedOther:               "other",
}

func RefusalCodes() []RefusalCode { return refusalCodeNames.Values() }

func (c RefusalCode) String() string { return refusalCodeNames.String(c) }

func (c RefusalCode) MarshalText() ([]byte, error) { return refusalCodeNames.MarshalText(c) }

func (c *RefusalCode) UnmarshalText(text []byte) error {
	return refusalCodeNames.UnmarshalText(c, text)
}

func RefusalCodeOf(err error) RefusalCode {
	var refusal apierr.Error
	if !errors.As(err, &refusal) {
		return NoRefusal
	}
	if code, listed := refusalCodeNames.Parse(refusal.Code); listed {
		return code
	}
	return RefusedOther
}
