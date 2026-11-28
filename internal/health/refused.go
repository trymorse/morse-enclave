package health

import "errors"

const (
	RefusedAssetUnavailable = "asset_unavailable"
	RefusedContentRejected  = "content_rejected"
	RefusedNoAsset          = "no_asset"
	RefusedStateCanceled    = "state_canceled"
	RefusedStateExpired     = "state_expired"
	RefusedStateFailed      = "state_failed"
	RefusedStateUnknown     = "state_unknown"
	RefusedUntrustedLink    = "untrusted_link"
)

var ResultRefusals = []string{
	RefusedAssetUnavailable, RefusedContentRejected, RefusedNoAsset, RefusedStateCanceled, RefusedStateExpired,
	RefusedStateFailed, RefusedStateUnknown, RefusedUntrustedLink,
}

type ResultRefused struct {
	Why string
	Err error
}

func (r ResultRefused) Error() string { return r.Err.Error() }

func (r ResultRefused) Unwrap() error { return r.Err }

func WhyRefused(err error) string {
	refused, _ := errors.AsType[ResultRefused](err)
	return refused.Why
}
