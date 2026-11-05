package worker

import (
	"errors"
	"net/http"

	"morse/backend/internal/apierr"
	"morse/backend/internal/chat"
	"morse/backend/internal/e2ee"
	"morse/backend/internal/e2ee/ehbp"
	"morse/backend/internal/e2ee/near"
)

type protocol struct {
	scheme *chat.Scheme
	params chat.E2EE
	err    error
}

var schemesNarrowestFirst = []*chat.Scheme{ehbp.Scheme, near.Scheme, e2ee.Scheme}

func protocolOf(header func(string) string) protocol {
	for _, s := range schemesNarrowestFirst {
		if params, sealed, err := s.Parse(header); sealed {
			return protocol{scheme: s, params: params, err: err}
		}
	}
	for _, s := range schemesNarrowestFirst {
		for _, name := range s.Headers {
			if header(name) != "" {
				return protocol{scheme: s, err: s.ErrHeaderMissing}
			}
		}
	}
	return protocol{}
}

func refuseProtocol(want *chat.Scheme, p protocol) error {
	switch {
	case p.scheme == want && p.err == nil:
		return nil
	case p.scheme == want, want == nil && p.err != nil:
		return protocolRefusal(p.err)
	case want == nil:
		return errE2EEUnsupportedModel
	case p.scheme == nil:
		return protocolRefusal(want.ErrHeaderMissing)
	}
	return errWrongE2EEProtocol
}

var (
	errWrongE2EEProtocol    = apierr.Error{Status: http.StatusBadRequest, Type: "e2ee_unsupported_model", Code: "e2ee_unsupported_model", Message: "This model serves end-to-end encryption under another protocol. Use the e2ee_protocol that GET /v1/attestation reports for it."}
	errE2EEUnsupportedModel = apierr.Error{Status: http.StatusBadRequest, Type: "e2ee_unsupported_model", Code: "e2ee_unsupported_model", Message: "This model does not serve end-to-end encryption. Send E2EE headers only to an e2ee model from GET /v1/models."}
)

func protocolRefusal(err error) apierr.Error {
	var e *e2ee.Error
	if !errors.As(err, &e) {
		return apierr.ErrInvalidBody
	}
	return apierr.Error{Status: http.StatusBadRequest, Type: e.Type, Code: e.Type, Message: e.Message}
}

func hintedHexOnly(err error) error {
	var e apierr.Error
	if !errors.As(err, &e) || e.Code != e2ee.ErrHeaderMissing.Type {
		return err
	}
	e.Message += " A plain message made only of long hex reads as ciphertext. Add any other text to it to send it plain."
	return e
}
