package worker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"morse/backend/internal/apierr"
	"morse/backend/internal/chat"
)

type Vendor struct {
	Route    string `json:"route"`
	Attester string `json:"attester"`
}

var (
	ErrReceiptNotFound = apierr.Invalid(http.StatusNotFound, "receipt_not_found", "No receipt with that id.")
	ErrSessionNotFound = apierr.Invalid(http.StatusNotFound, "session_not_found", "No attested session with that id. The gateway keeps a session for about an hour.")
	ErrSessionTooLarge = apierr.Error{Status: http.StatusRequestEntityTooLarge, Type: "upstream_error", Code: "session_too_large", Message: "The attested session is larger than this proxy relays."}
)

var errNoSuchVendor = errors.New("worker: no such vendor")

func (w *InProcess) vendor(v Vendor) (chatRoute, error) {
	for _, r := range w.chats[v.Route] {
		if r.attester == v.Attester {
			return r, nil
		}
	}
	return chatRoute{}, errNoSuchVendor
}

func (w *InProcess) Attest(ctx context.Context, v Vendor, nonce string) (chat.Attestation, error) {
	by, err := w.attesterOf(v)
	if err != nil {
		return chat.Attestation{}, err
	}
	att, err := by.Attest(ctx, nonce)
	return att, evidenceRefusal(err)
}

func (w *InProcess) attesterOf(v Vendor) (chat.Attester, error) {
	if t, ok := w.transcribers[v.Route]; ok && t.Attester != nil && t.attester == v.Attester {
		return t.Attester, nil
	}
	r, err := w.vendor(v)
	if err != nil {
		return nil, err
	}
	if by := r.Upstream.attester(); by != nil {
		return by, nil
	}
	return nil, errNoSuchVendor
}

func (w *InProcess) Receipt(ctx context.Context, v Vendor, id string) (json.RawMessage, error) {
	r, err := w.verbatim(v)
	if err != nil {
		return nil, err
	}
	receipt, err := r.Receipt(ctx, id)
	return receipt, evidenceRefusal(err)
}

func (w *InProcess) Session(ctx context.Context, v Vendor, id string) (json.RawMessage, error) {
	s, err := w.sessioner(v)
	if err != nil {
		return nil, err
	}
	record, err := s.Session(ctx, id)
	return record, evidenceRefusal(err)
}

func (w *InProcess) Sessions(ctx context.Context, v Vendor) ([]chat.ListedSession, error) {
	s, err := w.sessioner(v)
	if err != nil {
		return nil, err
	}
	listed, err := s.ListSessions(ctx)
	return listed, evidenceRefusal(err)
}

func (w *InProcess) verbatim(v Vendor) (chat.VerbatimRoute, error) {
	r, err := w.vendor(v)
	if err != nil {
		return nil, err
	}
	u, ok := r.Upstream.(Verbatim)
	if !ok {
		return nil, errNoSuchVendor
	}
	return u.Route, nil
}

func (w *InProcess) sessioner(v Vendor) (chat.Sessioner, error) {
	r, err := w.verbatim(v)
	if err != nil {
		return nil, err
	}
	s, ok := r.(chat.Sessioner)
	if !ok {
		return nil, errNoSuchVendor
	}
	return s, nil
}

func evidenceRefusal(err error) error {
	var nonce *chat.InvalidNonce
	var receipt *chat.InvalidReceiptID
	switch {
	case errors.As(err, &nonce):
		return apierr.Invalid(http.StatusBadRequest, "invalid_nonce", "nonce must be "+nonce.Form+".")
	case errors.As(err, &receipt):
		return apierr.Invalid(http.StatusBadRequest, "invalid_receipt_id", "Receipt id must be "+receipt.Form+".")
	case errors.Is(err, chat.ErrReceiptNotFound):
		return ErrReceiptNotFound
	case errors.Is(err, chat.ErrSessionNotFound):
		return ErrSessionNotFound
	case errors.Is(err, chat.ErrSessionTooLarge):
		return ErrSessionTooLarge
	}
	return err
}
