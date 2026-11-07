package phala

import (
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"time"

	"morse/backend/internal/chat"
	"morse/backend/internal/openaicompat"
	"morse/backend/internal/receipt"
)

// The gateway publishes a receipt only after the reply's last byte.
const receiptLag = time.Second

var receiptUnverified = expvar.NewMap("receipt_unverified")

var errNoReceiptID = errors.New("phala: the reply named no receipt")

var unverifiedReasons = []struct {
	err    error
	reason string
}{
	{errNoReceiptID, "no_receipt_id"},
	{errInvalidReceipt, "bad_receipt_id"},
	{chat.ErrReceiptNotFound, "missing"},
	{context.DeadlineExceeded, "unreachable"},
	{context.Canceled, "unreachable"},
	{receipt.ErrKeysetDigest, "keyset"},
	{receipt.ErrWorkloadID, "keyset"},
	{receipt.ErrKeysetExpired, "keyset"},
	{receipt.ErrKeyUnknown, "key"},
	{receipt.ErrKeyAlgo, "key"},
	{receipt.ErrSignature, "signature"},
	{receipt.ErrChatID, "chat_id"},
	{receipt.ErrModel, "model"},
	{receipt.ErrResponseHash, "response_hash"},
}

func unverifiedReason(err error) string {
	for _, r := range unverifiedReasons {
		if errors.Is(err, r.err) {
			return r.reason
		}
	}
	return "unreadable"
}

func (g Gateway) prover(model string, keys Keys) openaicompat.Prover {
	return func(ctx context.Context, read openaicompat.Read) (json.RawMessage, error) {
		raw, err := g.prove(ctx, model, keys, read)
		if err != nil {
			receiptUnverified.Add(unverifiedReason(err), 1)
		}
		return raw, err
	}
}

func (g Gateway) prove(ctx context.Context, model string, keys Keys, read openaicompat.Read) (json.RawMessage, error) {
	switch {
	case keys == nil:
		return nil, receipt.ErrKeysetDigest
	case read.ReceiptID == "":
		return nil, errNoReceiptID
	}
	raw, err := g.awaitReceipt(ctx, read.ReceiptID)
	if err != nil {
		return nil, err
	}
	r, err := receipt.Parse(raw)
	if err != nil {
		return nil, err
	}
	ks, verified := keys.Keyset(r.Digest)
	if !verified {
		return nil, receipt.ErrKeysetDigest
	}
	if err := r.VerifyResponse(ks, receipt.Response{Model: model, ID: read.ReplyID, Hash: read.Hash}, time.Now()); err != nil {
		return nil, err
	}
	return raw, nil
}

func (g Gateway) awaitReceipt(ctx context.Context, id string) ([]byte, error) {
	for {
		raw, err := g.Receipt(ctx, id)
		if err == nil {
			return raw, nil
		}
		if _, invalid := errors.AsType[*chat.InvalidReceiptID](err); invalid {
			return nil, err
		}
		select {
		case <-time.After(receiptLag):
		case <-ctx.Done():
			return nil, errors.Join(err, ctx.Err())
		}
	}
}
