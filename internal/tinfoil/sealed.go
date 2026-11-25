package tinfoil

import (
	"bytes"
	"context"
	"net/http"

	"morse/backend/internal/e2ee/ehbp"
	"morse/backend/internal/e2ee/ehbp/ehbpclient"
	"morse/backend/internal/upstream"
)

func postSealed(ctx context.Context, endpoint upstream.Endpoint, key [32]byte, path string, header http.Header, body []byte, limit int64) (upstream.Reply, []byte, error) {
	sealed, wire, err := ehbpclient.SealRequest(key[:], body)
	if err != nil {
		return upstream.Reply{}, nil, err
	}
	header = header.Clone()
	if header == nil {
		header = http.Header{}
	}
	header.Set(ehbp.HeaderEncapsulatedKey, sealed.EncapsulatedHex())
	header.Set("Content-Type", "application/json")
	reply, err := endpoint.Call(ctx, upstream.Request{Method: http.MethodPost, Path: path, Header: header, Body: wire}, limit)
	switch {
	case err != nil:
		return reply, nil, err
	case reply.Status/100 != 2:
		return reply, nil, endpoint.Refuse(reply)
	}
	opener, err := sealed.Reply(reply.Header.Get(ehbp.HeaderResponseNonce))
	if err != nil {
		return reply, nil, upstream.ErrMalformed
	}
	plain, err := opener.OpenAll(bytes.NewReader(reply.Body))
	if err != nil {
		return reply, nil, upstream.ErrMalformed
	}
	return reply, plain, nil
}
