package upstream

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// ErrEgressRefused is a body a check refused before it left: the Privacy Veil's, which refuses one that still holds a
// detail it veiled. Nothing was sent.
var ErrEgressRefused = errors.New("upstream: the body failed its egress check")

// Egress checks a body before it leaves.
type Egress func(body []byte) error

type egressKey struct{}

// WithEgress makes every request sent under ctx pass check first.
func WithEgress(ctx context.Context, check Egress) context.Context {
	return context.WithValue(ctx, egressKey{}, check)
}

// WithoutEgress lifts the check, for a body its sender sealed after checking the plaintext with CheckEgress.
func WithoutEgress(ctx context.Context) context.Context {
	return context.WithValue(ctx, egressKey{}, Egress(nil))
}

// CheckEgress runs ctx's check on body, if it carries one.
func CheckEgress(ctx context.Context, body []byte) error {
	check, _ := ctx.Value(egressKey{}).(Egress)
	if check == nil {
		return nil
	}
	if err := check(body); err != nil {
		return notSent(fmt.Errorf("%w: %w", ErrEgressRefused, err))
	}
	return nil
}

// egress checks req's body under its context's check. A body it cannot read again is refused, never sent unchecked.
func egress(req *http.Request) error {
	check, _ := req.Context().Value(egressKey{}).(Egress)
	if check == nil || req.Body == nil || req.Body == http.NoBody {
		return nil
	}
	if req.GetBody == nil {
		return notSent(fmt.Errorf("%w: a body that cannot be read twice", ErrEgressRefused))
	}
	copied, err := req.GetBody()
	if err != nil {
		return notSent(fmt.Errorf("%w: %w", ErrEgressRefused, err))
	}
	defer copied.Close()
	var body bytes.Buffer
	if _, err := io.Copy(&body, copied); err != nil {
		return notSent(fmt.Errorf("%w: %w", ErrEgressRefused, err))
	}
	return CheckEgress(req.Context(), body.Bytes())
}
