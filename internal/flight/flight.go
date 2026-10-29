package flight

import (
	"context"
	"time"

	"golang.org/x/sync/singleflight"
)

type Group[T any] struct {
	flight singleflight.Group
}

func (g *Group[T]) Do(ctx context.Context, key string, bound time.Duration, work func(context.Context) (T, error)) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	results := g.flight.DoChan(key, func() (any, error) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), bound)
		defer cancel()
		return work(ctx)
	})
	select {
	case r := <-results:
		v, _ := r.Val.(T)
		return v, r.Err
	case <-ctx.Done():
		return zero, ctx.Err()
	}
}
