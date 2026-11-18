package privacyveil

import "context"

type Lanes struct{ slots chan struct{} }

func NewLanes(n int) *Lanes {
	if n <= 0 {
		return nil
	}
	return &Lanes{slots: make(chan struct{}, n)}
}

func (l *Lanes) take(ctx context.Context) error {
	if err := ctx.Err(); err != nil || l == nil {
		return err
	}
	select {
	case l.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *Lanes) give() {
	if l != nil {
		<-l.slots
	}
}
