package flight

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestTheWorkRunsOnceDetachedFromItsInitiatorAndEachWaiterHonorsItsOwnContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var g Group[string]
		var runs atomic.Int32
		work := func(ctx context.Context) (string, error) {
			runs.Add(1)
			select {
			case <-time.After(time.Second):
				return "done", nil
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
		initiator, cancel := context.WithCancel(context.Background())
		initiated := make(chan error, 1)
		go func() {
			_, err := g.Do(initiator, "k", time.Minute, work)
			initiated <- err
		}()
		synctest.Wait()
		joined := make(chan string, 1)
		go func() {
			v, err := g.Do(context.Background(), "k", time.Minute, work)
			if err != nil {
				v = err.Error()
			}
			joined <- v
		}()
		synctest.Wait()
		cancel()
		if err := <-initiated; !errors.Is(err, context.Canceled) {
			t.Errorf("the cancelled initiator got %v, want its own cancellation", err)
		}
		if v := <-joined; v != "done" {
			t.Errorf("the joiner got %q, want the result of the work the initiator abandoned", v)
		}
		if n := runs.Load(); n != 1 {
			t.Errorf("the work ran %d times for two callers, want once", n)
		}
	})
}

func TestACallerAlreadyCancelledGetsItsCancellationAndStartsNoWork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var g Group[string]
		var runs atomic.Int32
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		v, err := g.Do(cancelled, "k", time.Minute, func(context.Context) (string, error) {
			runs.Add(1)
			return "done", nil
		})
		if !errors.Is(err, context.Canceled) || v != "" {
			t.Errorf("a cancelled caller got %q and %v, want its own cancellation and no result", v, err)
		}
		synctest.Wait()
		if n := runs.Load(); n != 0 {
			t.Errorf("the work ran %d times for a caller that had already left, want none", n)
		}
	})
}

func TestTheBoundEndsWorkThatOutlivesIt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var g Group[struct{}]
		start := time.Now()
		_, err := g.Do(context.Background(), "k", time.Second, func(ctx context.Context) (struct{}, error) {
			<-ctx.Done()
			return struct{}{}, ctx.Err()
		})
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != time.Second {
			t.Errorf("got %v after %v, want the bound's deadline after one second", err, time.Since(start))
		}
	})
}
