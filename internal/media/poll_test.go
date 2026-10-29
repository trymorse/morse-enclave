package media_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"morse/backend/internal/media"
)

func TestPollUntilWaitsBeforeEachStepAndStopsOnDoneAnErrorOrTheDeadline(t *testing.T) {
	steps := 0
	err := media.PollUntil(context.Background(), time.Millisecond, func(context.Context) (bool, error) {
		steps++
		return steps == 3, nil
	})
	if err != nil || steps != 3 {
		t.Errorf("done after %d steps, err %v", steps, err)
	}
	boom := errors.New("boom")
	steps = 0
	err = media.PollUntil(context.Background(), time.Millisecond, func(context.Context) (bool, error) {
		steps++
		return false, boom
	})
	if !errors.Is(err, boom) || steps != 1 {
		t.Errorf("a step error: %v after %d steps", err, steps)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	steps = 0
	err = media.PollUntil(ctx, time.Hour, func(context.Context) (bool, error) {
		steps++
		return false, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) || steps != 0 {
		t.Errorf("at the deadline: %v after %d steps, want no step before the first interval", err, steps)
	}
}

func TestPartialKeepsTheImagesInHandOverALaterErrorAndTruncatesThemToTheCount(t *testing.T) {
	img, err := media.NewImage(pngBase64)
	if err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	three := media.Images{List: []media.Image{img, img, img}}
	if got, err := three.Partial(2, boom); err != nil || len(got.List) != 2 {
		t.Errorf("three images for two: %d, %v", len(got.List), err)
	}
	if got, err := three.Partial(4, nil); err != nil || len(got.List) != 3 {
		t.Errorf("three images for four: %d, %v", len(got.List), err)
	}
	if _, err := (media.Images{}).Partial(1, boom); !errors.Is(err, boom) {
		t.Errorf("no images with an error: %v", err)
	}
	if _, err := (media.Images{}).Partial(1, nil); !errors.Is(err, media.ErrNoImages) {
		t.Errorf("no images and no error: %v, want %v", err, media.ErrNoImages)
	}
}
