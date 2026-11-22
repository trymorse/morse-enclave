package routesdata

import (
	"errors"
	"fmt"
	"strings"

	"morse/backend/internal/routebounds"
)

var ErrBounds = errors.New("routesdata: the routes file leaves the bounds of the image's own")

type OutOfBounds []routebounds.Breach

func (o OutOfBounds) Error() string {
	reasons := make([]string, len(o))
	for i, b := range o {
		reasons[i] = b.String()
	}
	return ErrBounds.Error() + ": it " + strings.Join(reasons, "; it ")
}

func (o OutOfBounds) Is(target error) bool { return target == ErrBounds }

func Bounds(boot, file []byte) error {
	image, err := routebounds.Read(boot)
	if err != nil {
		return fmt.Errorf("%w: the image's routes.json: %v", ErrBounds, err)
	}
	offered, err := routebounds.Read(file)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBounds, err)
	}
	if breaches := image.Breaches(offered); len(breaches) > 0 {
		return OutOfBounds(breaches)
	}
	return nil
}
