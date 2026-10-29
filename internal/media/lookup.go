package media

import "fmt"

type ModelKind string

const (
	ImageModel ModelKind = "an image model"
	VideoModel ModelKind = "a video model"
)

func Lookup[T any](models map[string]T, kind ModelKind, model, vendor string) (T, error) {
	spec, ok := models[model]
	if !ok {
		return spec, fmt.Errorf("%q is not %s %s serves", model, kind, vendor)
	}
	return spec, nil
}
