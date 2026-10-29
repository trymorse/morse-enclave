package enum

import (
	"fmt"
	"slices"
	"strings"
)

type Names[T ~uint8] []string

func (n Names[T]) Valid(v T) bool { return int(v) < len(n) && n[v] != "" }

func (n Names[T]) String(v T) string {
	if !n.Valid(v) {
		return fmt.Sprintf("%T(%d)", v, uint8(v))
	}
	return n[v]
}

func (n Names[T]) Parse(name string) (T, bool) {
	if i := slices.Index(n, name); i >= 0 && name != "" {
		return T(i), true
	}
	return 0, false
}

func (n Names[T]) MarshalText(v T) ([]byte, error) {
	if !n.Valid(v) {
		return nil, fmt.Errorf("%s has no name", n.String(v))
	}
	return []byte(n[v]), nil
}

func (n Names[T]) UnmarshalText(v *T, text []byte) error {
	parsed, ok := n.Parse(string(text))
	if !ok {
		return fmt.Errorf("%q is not one of %s", text, n.List())
	}
	*v = parsed
	return nil
}

func (n Names[T]) Values() []T {
	var all []T
	for i, name := range n {
		if name != "" {
			all = append(all, T(i))
		}
	}
	return all
}

func (n Names[T]) List() string {
	return strings.Join(slices.DeleteFunc(slices.Clone(n), func(name string) bool { return name == "" }), ", ")
}
