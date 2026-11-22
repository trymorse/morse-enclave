package routesdata

import "fmt"

type Mode string

const (
	Off Mode = "off"
	Log Mode = "log"
)

func ParseMode(s string) (Mode, error) {
	switch m := Mode(s); m {
	case "":
		return Off, nil
	case Off, Log:
		return m, nil
	}
	return "", fmt.Errorf("routes data mode %q is not off or log: this image can verify a signed routes file and log it, and loads only its own routes.json", s)
}
