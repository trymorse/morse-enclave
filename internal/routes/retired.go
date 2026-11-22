package routes

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

type Retirement struct {
	Name  string `json:"name"`
	To    string `json:"to"`
	Since string `json:"since"`
}

type File struct {
	Routes  []Route
	Retired map[string]string
}

func retiredNames(list []Retirement, rts []Route) (map[string]string, error) {
	live := func(name string) (Route, bool) {
		i := slices.IndexFunc(rts, func(rt Route) bool { return rt.Model == name || string(rt.ID) == name })
		if i < 0 {
			return Route{}, false
		}
		return rts[i], true
	}
	retired := map[string]string{}
	for _, r := range list {
		to, served := live(r.To)
		redirects := false
		switch to.Serves.(type) {
		case Chat, Image, Video:
			redirects = true
		}
		_, taken := retired[r.Name]
		_, serves := live(r.Name)
		switch {
		case r.Name == "":
			return nil, errors.New("a retired name has no name")
		case taken:
			return nil, fmt.Errorf("retired name %q is listed twice", r.Name)
		case serves:
			return nil, fmt.Errorf("retired name %q still serves; retire a name only once no model or alias has it", r.Name)
		case !served:
			return nil, fmt.Errorf("retired name %q goes to %q, which is no model id or alias", r.Name, r.To)
		case !redirects:
			return nil, fmt.Errorf("retired name %q goes to %q, which serves no chat, image, or video", r.Name, r.To)
		}
		if _, err := time.Parse(time.DateOnly, r.Since); err != nil {
			return nil, fmt.Errorf("retired name %q: since must be a date, YYYY-MM-DD", r.Name)
		}
		retired[r.Name] = r.To
	}
	return retired, nil
}
