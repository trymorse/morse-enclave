package chat

import "regexp"

type Host struct{ name string }

const HostPattern = `^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`

var hostPattern = regexp.MustCompile(HostPattern)

func ParseHost(name string) (Host, bool) {
	if !hostPattern.MatchString(name) {
		return Host{}, false
	}
	return Host{name: name}, true
}

func (h Host) Known() bool { return h.name != "" }

func (h Host) String() string { return h.name }

func (h Host) MarshalText() ([]byte, error) { return []byte(h.name), nil }

func (h *Host) UnmarshalText(text []byte) error {
	*h, _ = ParseHost(string(text))
	return nil
}
