package baseurl

import (
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
)

func Parse(name, example, raw string) (*url.URL, error) {
	return ParseAllowingPlain(name, example, raw)
}

func ParseAllowingPlain(name, example, raw string, plainHosts ...string) (*url.URL, error) {
	u, err := url.Parse(raw)
	switch {
	case err != nil || u.Host == "":
		return nil, fmt.Errorf("%s must be an absolute URL such as %s", name, example)
	case u.User != nil:
		return nil, fmt.Errorf("%s must not carry credentials", name)
	case strings.Contains(raw, "?"):
		return nil, fmt.Errorf("%s must not carry a query; a request path is appended to it", name)
	case strings.Contains(raw, "#"):
		return nil, fmt.Errorf("%s must not carry a fragment; a request path is appended to it", name)
	case u.Scheme == "https", u.Scheme == "http" && (isLoopback(u.Hostname()) || slices.Contains(plainHosts, u.Hostname())):
		return u, nil
	}
	return nil, fmt.Errorf("%s must use https; http is allowed only for a loopback host", name)
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
