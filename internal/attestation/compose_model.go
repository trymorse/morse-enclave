package attestation

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Service is one container as the pin checks and the release check read it: a docker compose service, or a
// Tinfoil container. Settings holds every other key, decoded as YAML decodes it.
type Service struct {
	Image       string
	Environment map[string]string
	Labels      map[string]string
	// Mounts lists the host paths and named volumes the service mounts, in the short `source:target` and the long
	// `source:` forms.
	Mounts   []string
	Settings map[string]any
}

// Strings lists every string the service holds, for a reader that looks for what any of them interpolates or pins.
func (s Service) Strings() []string {
	out := []string{s.Image}
	for _, set := range []map[string]string{s.Environment, s.Labels} {
		for k, v := range set {
			out = append(out, k, v)
		}
	}
	var walk func(any)
	walk = func(v any) {
		switch v := v.(type) {
		case string:
			out = append(out, v)
		case []any:
			for _, e := range v {
				walk(e)
			}
		case map[string]any:
			for _, e := range v {
				walk(e)
			}
		}
	}
	walk(s.Settings)
	return out
}

// TinfoilConfig is the YAML a Tinfoil deployment's base64 `config` holds.
type TinfoilConfig struct {
	Settings   map[string]any
	Containers []Service
}

func ParseTinfoilConfig(config []byte) (TinfoilConfig, error) {
	top, err := topLevel(string(config))
	if err != nil {
		return TinfoilConfig{}, err
	}
	c := TinfoilConfig{Settings: map[string]any{}}
	for _, key := range slices.Sorted(maps.Keys(top)) {
		node := top[key]
		if key != "containers" {
			if c.Settings[key], err = decodeAny(&node); err != nil {
				return TinfoilConfig{}, err
			}
			continue
		}
		list := resolve(&node)
		if list.Kind != yaml.SequenceNode {
			return TinfoilConfig{}, errors.New("containers is not a list")
		}
		for i, item := range list.Content {
			s, err := parseService(item, "env")
			if err != nil {
				return TinfoilConfig{}, fmt.Errorf("container %d: %w", i, err)
			}
			c.Containers = append(c.Containers, s)
		}
	}
	return c, nil
}

func resolve(n *yaml.Node) *yaml.Node {
	for n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

func decodeAny(n *yaml.Node) (any, error) {
	var v any
	if err := n.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// topLevel reads the one YAML document in text as a map of its top-level keys to their nodes. A key it repeats is an
// error, and so is a second document, which docker compose would merge into the first.
func topLevel(text string) (map[string]yaml.Node, error) {
	decoder := yaml.NewDecoder(strings.NewReader(text))
	var doc yaml.Node
	if err := decoder.Decode(&doc); err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, err
	}
	var rest yaml.Node
	if err := decoder.Decode(&rest); err != io.EOF {
		return nil, errors.New("holds more than one YAML document")
	}
	var top map[string]yaml.Node
	if err := doc.Decode(&top); err != nil {
		return nil, err
	}
	return top, nil
}

// parseComposeFile reads a docker compose file's services, and its other top-level settings but its x- extensions.
func parseComposeFile(text string) (map[string]any, map[string]Service, error) {
	top, err := topLevel(text)
	if err != nil {
		return nil, nil, fmt.Errorf("docker_compose_file is not YAML: %w", err)
	}
	settings, services := map[string]any{}, map[string]Service{}
	for _, key := range slices.Sorted(maps.Keys(top)) {
		node := top[key]
		switch {
		case key == "services":
			var named map[string]yaml.Node
			if err := node.Decode(&named); err != nil {
				return nil, nil, fmt.Errorf("docker_compose_file is not YAML: %w", err)
			}
			for _, name := range slices.Sorted(maps.Keys(named)) {
				n := named[name]
				if services[name], err = parseService(&n, "environment"); err != nil {
					return nil, nil, fmt.Errorf("service %s: %w", name, err)
				}
			}
		case strings.HasPrefix(key, "x-"):
		default:
			if settings[key], err = decodeAny(&node); err != nil {
				return nil, nil, fmt.Errorf("docker_compose_file is not YAML: %w", err)
			}
		}
	}
	return settings, services, nil
}

func parseService(n *yaml.Node, envKey string) (Service, error) {
	s := Service{Settings: map[string]any{}}
	n = resolve(n)
	if n.Kind == yaml.ScalarNode && n.Tag == "!!null" {
		return s, nil
	}
	var fields map[string]yaml.Node
	if err := n.Decode(&fields); err != nil {
		return Service{}, fmt.Errorf("is not YAML: %w", err)
	}
	for _, key := range slices.Sorted(maps.Keys(fields)) {
		node := fields[key]
		var err error
		switch key {
		case "image":
			if image := resolve(&node); image.Kind != yaml.ScalarNode {
				return Service{}, errors.New("image is not a string")
			} else {
				s.Image = image.Value
			}
		case envKey:
			s.Environment, err = keyed(&node, "environment")
		case "labels":
			s.Labels, err = keyed(&node, "labels")
		default:
			if key == "volumes" {
				if s.Mounts, err = mounts(&node); err != nil {
					return Service{}, err
				}
			}
			s.Settings[key], err = decodeAny(&node)
		}
		if err != nil {
			return Service{}, err
		}
	}
	return s, nil
}

// maxMerges bounds the `<<` merges one environment or labels may make, so aliases that merge aliases cannot expand
// without limit.
const maxMerges = 1000

type keyedSet struct {
	what             string
	explicit, merged map[string]string
	merges           *int
}

func (k *keyedSet) set(key, value string) error {
	if _, dup := k.explicit[key]; dup {
		return fmt.Errorf("%s sets %s twice", k.what, key)
	}
	k.explicit[key] = value
	return nil
}

func (k *keyedSet) all() map[string]string {
	all := maps.Clone(k.merged)
	maps.Copy(all, k.explicit)
	return all
}

func (k *keyedSet) mapping(n *yaml.Node) error {
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, v := resolve(n.Content[i]), resolve(n.Content[i+1])
		if key.Tag == "!!merge" {
			sources := []*yaml.Node{v}
			if v.Kind == yaml.SequenceNode {
				sources = v.Content
			}
			for _, m := range sources {
				if *k.merges++; *k.merges > maxMerges {
					return fmt.Errorf("%s merges more than %d maps", k.what, maxMerges)
				}
				if m = resolve(m); m.Kind != yaml.MappingNode {
					return fmt.Errorf("%s merges an entry that is not a map", k.what)
				}
				inner := &keyedSet{what: k.what, explicit: map[string]string{}, merged: map[string]string{}, merges: k.merges}
				if err := inner.mapping(m); err != nil {
					return err
				}
				for name, value := range inner.all() {
					if _, ok := k.merged[name]; !ok {
						k.merged[name] = value
					}
				}
			}
			continue
		}
		if key.Kind != yaml.ScalarNode || v.Kind != yaml.ScalarNode {
			return fmt.Errorf("%s maps an entry that is not a scalar", k.what)
		}
		if err := k.set(key.Value, v.Value); err != nil {
			return err
		}
	}
	return nil
}

// keyed reads compose's `K=V` list or `K: V` map, as an environment or labels give it, or Tinfoil's list of one-entry
// maps, as the names it sets and their values. A name set twice is an error, which a map would collapse to its last
// value. A name with no value, `K` alone, has the value "".
func keyed(n *yaml.Node, what string) (map[string]string, error) {
	n = resolve(n)
	k := &keyedSet{what: what, explicit: map[string]string{}, merged: map[string]string{}, merges: new(int)}
	switch {
	case n.Kind == 0, n.Kind == yaml.ScalarNode && n.Tag == "!!null":
	case n.Kind == yaml.SequenceNode:
		for _, item := range n.Content {
			switch item = resolve(item); item.Kind {
			case yaml.ScalarNode:
				key, value, _ := strings.Cut(item.Value, "=")
				if err := k.set(key, value); err != nil {
					return nil, err
				}
			case yaml.MappingNode:
				if err := k.mapping(item); err != nil {
					return nil, err
				}
			default:
				return nil, fmt.Errorf("%s lists an entry that is not a string", what)
			}
		}
	case n.Kind == yaml.MappingNode:
		if err := k.mapping(n); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%s is neither a list nor a map", what)
	}
	return k.all(), nil
}

func mounts(n *yaml.Node) ([]string, error) {
	n = resolve(n)
	if n.Kind == yaml.ScalarNode && n.Tag == "!!null" {
		return nil, nil
	}
	if n.Kind != yaml.SequenceNode {
		return nil, errors.New("volumes is not a list")
	}
	var sources []string
	for _, item := range n.Content {
		switch v := resolve(item); v.Kind {
		case yaml.ScalarNode:
			if source, _, ok := strings.Cut(v.Value, ":"); ok {
				sources = append(sources, source)
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(v.Content); i += 2 {
				if resolve(v.Content[i]).Value == "source" {
					sources = append(sources, resolve(v.Content[i+1]).Value)
				}
			}
		}
	}
	return sources, nil
}
