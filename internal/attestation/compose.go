package attestation

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	composeRepoURLKey    = "PRIVATE_AI_GATEWAY_REPO_URL"
	composeRepoCommitKey = "PRIVATE_AI_GATEWAY_REPO_COMMIT"
	repoURLScheme        = "https://"
	sourceCommitSep      = "@"
)

var (
	repoCommitForm    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPinnedImage = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:-]*@sha256:[0-9a-f]{64}$`)
)

// AppCompose is the measured app_compose: dstack's manifest and the docker compose file it runs.
type AppCompose struct {
	PreLaunchScript string
	AllowedEnvs     []string
	Services        map[string]Service
}

type Service struct {
	Image       string
	Environment map[string]string
	Mounts      []string
}

func ParseAppCompose(raw string) (AppCompose, error) {
	fields, err := manifestFields(raw)
	if err != nil {
		return AppCompose{}, fmt.Errorf("app_compose is not JSON: %w", err)
	}
	var manifest struct {
		DockerComposeFile string
		PreLaunchScript   string
		AllowedEnvs       []string
	}
	for key, into := range map[string]any{
		"docker_compose_file": &manifest.DockerComposeFile,
		"pre_launch_script":   &manifest.PreLaunchScript,
		"allowed_envs":        &manifest.AllowedEnvs,
	} {
		if value, ok := fields[key]; ok {
			if err := json.Unmarshal(value, into); err != nil {
				return AppCompose{}, fmt.Errorf("app_compose %s: %w", key, err)
			}
		}
	}
	var file struct {
		Services map[string]struct {
			Image       string      `yaml:"image"`
			Environment yaml.Node   `yaml:"environment"`
			Volumes     []yaml.Node `yaml:"volumes"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(manifest.DockerComposeFile), &file); err != nil {
		return AppCompose{}, fmt.Errorf("docker_compose_file is not YAML: %w", err)
	}
	c := AppCompose{PreLaunchScript: manifest.PreLaunchScript, AllowedEnvs: manifest.AllowedEnvs, Services: map[string]Service{}}
	for name, s := range file.Services {
		env, err := environment(&s.Environment)
		if err != nil {
			return AppCompose{}, fmt.Errorf("service %s: %w", name, err)
		}
		c.Services[name] = Service{Image: s.Image, Environment: env, Mounts: mounts(s.Volumes)}
	}
	return c, nil
}

// manifestFields reads the manifest's top-level keys by their exact names, as dstack does. encoding/json would match
// a struct field case-insensitively and take the last of several spellings, so the checks could read a compose
// other than the one dstack runs.
func manifestFields(raw string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(strings.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("not an object")
	}
	fields := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := tok.(string)
		if _, seen := fields[key]; seen {
			return nil, fmt.Errorf("repeats %q", key)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		fields[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("holds more than one value")
	}
	return fields, nil
}

func resolve(n *yaml.Node) *yaml.Node {
	for n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

func environment(n *yaml.Node) (map[string]string, error) {
	n = resolve(n)
	env := map[string]string{}
	set := func(key, value string) error {
		if _, dup := env[key]; dup {
			return fmt.Errorf("environment sets %s twice", key)
		}
		env[key] = value
		return nil
	}
	switch {
	case n.Kind == 0, n.Kind == yaml.ScalarNode && n.Tag == "!!null":
	case n.Kind == yaml.SequenceNode:
		for _, item := range n.Content {
			if item = resolve(item); item.Kind != yaml.ScalarNode {
				return nil, errors.New("environment lists an entry that is not a string")
			}
			key, value, _ := strings.Cut(item.Value, "=")
			if err := set(key, value); err != nil {
				return nil, err
			}
		}
	case n.Kind == yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := resolve(n.Content[i]), resolve(n.Content[i+1])
			if k.Kind != yaml.ScalarNode || v.Kind != yaml.ScalarNode {
				return nil, errors.New("environment maps an entry that is not a scalar")
			}
			if err := set(k.Value, v.Value); err != nil {
				return nil, err
			}
		}
	default:
		return nil, errors.New("environment is neither a list nor a map")
	}
	return env, nil
}

// mounts lists the host paths and named volumes a service mounts, in the short `source:target` and the
// long `source:` forms.
func mounts(volumes []yaml.Node) []string {
	var sources []string
	for i := range volumes {
		switch v := resolve(&volumes[i]); v.Kind {
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
	return sources
}

type launcher struct {
	service string
	image   string
	repoURL string
	commit  string
}

// launcher is the one service whose measured environment names the gateway source it builds. Its image
// is what runs that build, so it must be a digest the pins can compare.
func (c AppCompose) launcher() (launcher, error) {
	var setting []string
	for _, name := range slices.Sorted(maps.Keys(c.Services)) {
		env := c.Services[name].Environment
		_, hasURL := env[composeRepoURLKey]
		_, hasCommit := env[composeRepoCommitKey]
		if hasURL || hasCommit {
			setting = append(setting, name)
		}
	}
	if len(setting) != 1 {
		return launcher{}, fmt.Errorf("%d services set %s or %s in their environment, want 1: %s", len(setting), composeRepoURLKey, composeRepoCommitKey, strings.Join(setting, ", "))
	}
	name := setting[0]
	s := c.Services[name]
	l := launcher{service: name, image: s.Image, repoURL: s.Environment[composeRepoURLKey], commit: s.Environment[composeRepoCommitKey]}
	switch {
	case strings.ContainsRune(l.repoURL+l.commit, '$'):
		return launcher{}, fmt.Errorf("service %s interpolates %s=%q or %s=%q, want literals", name, composeRepoURLKey, l.repoURL, composeRepoCommitKey, l.commit)
	case !strings.HasPrefix(l.repoURL, repoURLScheme):
		return launcher{}, fmt.Errorf("service %s sets %s=%q, not an %s URL", name, composeRepoURLKey, l.repoURL, repoURLScheme)
	case !repoCommitForm.MatchString(l.commit):
		return launcher{}, fmt.Errorf("service %s sets %s=%q, not 40 lowercase hex", name, composeRepoCommitKey, l.commit)
	case !digestPinnedImage.MatchString(l.image):
		return launcher{}, fmt.Errorf("service %s runs image %q, not one pinned by sha256 digest", name, l.image)
	case slices.Contains(c.AllowedEnvs, composeRepoURLKey) || slices.Contains(c.AllowedEnvs, composeRepoCommitKey):
		return launcher{}, fmt.Errorf("allowed_envs lets the deployer set %s or %s", composeRepoURLKey, composeRepoCommitKey)
	}
	return l, nil
}
