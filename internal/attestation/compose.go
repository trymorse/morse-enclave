package attestation

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strconv"
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
	// Manifest holds the manifest's other settings, as JSON decodes them, and Settings the compose file's other
	// top-level settings, but its x- extensions.
	Manifest map[string]any
	Settings map[string]any
	Services map[string]Service
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
	c := AppCompose{PreLaunchScript: manifest.PreLaunchScript, AllowedEnvs: manifest.AllowedEnvs, Manifest: map[string]any{}}
	for key, value := range fields {
		switch key {
		case "docker_compose_file", "pre_launch_script", "allowed_envs":
		default:
			var v any
			if err := json.Unmarshal(value, &v); err != nil {
				return AppCompose{}, fmt.Errorf("app_compose %s: %w", key, err)
			}
			c.Manifest[key] = v
		}
	}
	if c.Settings, c.Services, err = parseComposeFile(manifest.DockerComposeFile); err != nil {
		return AppCompose{}, err
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

type deployerVariables struct {
	listed   []string
	reviewed map[string]string
}

var nearReviewedInterpolations = map[string]string{
	"services.certbot-init.command":          "certonly --dns-cloudflare --dns-cloudflare-credentials /etc/cloudflare/credentials.ini --dns-cloudflare-propagation-seconds 30 --email ${CERTBOT_EMAIL} --agree-tos --no-eff-email --non-interactive --key-type ecdsa --elliptic-curve secp256r1 --cert-name completions.near.ai -d \"*.completions.near.ai\" -d \"completions.near.ai\" -d \"$HOSTNAME.hosts.near.ai\"\n",
	"configs.cloudflare_credentials.content": "dns_cloudflare_api_token = ${CLOUDFLARE_API_TOKEN}\n",
}

func checkDeployerVariables(raw string, reviewed map[string]string) error {
	fields, err := manifestFields(raw)
	if err != nil {
		return fmt.Errorf("app_compose is not JSON: %w", err)
	}
	var composeFile string
	var allowedEnvs []string
	for key, into := range map[string]any{"docker_compose_file": &composeFile, "allowed_envs": &allowedEnvs} {
		if value, ok := fields[key]; ok {
			if err := json.Unmarshal(value, into); err != nil {
				return fmt.Errorf("app_compose %s: %w", key, err)
			}
		}
	}
	d := deployerVariables{listed: allowedEnvs, reviewed: reviewed}
	for documents := yaml.NewDecoder(strings.NewReader(composeFile)); ; {
		var doc yaml.Node
		var expanded any
		err := documents.Decode(&doc)
		if err == io.EOF {
			return nil
		}
		if err == nil {
			err = doc.Decode(&expanded)
		}
		if err != nil {
			return fmt.Errorf("docker_compose_file is not YAML: %w", err)
		}
		if err := d.check(&doc, nil); err != nil {
			return err
		}
	}
}

func holdsDeployerData(path []string) bool {
	return len(path) == 3 && path[0] == "services" && (path[2] == "environment" || path[2] == "labels")
}

func (d deployerVariables) check(n *yaml.Node, path []string) error {
	n = resolve(n)
	data := holdsDeployerData(path)
	switch n.Kind {
	case yaml.DocumentNode:
		for _, child := range n.Content {
			if err := d.check(child, path); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for i, item := range n.Content {
			item = resolve(item)
			at := slices.Concat(path, []string{strconv.Itoa(i)})
			if data && item.Kind == yaml.ScalarNode {
				literal := len(item.Value)
				if name, _, ok := strings.Cut(item.Value, "="); ok {
					literal = len(name)
				}
				if err := d.checkScalar(at, item.Value, literal); err != nil {
					return err
				}
				continue
			}
			if err := d.check(item, at); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := resolve(n.Content[i]), resolve(n.Content[i+1])
			if k.Tag == "!!merge" {
				merged := []*yaml.Node{v}
				if v.Kind == yaml.SequenceNode {
					merged = v.Content
				}
				for _, m := range merged {
					if err := d.check(m, path); err != nil {
						return err
					}
				}
				continue
			}
			if len(path) == 0 && strings.HasPrefix(k.Value, "x-") {
				continue
			}
			at := slices.Concat(path, []string{k.Value})
			if err := d.check(k, at); err != nil {
				return err
			}
			if data && v.Kind == yaml.ScalarNode {
				continue
			}
			if err := d.check(v, at); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		return d.checkScalar(path, n.Value, len(n.Value))
	}
	return nil
}

func (d deployerVariables) checkScalar(path []string, text string, literal int) error {
	at := strings.Join(path, ".")
	if reviewed, ok := d.reviewed[at]; ok && reviewed == text {
		return nil
	}
	for _, name := range Names(text[:literal]) {
		if slices.Contains(d.listed, name) {
			return fmt.Errorf("%s is %.200q, which interpolates %s, and allowed_envs lets the deployer set it", at, text, name)
		}
	}
	return nil
}
