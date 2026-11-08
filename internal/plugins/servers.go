// Package plugins calls the MCP servers of the vendors a user connects, from inside the enclave, under the
// user's own token for each call. The device seals each call to the worker, which checks it, re-encodes it, and
// sends it only to the server's pinned address; nothing about it is kept or logged. The web app's design is
// docs/design/plugins.md in the frontend repository.
package plugins

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
)

// Revision is an MCP revision a server speaks, which decides the session and the headers its calls carry.
type Revision string

const (
	June2025     Revision = "2025-06-18"
	November2025 Revision = "2025-11-25"
	// July2026 is the first stateless revision: no initialize, no session, and every request carries the revision,
	// the client's capabilities, and its name in params._meta.
	July2026 Revision = "2026-07-28"
)

var revisions = []Revision{June2025, November2025, July2026}

func (r Revision) stateless() bool { return r == July2026 }

// ClientAuth is how Morse's client authenticates at a server's token and revocation endpoints.
type ClientAuth uint8

const (
	PublicClient ClientAuth = iota
	SecretPost
	SecretBasic
)

// Server is one vendor's MCP server, pinned. The web app's catalog holds the same id, endpoint, revision, and
// clients, and the device builds the sign-in from it; the worker sends to nothing but these addresses.
type Server struct {
	ID string
	// MCP is the only address the server's calls go to, and the resource its tokens are asked for (RFC 8707) unless
	// Resource names another.
	MCP string
	// Resource is the resource its tokens are asked for, where the server publishes one other than MCP, such as its
	// whole origin.
	Resource string
	Protocol Revision
	Token    string
	// Revoke is the server's RFC 7009 revocation endpoint, or empty where it has none.
	Revoke string
	// Issuer and Authorize are the authorization server's name and where a sign-in starts, which only the device
	// uses. They're pinned here so the hourly watch sees either move, which would refuse or break every sign-in.
	Issuer    string
	Authorize string
	// Clients holds Morse's client id at the server for each environment, each registered with that
	// environment's callback alone.
	Clients map[string]string
	Auth    ClientAuth
	// SecretEnv names the variable that holds a confidential client's secret, which the host supplies.
	SecretEnv string
	// RPM is how many calls a minute one worker sends the server, across every user.
	RPM int
	// OlderDiscovery is a server on MCP's older discovery, which publishes no protected resource metadata and keeps
	// its authorization server at its own origin. The hourly watch goes by that for it, and for no other.
	OlderDiscovery bool
	// NoRefresh is a server that never granted refresh tokens, so a user signs in again when a token expires. The
	// hourly watch alerts on any other server that stops granting them.
	NoRefresh bool
}

// Servers are the plugins Morse offers. `make plugin-add` adds one, once `make plugin-probe` says its vendor is ready,
// as the web app's design says under Adding a plugin. cmd/pluginwatch checks every hour that each vendor still publishes
// the endpoints pinned here.
var Servers = []Server{
	{
		// Notion's authorization server publishes its revocation endpoint at the token endpoint's address, and takes
		// a client metadata document's URL as a client id, so Morse's client at Notion is the document the web app
		// serves for each environment, a public client with PKCE.
		ID:        "notion",
		MCP:       "https://mcp.notion.com/mcp",
		Protocol:  June2025,
		Token:     "https://mcp.notion.com/token",
		Issuer:    "https://mcp.notion.com",
		Authorize: "https://mcp.notion.com/authorize",
		Revoke:    "https://mcp.notion.com/token",
		Clients:   ClientDocuments("notion"),
		Auth:      PublicClient,
		RPM:       600,
	},
}

// ClientDocuments are the client ids of a server that takes a client metadata document's URL as one: the document
// the web app serves for it in each environment, which names that environment's callback alone.
func ClientDocuments(id string) map[string]string {
	clients := map[string]string{}
	for environment, origin := range Origins {
		clients[environment] = origin + clientDocumentPath + id + ".json"
	}
	return clients
}

const clientDocumentPath = "/plugins/clients/"

// TokenResource is the resource (RFC 8707) the server's tokens are asked for.
func (s Server) TokenResource() string {
	if s.Resource != "" {
		return s.Resource
	}
	return s.MCP
}

// Callback is where a server sends a sign-in's code back in environment.
func (s Server) Callback(environment string) string { return s.callback(environment) }

// Origins are where the web app runs in each environment, to whose callback a server sends its code back.
var Origins = map[string]string{"prod": "https://trymorse.ai", "dev": "https://vault.watermark.ac"}

const callbackPath = "/plugins/callback/"

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)

var errNoServer = errors.New("plugins: no such server")

func (s Server) callback(environment string) string {
	return Origins[environment] + callbackPath + s.ID
}

// Validate refuses a server the worker could not call safely: an address that isn't https, a revision it doesn't
// speak, a client missing for an environment, or a secret that is named where none is sent or sent where none is
// named.
func (s Server) Validate() error {
	if !idPattern.MatchString(s.ID) {
		return fmt.Errorf("plugins: server id %q", s.ID)
	}
	for name, raw := range map[string]string{"MCP": s.MCP, "Resource": s.Resource, "Token": s.Token, "Revoke": s.Revoke} {
		if raw == "" && (name == "Revoke" || name == "Resource") {
			continue
		}
		if err := pinned(raw); err != nil {
			return fmt.Errorf("plugins: %s's %s: %w", s.ID, name, err)
		}
	}
	if !slices.Contains(revisions, s.Protocol) {
		return fmt.Errorf("plugins: %s speaks %q, which the worker doesn't", s.ID, s.Protocol)
	}
	for environment := range Origins {
		if s.Clients[environment] == "" {
			return fmt.Errorf("plugins: %s has no client in %s", s.ID, environment)
		}
	}
	if (s.Auth == PublicClient) != (s.SecretEnv == "") {
		return fmt.Errorf("plugins: %s names a secret only a confidential client may have", s.ID)
	}
	if s.RPM <= 0 {
		return fmt.Errorf("plugins: %s has no rate", s.ID)
	}
	return nil
}

func pinned(raw string) error {
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return err
	case u.Scheme != "https" || u.Host == "" || u.User != nil:
		return errors.New("not an https address")
	case u.RawQuery != "" || u.Fragment != "" || u.Opaque != "":
		return errors.New("an address with a query or a fragment")
	}
	return nil
}

// SecretEnvs are the variables the confidential clients' secrets come in, which the enclave takes from the host.
func SecretEnvs(servers []Server) []string {
	var names []string
	for _, s := range servers {
		if s.SecretEnv != "" {
			names = append(names, s.SecretEnv)
		}
	}
	return names
}
