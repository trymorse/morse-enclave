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
	{
		ID:        "todoist",
		MCP:       "https://ai.todoist.net/mcp",
		Protocol:  June2025,
		Token:     "https://todoist.com/oauth/access_token",
		Issuer:    "https://todoist.com",
		Authorize: "https://todoist.com/oauth/authorize",
		Revoke:    "https://todoist.com/api/v1/revoke",
		Clients:   ClientDocuments("todoist"),
		Auth:      PublicClient,
		RPM:       600,
	},
	{
		ID:        "trello",
		MCP:       "https://mcp.trello.com/v1",
		Protocol:  June2025,
		Token:     "https://auth.atlassian.com/oauth/token",
		Issuer:    "https://auth.atlassian.com/VCeDsk8ZHncYF1g234fKtc4lNipbBhu3",
		Authorize: "https://auth.atlassian.com/authorize",
		Revoke:    "https://auth.atlassian.com/oauth/revoke",
		Clients:   ClientDocuments("trello"),
		Auth:      PublicClient,
		RPM:       600,
	},
	{
		ID:        "linear",
		MCP:       "https://mcp.linear.app/mcp",
		Protocol:  June2025,
		Token:     "https://mcp.linear.app/token",
		Issuer:    "https://mcp.linear.app",
		Authorize: "https://mcp.linear.app/authorize",
		Revoke:    "https://mcp.linear.app/token",
		Clients:   ClientDocuments("linear"),
		Auth:      PublicClient,
		RPM:       600,
	},
	{
		ID:        "granola",
		MCP:       "https://mcp.granola.ai/mcp",
		Protocol:  June2025,
		Token:     "https://mcp-auth.granola.ai/oauth2/token",
		Issuer:    "https://mcp-auth.granola.ai",
		Authorize: "https://mcp-auth.granola.ai/oauth2/authorize",
		Clients:   ClientDocuments("granola"),
		Auth:      PublicClient,
		RPM:       600,
	},
	{
		ID:        "wix",
		MCP:       "https://mcp.wix.com/mcp",
		Protocol:  June2025,
		Token:     "https://mcp.wix.com/token",
		Issuer:    "https://mcp.wix.com",
		Authorize: "https://mcp.wix.com/authorize",
		Revoke:    "https://mcp.wix.com/token",
		Clients:   map[string]string{"dev": "VmYFxjgbWjDKNuy2", "prod": "UhkGJPIXKeJKXr5K"},
		Auth:      PublicClient,
		RPM:       600,
	},
	{
		ID:        "airtable",
		MCP:       "https://mcp.airtable.com/mcp",
		Resource:  "https://mcp.airtable.com",
		Protocol:  June2025,
		Token:     "https://airtable.com/oauth2/v1/token",
		Issuer:    "https://airtable.com/oauth2/v1",
		Authorize: "https://airtable.com/oauth2/v1/authorize",
		Clients:   map[string]string{"dev": "fd3589c8-d227-4777-bb47-6e0b83a44ce0", "prod": "57005633-b4cb-411a-b1b0-6317b327f488"},
		Auth:      PublicClient,
		RPM:       600,
	},
	{
		ID:        "atlassian",
		MCP:       "https://mcp.atlassian.com/v2/mcp",
		Protocol:  June2025,
		Token:     "https://auth.atlassian.com/oauth/token",
		Issuer:    "https://auth.atlassian.com/VCeDsk8ZHncYF1g234fKtc4lNipbBhu3",
		Authorize: "https://auth.atlassian.com/authorize",
		Revoke:    "https://auth.atlassian.com/oauth/revoke",
		Clients:   ClientDocuments("atlassian"),
		Auth:      PublicClient,
		RPM:       600,
	},
	{
		ID:        "sentry",
		MCP:       "https://mcp.sentry.dev/mcp",
		Protocol:  June2025,
		Token:     "https://mcp.sentry.dev/oauth/token",
		Issuer:    "https://mcp.sentry.dev",
		Authorize: "https://mcp.sentry.dev/oauth/authorize",
		Revoke:    "https://mcp.sentry.dev/oauth/token",
		Clients:   ClientDocuments("sentry"),
		Auth:      PublicClient,
		RPM:       600,
	},
	{
		ID:        "vercel",
		MCP:       "https://mcp.vercel.com",
		Resource:  "https://mcp.vercel.com/",
		Protocol:  June2025,
		Token:     "https://api.vercel.com/login/oauth/token",
		Issuer:    "https://vercel.com",
		Authorize: "https://vercel.com/oauth/authorize",
		Revoke:    "https://api.vercel.com/login/oauth/token/revoke",
		Clients:   ClientDocuments("vercel"),
		Auth:      PublicClient,
		RPM:       600,
	},
	{
		ID:        "monday",
		MCP:       "https://mcp.monday.com/mcp",
		Protocol:  June2025,
		Token:     "https://auth.monday.com/oauth_ms/oauth/token",
		Issuer:    "https://auth.monday.com/mcp",
		Authorize: "https://auth.monday.com/oauth2/authorize",
		Revoke:    "https://auth.monday.com/oauth_ms/oauth/revoke",
		Clients:   ClientDocuments("monday"),
		Auth:      PublicClient,
		RPM:       600,
	},
	{
		ID:        "neon",
		MCP:       "https://mcp.neon.tech/mcp",
		Protocol:  June2025,
		Token:     "https://mcp.neon.tech/api/token",
		Issuer:    "https://mcp.neon.tech",
		Authorize: "https://mcp.neon.tech/api/authorize",
		Revoke:    "https://mcp.neon.tech/api/revoke",
		Clients:   ClientDocuments("neon"),
		Auth:      PublicClient,
		RPM:       600,
	},
	{
		ID:        "posthog",
		MCP:       "https://mcp.posthog.com/mcp",
		Protocol:  June2025,
		Token:     "https://oauth.posthog.com/oauth/token/",
		Issuer:    "https://oauth.posthog.com",
		Authorize: "https://oauth.posthog.com/oauth/authorize/",
		Revoke:    "https://oauth.posthog.com/oauth/revoke/",
		Clients:   ClientDocuments("posthog"),
		Auth:      PublicClient,
		RPM:       600,
	},
	{
		ID:        "fireflies",
		MCP:       "https://api.fireflies.ai/mcp",
		Protocol:  June2025,
		Token:     "https://api.fireflies.ai/token",
		Issuer:    "https://api.fireflies.ai/",
		Authorize: "https://api.fireflies.ai/authorize",
		Revoke:    "https://api.fireflies.ai/revoke",
		Clients:   ClientDocuments("fireflies"),
		Auth:      PublicClient,
		RPM:       600,
	},
	{
		ID:        "apollo",
		MCP:       "https://mcp.apollo.io/mcp",
		Protocol:  June2025,
		Token:     "https://mcp.apollo.io/api/v1/oauth/token",
		Issuer:    "https://mcp.apollo.io",
		Authorize: "https://mcp.apollo.io/mcp/oauth_metadata/redirect_to_authorize",
		Revoke:    "https://mcp.apollo.io/api/v1/oauth/revoke",
		Clients:   ClientDocuments("apollo"),
		Auth:      PublicClient,
		RPM:       600,
	},
	{
		ID:        "grafana",
		MCP:       "https://mcp.grafana.com/mcp",
		Protocol:  June2025,
		Token:     "https://mcp.grafana.com/mcp/oauth/token",
		Issuer:    "https://mcp.grafana.com/mcp",
		Authorize: "https://mcp.grafana.com/mcp/oauth/authorize",
		Clients:   ClientDocuments("grafana"),
		Auth:      PublicClient,
		RPM:       600,
	},
	{
		ID:        "tldv",
		MCP:       "https://mcp.tldv.io/mcp",
		Resource:  "https://mcp.tldv.io/",
		Protocol:  June2025,
		Token:     "https://keycloak.tldv.io/realms/mcp.tldv.io/protocol/openid-connect/token",
		Issuer:    "https://keycloak.tldv.io/realms/mcp.tldv.io",
		Authorize: "https://keycloak.tldv.io/realms/mcp.tldv.io/protocol/openid-connect/auth",
		Revoke:    "https://keycloak.tldv.io/realms/mcp.tldv.io/protocol/openid-connect/revoke",
		Clients:   ClientDocuments("tldv"),
		Auth:      PublicClient,
		RPM:       600,
	},
	{
		ID:        "stripe",
		MCP:       "https://mcp.stripe.com",
		Protocol:  June2025,
		Token:     "https://access.stripe.com/mcp/oauth2/token",
		Issuer:    "https://access.stripe.com/mcp",
		Authorize: "https://access.stripe.com/mcp/oauth2/authorize",
		Revoke:    "https://access.stripe.com/mcp/oauth2/revoke",
		Clients:   map[string]string{"dev": "oacli_Vbi7NLTLXpB8cJ", "prod": "oacli_Vbi7Sk8gAKj2UB"},
		Auth:      PublicClient,
		RPM:       600,
	},
	{
		ID:        "paypal",
		MCP:       "https://mcp.paypal.com/mcp",
		Protocol:  June2025,
		Token:     "https://mcp.paypal.com/token",
		Issuer:    "https://mcp.paypal.com",
		Authorize: "https://mcp.paypal.com/authorize",
		Revoke:    "https://mcp.paypal.com/token",
		Clients:   map[string]string{"dev": "mibxX0q9Q9llVa2J", "prod": "NkwtNBd_b3e-THce"},
		Auth:      PublicClient,
		RPM:       600,
	},
	{
		ID:        "cloudflare",
		MCP:       "https://bindings.mcp.cloudflare.com/mcp",
		Protocol:  June2025,
		Token:     "https://bindings.mcp.cloudflare.com/token",
		Issuer:    "https://bindings.mcp.cloudflare.com",
		Authorize: "https://bindings.mcp.cloudflare.com/oauth/authorize",
		Revoke:    "https://bindings.mcp.cloudflare.com/token",
		Clients:   map[string]string{"dev": "bG__EAoZc_D_Qv2z", "prod": "NNUTJW8nmu-U95VK"},
		Auth:      PublicClient,
		RPM:       600,
	},
	{
		ID:        "zapier",
		MCP:       "https://mcp.zapier.com/api/mcp/mcp",
		Protocol:  June2025,
		Token:     "https://mcp.zapier.com/api/v1/oauth/token",
		Issuer:    "https://mcp.zapier.com",
		Authorize: "https://mcp.zapier.com/oauth/authorize",
		Revoke:    "https://mcp.zapier.com/api/v1/oauth/revoke",
		Clients:   map[string]string{"dev": "Fjv8GhvsH3NDrMwPluuQJ00zgtBiH4MqsLSd3PR-g5s", "prod": "bChBkR5M0l6BnWIU0g2oCR8nmd8km4WaX_XX4TPhT5U"},
		Auth:      PublicClient,
		RPM:       600,
	},
	{
		ID:        "clickup",
		MCP:       "https://mcp.clickup.com/mcp",
		Protocol:  June2025,
		Token:     "https://mcp.clickup.com/oauth/token",
		Issuer:    "https://mcp.clickup.com",
		Authorize: "https://mcp.clickup.com/oauth/authorize",
		NoRefresh: true,
		Clients:   map[string]string{"dev": "mcp-client-eyJhbGciOiJIUzI1NiIsImtpZCI6IjEifQ.eyJ0b2tlblR5cGUiOiJqd3RfY2xpZW50X2lkIiwidXJpX2hhc2hlcyI6WyJ1SWlLS1pFWDQxR05tc0JjSTBUeGRRIl0sImlzcyI6ImNsaWNrdXAtbWNwLXNlcnZlciIsImlhdCI6MTc5NDM3NzI4M30.TE52AJOqj0WHI5xGEjpxgsM9py-HHDha7iDqDKw8i_k", "prod": "mcp-client-eyJhbGciOiJIUzI1NiIsImtpZCI6IjEifQ.eyJ0b2tlblR5cGUiOiJqd3RfY2xpZW50X2lkIiwidXJpX2hhc2hlcyI6WyIyeUNPeTc2WlhxUG1aRG9CYU9VYi1nIl0sImlzcyI6ImNsaWNrdXAtbWNwLXNlcnZlciIsImlhdCI6MTc5NDM3NzI4M30.5fpDJtarJfqN0ZOP0Zix9ZNIpFM4p_zWsQLn9rJt7E0"},
		Auth:      PublicClient,
		RPM:       600,
	},
	{
		ID:        "webflow",
		MCP:       "https://mcp.webflow.com/mcp",
		Protocol:  June2025,
		Token:     "https://mcp.webflow.com/oauth/token",
		Issuer:    "https://mcp.webflow.com",
		Authorize: "https://mcp.webflow.com/oauth/authorize",
		Revoke:    "https://mcp.webflow.com/oauth/token",
		Clients:   map[string]string{"dev": "WezhAntPtwn-NJg_", "prod": "bOp6c9Z7x_FJPHNp"},
		Auth:      PublicClient,
		RPM:       600,
	},
	{
		ID:        "netlify",
		MCP:       "https://netlify-mcp.netlify.app/mcp",
		Protocol:  June2025,
		Token:     "https://netlify-mcp.netlify.app/oauth-server/token",
		Issuer:    "https://netlify-mcp.netlify.app/",
		Authorize: "https://netlify-mcp.netlify.app/oauth-server/auth",
		Clients:   map[string]string{"dev": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..Rak0xksDcVtHB9E8.zbF5wtoc66QyKGyreyLkNSS-9CIiqIZmsZliFOb6ByetseQ7wy3m019q_T4mTxPTx1a-iRp6gA527Vd5F_LRn3NnshXi-U2LP_x4rgi31Go32C0teInMU2jLthglJFNCUCfcPrexi8To7KMtuyJfMBXBfjbILIaE632tERWpECSQ7MS7C6rxyJpLHzWzQvNDtkFwGN7OGdx5Ydh0OZbxWF1IBr5lSIOvfqe2sEjjIk_AU06I07xvUpZtIMp9r2FHASYlMAN9Rnr5EFcP6vjnx7k7i53aX7t33CPPtF7FYeI2aS7aqn4I5mlNtLYZX9YakaKKOxcQkTlxfw1BqjTPRaHO6I8hIyYauts3nrWORfcls62WzV4QqTJ4DO-XRTD0nZKuAjHsBejfHjyNXulmOLKhuEbqX98JMl6OUSrNjrSGDuoF_KvyfBwR2A.cddwliGJu6svMPvZBtLWew", "prod": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..eYJIx9EPO5cOyX2w.e2QVRHks8Yku4O_9A1BsNw_INHBY4hQuJb_BkhmN9M1pSxHnUarF3xN_TsF2LofJf77vmRrR3suoSZOtRsrn9uQm02eU8Gh9Wq50Hr03t5GtJMkpE9yIS0EwrOaDeevaLvt6uF0QAElOvNrcyBpsIe92Don7nsZyMWQS81mghcK9FjJIdBwj0_TEqtKZ7AB9wDxZBxI5heW55iqFR_nXGIv2If8LB60sUXoBHgLLwsl82Qda8hvEoq_SH6OOisMFeQKrmMlLA1MMadzGAMVikQRCQz_3h0rYHNXXVwLxmqDVP_sGVRXajTOQxXOypqJ_h8e60MVA54c-RcViJ8IRGNz7KtVfvkRRJQ4PbvS7XMMavIfiL7CrAIM98bkjrkQO-3w-EkYi-f-HlE3xMTNtvNQeHEkQdDyE5JCIlAIkSZDOpj0E.8fPPqqkzVEP61AI7nA6WXA"},
		Auth:      PublicClient,
		RPM:       600,
	},
	{
		ID:        "attio",
		MCP:       "https://mcp.attio.com/mcp",
		Protocol:  June2025,
		Token:     "https://app.attio.com/oidc/token",
		Issuer:    "https://app.attio.com",
		Authorize: "https://app.attio.com/oidc/authorize",
		Revoke:    "https://app.attio.com/oidc/revoke",
		Clients:   map[string]string{"dev": "e6b923fe-6d37-4837-9b35-3ea4f48f2219", "prod": "f3e934d9-0b39-41c7-98db-32d5618301e7"},
		Auth:      PublicClient,
		RPM:       600,
	},
	{
		ID:        "close",
		MCP:       "https://mcp.close.com/mcp",
		Protocol:  June2025,
		Token:     "https://api.close.com/oauth2/token/",
		Issuer:    "https://api.close.com",
		Authorize: "https://app.close.com/oauth2/authorize/",
		Revoke:    "https://api.close.com/oauth2/revoke/",
		Clients:   map[string]string{"dev": "oa2client_2HiZvb5jbX16o5y2OblGsT", "prod": "oa2client_705rrEBfgkMJT5Pd7mvL37"},
		Auth:      PublicClient,
		RPM:       600,
	},
	{
		ID:        "calendly",
		MCP:       "https://mcp.calendly.com",
		Resource:  "https://mcp.calendly.com/",
		Protocol:  June2025,
		Token:     "https://calendly.com/oauth/token",
		Issuer:    "https://calendly.com/",
		Authorize: "https://calendly.com/oauth/authorize",
		Clients:   map[string]string{"dev": "gsA1MYGog4xcEWdLoJOq-LKCHzaEK4MNbrHunuaDB0w", "prod": "qpE8m9_P8YUp_QZD59ptVn0AMcOAAcz-I9n9aVTcCCw"},
		Auth:      PublicClient,
		RPM:       600,
	},
	{
		ID:        "pipedream",
		MCP:       "https://mcp.pipedream.net/v2",
		Resource:  "https://mcp.pipedream.net",
		Protocol:  June2025,
		Token:     "https://mcp.pipedream.com/api/oauth/token",
		Issuer:    "https://mcp.pipedream.com",
		Authorize: "https://mcp.pipedream.com/api/oauth/authorize",
		Clients:   map[string]string{"dev": "dyn_M-VIMDCcp_I5KkA0", "prod": "dyn_ISgyIpeZUpdGRs35"},
		Auth:      PublicClient,
		RPM:       600,
	},
	{
		ID:        "supabase",
		MCP:       "https://mcp.supabase.com/mcp",
		Protocol:  June2025,
		Token:     "https://api.supabase.com/v1/oauth/token",
		Issuer:    "https://api.supabase.com",
		Authorize: "https://api.supabase.com/v1/oauth/authorize",
		Clients:   map[string]string{"dev": "79721b45-3e3c-4a7a-ba68-d0bccfb7ee9b", "prod": "4e4e0f59-fc25-472c-8e72-4fe4ff9476b6"},
		Auth:      SecretPost,
		SecretEnv: "PLUGIN_SUPABASE_CLIENT_SECRET",
		RPM:       600,
	},
	{
		ID:        "miro",
		MCP:       "https://mcp.miro.com",
		Resource:  "https://mcp.miro.com/",
		Protocol:  June2025,
		Token:     "https://mcp.miro.com/token",
		Issuer:    "https://mcp.miro.com/",
		Authorize: "https://mcp.miro.com/authorize",
		Clients:   map[string]string{"dev": "d0ebac88-802d-4772-9d14-dba07ebf8ebb", "prod": "bbdeca43-9991-4cdd-b2c2-a62e1d8c7aab"},
		Auth:      SecretPost,
		SecretEnv: "PLUGIN_MIRO_CLIENT_SECRET",
		RPM:       600,
	},
	{
		ID:        "jam",
		MCP:       "https://mcp.jam.dev/mcp",
		Protocol:  June2025,
		Token:     "https://api.jam.dev/oauth/token",
		Issuer:    "https://api.jam.dev",
		Authorize: "https://api.jam.dev/oauth/authorize",
		Revoke:    "https://api.jam.dev/oauth/revoke",
		Clients:   map[string]string{"dev": "TT6UBCaarAEDHzkTvEproozzXARE3GHD", "prod": "pah2KBidd9diTXqsHRUjzDTYIllJ0rWD"},
		Auth:      SecretPost,
		SecretEnv: "PLUGIN_JAM_CLIENT_SECRET",
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
