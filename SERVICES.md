# Services the enclave calls

The worker calls these services.

Model and media vendors that serve the developer API, and the Morse Chat app too:

- DeepInfra, `api.deepinfra.com`
- Isoquant, `api.isoquant.ai`
- Morph, `api.morphllm.com`
- NEAR AI, `cloud-api.near.ai`
- Novita AI, `api.novita.ai`
- Phala, `inference.phala.com`
- Tinfoil, `inference.tinfoil.sh`
- Tinfoil's privacy filter, `pii-filter.tinfoil.sh`, which reads the text of a chat that asks for the Privacy Veil, over TLS pinned to the key its attested report binds
- Wafer, `pass.wafer.ai`

Model and media vendors that only the Morse Chat app reaches. An API key cannot list or call their models:

- Anthropic, `api.anthropic.com`
- fal, `queue.fal.run`
- Google, `generativelanguage.googleapis.com`
- Meta, `api.meta.ai`
- OpenAI, `api.openai.com`
- Parallel, `api.parallel.ai`
- Runware, `api.runware.ai`
- Venice, `api.venice.ai`
- xAI, `api.x.ai`

Lookup tools:

- Wikipedia, `en.wikipedia.org`
- Photon by komoot, `photon.komoot.io`
- MET Norway, `api.met.no`
- Frankfurter, `api.frankfurter.dev`
- CoinGecko, `api.coingecko.com` and `pro-api.coingecko.com`
- OpenAlex, `api.openalex.org`

Attestation checks for the NEAR AI, Phala and Tinfoil enclaves:

- NVIDIA's attestation service, `nras.attestation.nvidia.com`
- Intel's Provisioning Certification Service, for TDX collateral
- AMD's Key Distribution Service, `kdsintf.amd.com`, for the VCEK that signs a Tinfoil router's SEV-SNP report

Each plugin is the user's own account at its vendor. The worker calls the vendor's MCP server with the user's token, and sends the sign-in code and refresh token to the vendor's sign-in host. `internal/plugins/servers.go` pins each one's hosts:

Notion, Todoist, Trello, Linear, Granola, Wix, Airtable, Atlassian, Sentry, Vercel, monday, Neon, PostHog, Fireflies, Apollo, Grafana, tl;dv, Stripe, PayPal, Cloudflare, Zapier, ClickUp, Webflow, Netlify, Attio, Close, Calendly, Pipedream, Supabase, Miro and Jam.
