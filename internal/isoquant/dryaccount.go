package isoquant

// RefusesDryAccount is whether this adapter maps a dry Morse account at the vendor to an account refusal, which fails over
// and opens the endpoint's circuit, so a model may serve tiers on different terms through it (routes.FailoverOnOneTerm).
// Isoquant answers 402 when the balance cannot cover a request's max_tokens (the scout's report of 2026-11-05, not a
// captured reply), and its chat path takes apierr.SanitizedUpstreamError's default mapping of a 402 to upstream_unavailable.
// A model the key may not use answers 403 model_forbidden (captured 2026-11-05), which apierr maps to the same account
// refusal. No dry account has answered a request yet.
const RefusesDryAccount = true
