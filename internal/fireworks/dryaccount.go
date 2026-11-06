package fireworks

// RefusesDryAccount is whether this adapter maps a dry Morse account at the vendor to an account refusal, which fails over
// and opens the endpoint's circuit, so a model may serve tiers on different terms through it (routes.FailoverOnOneTerm).
// Fireworks documents 402 for usage limits, and its chat path takes apierr.SanitizedUpstreamError's default mapping of a 402 to upstream_unavailable. Its 412 for a suspended account maps to invalid_request. No dry account has answered a request yet.
const RefusesDryAccount = true
