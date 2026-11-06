package wafer

// RefusesDryAccount is whether this adapter maps a dry Morse account at the vendor to an account refusal, which fails over
// and opens the endpoint's circuit, so a model may serve tiers on different terms through it (routes.FailoverOnOneTerm).
// Wafer documents no status for a dry account; its chat path takes apierr.SanitizedUpstreamError's default mapping of a
// 401 or 402 to upstream_unavailable. No dry account has answered a request yet.
const RefusesDryAccount = true
