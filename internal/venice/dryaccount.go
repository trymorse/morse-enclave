package venice

// RefusesDryAccount is whether this adapter maps a dry Morse account at the vendor to an account refusal, which fails over
// and opens the endpoint's circuit, so a model may serve tiers on different terms through it (routes.FailoverOnOneTerm).
// Venice documents 402 INSUFFICIENT_BALANCE and the two spend-limit codes for a dry account, and its chat path takes apierr.SanitizedUpstreamError's default mapping of a 402 to upstream_unavailable. No dry account has answered a request yet.
const RefusesDryAccount = true
