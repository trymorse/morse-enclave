package novita

// RefusesDryAccount is whether this adapter maps a dry Morse account at the vendor to an account refusal, which fails over
// and opens the endpoint's circuit, so a model may serve tiers on different terms through it (routes.FailoverOnOneTerm).
// Novita documents 402 for an insufficient balance; its chat path takes apierr.SanitizedUpstreamError's default mapping of
// a 401 or 402 to upstream_unavailable.
const RefusesDryAccount = true
