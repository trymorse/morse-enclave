package gemini

// RefusesDryAccount is whether this adapter maps a dry Morse account at the vendor to an account refusal, which fails over
// and opens the endpoint's circuit, so a model may serve tiers on different terms through it (routes.FailoverOnOneTerm).
// Gemini's docs name no status for a dry billing account, and its 403 PERMISSION_DENIED maps to upstream_refused.
const RefusesDryAccount = false
