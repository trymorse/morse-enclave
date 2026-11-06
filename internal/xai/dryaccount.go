package xai

// RefusesDryAccount is whether this adapter maps a dry Morse account at the vendor to an account refusal, which fails over
// and opens the endpoint's circuit, so a model may serve tiers on different terms through it (routes.FailoverOnOneTerm).
// xAI's docs say only that requests are rejected once prepaid credit runs out. The status is unknown until a depleted key answers.
const RefusesDryAccount = false
