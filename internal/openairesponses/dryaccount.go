package openairesponses

// RefusesDryAccount is whether this adapter maps a dry Morse account at the vendor to an account refusal, which fails over
// and opens the endpoint's circuit, so a model may serve tiers on different terms through it (routes.FailoverOnOneTerm).
// OpenAI's status for an account out of credit is not documented, and none has been captured.
const RefusesDryAccount = false
