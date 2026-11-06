package anthropic

// RefusesDryAccount is whether this adapter maps a dry Morse account at the vendor to an account refusal, which fails over
// and opens the endpoint's circuit, so a model may serve tiers on different terms through it (routes.FailoverOnOneTerm).
// An empty Anthropic prepaid balance has a documented message and no documented status, and a spend limit we set is a 400 that stands as a bad request.
const RefusesDryAccount = false
