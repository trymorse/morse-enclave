package phala

// RefusesDryAccount is whether this adapter maps a dry Morse account at the vendor to an account refusal, which fails over
// and opens the endpoint's circuit, so a model may serve tiers on different terms through it (routes.FailoverOnOneTerm).
// A zero-balance Phala account answered a plaintext chat 402 insufficient_quota on 2026-11-04, which apierr.SanitizedUpstreamError maps to upstream_unavailable, and refuseSealed maps the documented "Balance is too low" 403 the same way. internal/phala/phalatest/testdata/dry-account-402.http replays the capture.
const RefusesDryAccount = true
