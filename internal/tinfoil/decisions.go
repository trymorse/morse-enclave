package tinfoil

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"morse/backend/internal/e2ee/ehbp"
	"morse/backend/internal/promptcheck"
	"morse/backend/internal/upstream"
)

const (
	decisionsPath = "/v1/decisions"
	maxDecision   = 64 << 10
	DecisionSmall = "decision-small"
	DecisionLarge = "decision-large"
)

type PromptChecker struct {
	endpoint upstream.Endpoint
	gate     Gate
	model    string
	sealTo   func() ([32]byte, bool)
}

var _ promptcheck.Scorer = (*PromptChecker)(nil)

func NewPromptChecker(baseURL, apiKey, model string, pinned *http.Client, gate Gate, sealTo func() ([32]byte, bool)) *PromptChecker {
	return &PromptChecker{endpoint: upstream.Endpoint{BaseURL: baseURL, Auth: upstream.Bearer(apiKey), HTTP: pinned, Refuse: refuseDecision}, gate: gate, model: model, sealTo: sealTo}
}

func refuseDecision(r upstream.Reply) error {
	if r.Status == http.StatusUnprocessableEntity && bytes.Contains(r.Body, []byte(keyConfigProblem)) {
		return errKeyStale
	}
	if r.Status == http.StatusTooManyRequests {
		return promptcheck.ErrBusy
	}
	return fmt.Errorf("tinfoil: the decision model answered %d", r.Status)
}

type question struct {
	Type         string `json:"type"`
	Name         string `json:"name"`
	Instructions string `json:"instructions"`
}

const (
	minorName  = "minor"
	realName   = "real_person"
	sexualName = "sexual"
)

var questions = []question{
	{"predicate", minorName, promptcheck.MinorQuestion},
	{"predicate", realName, promptcheck.RealPersonQuestion},
	{"predicate", sexualName, promptcheck.SexualQuestion},
}

func (c *PromptChecker) Score(ctx context.Context, prompt string) (promptcheck.Scores, error) {
	if !c.gate.Ready() {
		return promptcheck.Scores{}, promptcheck.ErrUnattested
	}
	key, ok := c.sealTo()
	if !ok {
		return promptcheck.Scores{}, promptcheck.ErrUnattested
	}
	body, err := json.Marshal(struct {
		Model     string     `json:"model"`
		Input     string     `json:"input"`
		Questions []question `json:"questions"`
	}{c.model, prompt, questions})
	if err != nil {
		return promptcheck.Scores{}, err
	}
	_, plain, err := postSealed(ctx, c.endpoint, key, decisionsPath, http.Header{ehbp.HeaderModel: {c.model}}, body, maxDecision)
	switch {
	case errors.Is(err, errKeyStale):
		c.gate.Wake()
		return promptcheck.Scores{}, promptcheck.ErrUnattested
	case errors.Is(err, upstream.ErrMalformed):
		return promptcheck.Scores{}, promptcheck.ErrMalformed
	case err != nil:
		return promptcheck.Scores{}, err
	}
	return scoresOf(plain)
}

func scoresOf(plain []byte) (promptcheck.Scores, error) {
	var out struct {
		Answers []struct {
			Name        string   `json:"name"`
			Probability *float64 `json:"probability"`
		} `json:"answers"`
	}
	if json.Unmarshal(plain, &out) != nil || len(out.Answers) != len(questions) {
		return promptcheck.Scores{}, promptcheck.ErrMalformed
	}
	var s promptcheck.Scores
	into := map[string]*float64{minorName: &s.Minor, realName: &s.RealPerson, sexualName: &s.Sexual}
	for _, a := range out.Answers {
		score, asked := into[a.Name]
		if !asked || a.Probability == nil || !(*a.Probability >= 0 && *a.Probability <= 1) {
			return promptcheck.Scores{}, promptcheck.ErrMalformed
		}
		*score = *a.Probability
		delete(into, a.Name)
	}
	return s, nil
}
