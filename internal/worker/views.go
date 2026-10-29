package worker

import (
	"morse/backend/internal/jobs"
	"morse/backend/internal/research"
)

type JobError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type VideoView struct {
	ID        string    `json:"id"`
	Object    string    `json:"object"`
	Model     string    `json:"model"`
	Status    string    `json:"status"`
	Progress  int       `json:"progress"`
	CreatedAt int64     `json:"created_at"`
	ExpiresAt *int64    `json:"expires_at"`
	Error     *JobError `json:"error"`
}

type ResearchView struct {
	ID        string           `json:"id"`
	Object    string           `json:"object"`
	Model     string           `json:"model"`
	Status    string           `json:"status"`
	CreatedAt int64            `json:"created_at"`
	Error     *JobError        `json:"error,omitempty"`
	Output    *research.Output `json:"output,omitempty"`
}

var researchFailures = [...]string{
	jobs.UpstreamError: "The research provider failed to finish the research.",
	jobs.Timeout:       "The research provider did not finish the research in time.",
}
