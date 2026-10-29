package attestation

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"morse/backend/internal/nras"
)

var (
	ErrGPU        = errors.New("attestation: the GPU evidence does not verify")
	ErrGPUService = errors.New("attestation: NVIDIA's attestation service could not be reached, so the GPU evidence was not judged")
)

type GPUVerifier interface {
	VerifyGPU(ctx context.Context, payload []byte, nonce [32]byte, now time.Time) (nras.Verdict, error)
}

func (p Policy) verifyGPU(ctx context.Context, payload []byte, commitment [sha256.Size]byte, now time.Time) (nras.Verdict, error) {
	verdict, err := p.gpu.VerifyGPU(ctx, payload, commitment, now)
	switch {
	case err == nil:
		return verdict, nil
	case errors.Is(err, nras.ErrUnreachable):
		return nras.Verdict{}, Outage{Err: fmt.Errorf("%w: %w", ErrGPUService, err)}
	}
	return nras.Verdict{}, fmt.Errorf("%w: %w", ErrGPU, err)
}

func gpuModels(verdict nras.Verdict) ([]string, error) {
	seen := map[string]bool{}
	models := make([]string, 0, len(verdict.GPUs))
	for _, g := range verdict.GPUs {
		if g.UEID == "" || seen[g.UEID] {
			return nil, fmt.Errorf("%w: %s repeats or lacks a ueid (%q), so the evidence may describe fewer GPUs than it claims", ErrGPU, g.Name, g.UEID)
		}
		seen[g.UEID] = true
		models = append(models, g.Arch)
	}
	return models, nil
}
