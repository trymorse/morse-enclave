package attestation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"morse/backend/internal/aci"
)

const (
	teeTypeTDX        = "tdx"
	reportDataPurpose = "aci.report_data.v1"
)

var (
	ErrTEEType       = errors.New("attestation: tee_type is not tdx")
	ErrKeyset        = errors.New("attestation: workload_keyset is not the well-formed keyset workload_keyset_digest names")
	ErrKeysetExpired = errors.New("attestation: workload_keyset is past not_after")
	ErrReportData    = errors.New("attestation: report_data is not bound to this nonce and keyset")
	ErrNoTLSKey      = errors.New("attestation: the verified Phala keyset lists no TLS key for the gateway host")
)

type PhalaReport struct {
	OSMeasurement
	GatewayAnchors
	Release    Release
	InstanceID string
	RTMR3      Register
	Keyset     aci.Keyset
	VMConfig   json.RawMessage
	Endpoint   Endpoint[aci.SPKI]
}

type Workload struct {
	OSMeasurement
	GatewayAnchors
	ComposeHash string `json:"compose_hash"`
	// AppCompose is the compose text whose sha256 is ComposeHash.
	AppCompose string   `json:"-"`
	InstanceID string   `json:"instance_id"`
	RTMR3      Register `json:"rtmr3"`
	TCB        TCB      `json:"tcb"`
}

type phalaReport struct {
	Attestation struct {
		TEEType          string `json:"tee_type"`
		ReportData       string `json:"report_data"`
		SourceProvenance struct {
			RepoURL    string `json:"repo_url"`
			RepoCommit string `json:"repo_commit"`
		} `json:"source_provenance"`
		Evidence dstackEvidence `json:"evidence"`
	} `json:"attestation"`
}

type dstackEvidence struct {
	Quote      string          `json:"quote"`
	EventLog   json.RawMessage `json:"event_log"`
	AppCompose string          `json:"app_compose"`
	VMConfig   json.RawMessage `json:"vm_config"`
}

func ReportData(keysetDigest aci.Hash, n Nonce) [sha256.Size]byte {
	statement := `{"keyset_digest":"` + keysetDigest.String() + `","nonce":"` + n.String() + `","purpose":"` + reportDataPurpose + `"}`
	return sha256.Sum256([]byte(statement))
}

func (p Policy) VerifyPhala(ctx context.Context, raw []byte, nonce Nonce, host string) (PhalaReport, error) {
	v, err := p.VerifyPhalaUnboundToHost(ctx, raw, nonce)
	if err != nil {
		return PhalaReport{}, err
	}
	for _, k := range v.Keyset.TLSKeys {
		if k.Domain == host {
			v.Endpoint.Keys = append(v.Endpoint.Keys, k.SPKI)
		}
	}
	if len(v.Endpoint.Keys) == 0 {
		return PhalaReport{}, fmt.Errorf("%w %s", ErrNoTLSKey, host)
	}
	return v, nil
}

func (p Policy) VerifyPhalaUnboundToHost(ctx context.Context, raw []byte, nonce Nonce) (PhalaReport, error) {
	var r phalaReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return PhalaReport{}, fmt.Errorf("attestation: report is not JSON: %w", err)
	}
	a := r.Attestation
	now := p.now()

	if a.TEEType != teeTypeTDX {
		return PhalaReport{}, fmt.Errorf("%w: %q", ErrTEEType, a.TEEType)
	}
	keyset, err := aci.ParseKeyset(raw)
	if err != nil {
		return PhalaReport{}, fmt.Errorf("%w: %w", ErrKeyset, err)
	}
	if !now.Before(keyset.NotAfter) {
		return PhalaReport{}, fmt.Errorf("%w: not_after %s, now %s", ErrKeysetExpired, keyset.NotAfter.Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	bound := ReportData(keyset.Digest, nonce)
	if a.ReportData != hex.EncodeToString(bound[:]) {
		return PhalaReport{}, fmt.Errorf("%w: report_data %s, nonce %s, keyset %s", ErrReportData, a.ReportData, nonce, keyset.Digest)
	}
	var want [quoteReportDataLen]byte
	copy(want[:], bound[:])
	w, err := p.measure(ctx, a.Evidence, want, now, requireUpToDate)
	if err != nil {
		return PhalaReport{}, err
	}
	prov := a.SourceProvenance
	l, err := checkProvenance(a.Evidence.AppCompose, prov.RepoURL, prov.RepoCommit)
	if err != nil {
		return PhalaReport{}, err
	}
	return PhalaReport{
		OSMeasurement:  w.OSMeasurement,
		GatewayAnchors: w.GatewayAnchors,
		Release:        Release{Source: l.repoURL + sourceCommitSep + l.commit, ComposeHash: w.ComposeHash, LauncherImage: l.image},
		InstanceID:     w.InstanceID,
		RTMR3:          w.RTMR3,
		Keyset:         keyset,
		VMConfig:       a.Evidence.VMConfig,
		Endpoint:       Endpoint[aci.SPKI]{ID: keyset.Digest.String(), NotAfter: keyset.NotAfter},
	}, nil
}

func (p Policy) measure(ctx context.Context, ev dstackEvidence, want [quoteReportDataLen]byte, now time.Time, tcb tcbPolicy) (Workload, error) {
	quote, err := hex.DecodeString(ev.Quote)
	if err != nil {
		return Workload{}, fmt.Errorf("%w: quote is not hex: %w", ErrQuote, err)
	}
	body, standing, err := p.quoteBoundTo(ctx, quote, want, now, tcb)
	if err != nil {
		return Workload{}, err
	}
	events, err := parseEventLog(ev.EventLog)
	if err != nil {
		return Workload{}, err
	}
	m := measured(body)
	if replayed := replayRuntime(events); Register(replayed) != m.RTMR3 {
		return Workload{}, fmt.Errorf("%w: replay %x, quote %s", ErrEventLog, replayed, m.RTMR3)
	}
	runtime, err := runtimeMeasurements(events)
	if err != nil {
		return Workload{}, err
	}
	composeHash := sha256.Sum256([]byte(ev.AppCompose))
	if !bytes.Equal(composeHash[:], runtime.composeHash) {
		return Workload{}, fmt.Errorf("%w: sha256(app_compose) %x, measured %x", ErrComposeHash, composeHash, runtime.composeHash)
	}
	if err := checkConfigID(body.GetMrConfigId(), composeHash); err != nil {
		return Workload{}, err
	}
	keyProvider, err := keyProviderID(runtime.keyProvider)
	if err != nil {
		return Workload{}, err
	}
	return Workload{
		OSMeasurement:  OSMeasurement{OSImageHash: hex.EncodeToString(runtime.osImageHash), Boot: m.Boot},
		GatewayAnchors: GatewayAnchors{TDAttributes: m.TDAttributes, AppID: hex.EncodeToString(runtime.appID), KeyProviderID: keyProvider},
		ComposeHash:    hex.EncodeToString(composeHash[:]),
		AppCompose:     ev.AppCompose,
		InstanceID:     hex.EncodeToString(runtime.instanceID),
		RTMR3:          m.RTMR3,
		TCB:            standing,
	}, nil
}

func checkConfigID(mrConfigID []byte, composeHash [sha256.Size]byte) error {
	var want [configIDLen]byte
	want[0] = configIDComposeHash
	copy(want[1:], composeHash[:])
	if !bytes.Equal(mrConfigID, want[:]) {
		return fmt.Errorf("%w: mrconfigid %x, want %x", ErrConfigID, mrConfigID, want)
	}
	return nil
}

// checkProvenance reads the source the measured compose's launcher builds and requires the report to
// claim that source, so the release names what the quote measured rather than what the gateway says.
func checkProvenance(compose, repoURL, repoCommit string) (launcher, error) {
	c, err := ParseAppCompose(compose)
	if err != nil {
		return launcher{}, fmt.Errorf("%w: %w", ErrProvenance, err)
	}
	l, err := c.launcher()
	if err != nil {
		return launcher{}, fmt.Errorf("%w: %w", ErrProvenance, err)
	}
	if l.repoURL != repoURL || l.commit != repoCommit {
		return launcher{}, fmt.Errorf("%w: the launcher service %s builds %s%s%s, the report claims %s%s%s", ErrProvenance, l.service, l.repoURL, sourceCommitSep, l.commit, repoURL, sourceCommitSep, repoCommit)
	}
	return l, nil
}
