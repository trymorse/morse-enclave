package attestation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"

	"morse/backend/internal/nras"
)

const (
	quoteReportDataLen  = 64
	tdAttributeDebug    = 1
	configIDLen         = 48
	configIDComposeHash = 0x01
)

var (
	ErrQuote           = errors.New("attestation: TDX quote does not verify under the Intel root and current collateral")
	ErrCollateral      = errors.New("attestation: Intel collateral could not be fetched, so the quote was not judged")
	ErrDebugTD         = errors.New("attestation: the TD runs with the DEBUG attribute set")
	ErrQuoteReportData = errors.New("attestation: the verified quote carries a different report_data")
	ErrEventLog        = errors.New("attestation: event_log is not the runtime log the quote measured")
	ErrComposeHash     = errors.New("attestation: app_compose is not the measured compose-hash")
	ErrConfigID        = errors.New("attestation: the quote's MRCONFIGID is not 01 || sha256(app_compose) || zeros")
	ErrProvenance      = errors.New("attestation: the release provenance is not corroborated by the measured app_compose")
)

type Nonce [32]byte

func NewNonce() (Nonce, error) {
	var n Nonce
	_, err := rand.Read(n[:])
	return n, err
}

func (n Nonce) String() string { return hex.EncodeToString(n[:]) }

//go:embed intel_sgx_root_ca.pem
var intelRootPEM []byte

var intelRoot = sync.OnceValue(func() *x509.CertPool {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(intelRootPEM) {
		panic("attestation: embedded Intel SGX Root CA does not parse")
	}
	return pool
})

type Policy struct {
	roots      *x509.CertPool
	collateral CollateralSource
	gpu        GPUVerifier
	Now        time.Time
}

func NewPolicy(collateral CollateralSource, gpu GPUVerifier) Policy {
	return Policy{roots: intelRoot(), collateral: collateral, gpu: gpu}
}

func NVIDIAPolicy() Policy {
	return NewPolicy(NewCollateralCache(), nras.NewCache(nras.NVIDIA()))
}

type Endpoint[K comparable] struct {
	ID       string
	NotAfter time.Time
	Keys     []K
}

type Measured struct {
	Boot
	RTMR3        Register
	TDAttributes string
}

type Verified interface{ Facts() []any }

func (r PhalaReport) Facts() []any {
	return []any{"endpoint", r.Endpoint.ID, "instance_id", r.InstanceID, "not_after", r.Endpoint.NotAfter.UTC().Format(time.RFC3339), "app_id", r.AppID, "compose_hash", r.Release.ComposeHash, "source", r.Release.Source}
}

type Judged[K comparable] struct {
	Endpoint[K]
	Drift    []Drift
	Verified Verified
}

type Verdicts[K comparable] struct {
	Endpoints []Judged[K]
	Refused   []Refusal
	Serve     Serve
}

type Serve func(held func(id string) bool) json.RawMessage

type Refusal struct {
	EndpointID string
	Err        error
}

type Outage struct{ Err error }

func (o Outage) Error() string { return o.Err.Error() }
func (o Outage) Unwrap() error { return o.Err }

func Unjudged(err error) bool {
	_, ok := err.(Outage)
	return ok
}

func (p Policy) now() time.Time {
	if p.Now.IsZero() {
		return time.Now()
	}
	return p.Now
}

func (p Policy) quoteBoundTo(ctx context.Context, quote []byte, want [quoteReportDataLen]byte, now time.Time, tcb tcbPolicy) (*pb.TDQuoteBody, TCB, error) {
	body, standing, err := p.verifyQuote(ctx, quote, now, tcb)
	if err != nil {
		return nil, TCB{}, err
	}
	if err := refuseDebugTD(body.GetTdAttributes()); err != nil {
		return nil, TCB{}, err
	}
	if !bytes.Equal(body.GetReportData(), want[:]) {
		return nil, TCB{}, fmt.Errorf("%w: quote %x, report %x", ErrQuoteReportData, body.GetReportData(), want)
	}
	return body, standing, nil
}

func measured(body *pb.TDQuoteBody) Measured {
	rtmr := body.GetRtmrs()
	return Measured{
		Boot:         Boot{MRTD: Register(body.GetMrTd()), RTMR0: Register(rtmr[0]), RTMR1: Register(rtmr[1]), RTMR2: Register(rtmr[2])},
		RTMR3:        Register(rtmr[runtimeIMR]),
		TDAttributes: hex.EncodeToString(body.GetTdAttributes()),
	}
}

// go-tdx-guest refuses a platform TCB below UpToDate and never reports which status matched, so
// under reportTCBStatus a refusal is rechecked with DisableTcbStatusCheck. For a v4 quote it also
// passes a TDX module level below UpToDate, so every admitted quote's standing is read from the
// collateral it fetched.
func (p Policy) verifyQuote(ctx context.Context, raw []byte, now time.Time, tcb tcbPolicy) (*pb.TDQuoteBody, TCB, error) {
	parsed, err := abi.QuoteToProto(raw)
	if err != nil {
		return nil, TCB{}, fmt.Errorf("%w: %w", ErrQuote, err)
	}
	quote, ok := parsed.(*pb.QuoteV4)
	if !ok {
		return nil, TCB{}, fmt.Errorf("%w: quote is %T, not a TDX quote v4", ErrQuote, parsed)
	}
	collateral := &fetchedCollateral{Collateral: p.collateral.For(ctx)}
	options := func(withCollateral, checkTCBStatus bool) *verify.Options {
		return &verify.Options{
			TrustedRoots:          p.roots,
			GetCollateral:         withCollateral,
			CheckRevocations:      withCollateral,
			Getter:                collateral,
			Now:                   &verify.TimeSet{PckCertChain: now, TcbInfo: now, QeIdentity: now, PckCrl: now, RootCaCrl: now},
			DisableTcbStatusCheck: !checkTCBStatus,
		}
	}
	if err := verify.TdxQuote(quote, options(false, true)); err != nil {
		return nil, TCB{}, fmt.Errorf("%w: %w", ErrQuote, err)
	}
	refused := verify.TdxQuote(quote, options(true, true))
	if refused != nil {
		switch {
		case collateral.lastFetchErr != nil:
			return nil, TCB{}, Outage{Err: fmt.Errorf("%w: %w", ErrCollateral, collateral.lastFetchErr)}
		case tcb == requireUpToDate:
			return nil, TCB{}, fmt.Errorf("%w: %w", ErrQuote, refused)
		}
		if err := verify.TdxQuote(quote, options(true, false)); err != nil {
			if collateral.lastFetchErr != nil {
				return nil, TCB{}, Outage{Err: fmt.Errorf("%w: %w", ErrCollateral, collateral.lastFetchErr)}
			}
			return nil, TCB{}, fmt.Errorf("%w: %w", ErrQuote, err)
		}
	}
	standing, err := platformTCB(quote, collateral.bodies)
	if err != nil {
		return nil, TCB{}, fmt.Errorf("%w: %w", ErrQuote, err)
	}
	if standing, err = tcb.judge(standing, refused); err != nil {
		return nil, TCB{}, err
	}
	return quote.GetTdQuoteBody(), standing, nil
}

type fetchedCollateral struct {
	Collateral
	bodies       map[string][]byte
	lastFetchErr error
}

func (c *fetchedCollateral) Get(url string) (map[string][]string, []byte, error) {
	header, body, err := c.Collateral.Get(url)
	c.lastFetchErr = nil
	if err != nil {
		c.lastFetchErr = fmt.Errorf("%s: %w", url, err)
		return header, body, err
	}
	if c.bodies == nil {
		c.bodies = map[string][]byte{}
	}
	c.bodies[url] = body
	return header, body, nil
}

func refuseDebugTD(attributes []byte) error {
	if len(attributes) == 0 || attributes[0]&tdAttributeDebug != 0 {
		return fmt.Errorf("%w: td_attributes %x", ErrDebugTD, attributes)
	}
	return nil
}
