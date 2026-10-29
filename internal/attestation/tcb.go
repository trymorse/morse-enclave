package attestation

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/google/go-tdx-guest/pcs"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"
)

type TCBStatus string

const (
	TCBUpToDate TCBStatus = "UpToDate"
	TCBRevoked  TCBStatus = "Revoked"
)

var tcbStatusesCurrentToStale = []TCBStatus{
	TCBUpToDate,
	TCBStatus(pcs.TcbComponentStatusSwHardeningNeeded),
	TCBStatus(pcs.TcbComponentStatusConfigurationNeeded),
	TCBStatus(pcs.TcbComponentStatusConfigurationAndSWHardeningNeeded),
	TCBStatus(pcs.TcbComponentStatusRelaunchAdvisedConfigurationNeeded),
	TCBStatus(pcs.TcbComponentStatusOutOfDate),
	TCBStatus(pcs.TcbComponentStatusOutOfDateConfigurationNeeded),
}

// TCB is the stalest status among the TCB levels the platform, its TDX module, and its quoting
// enclave match, with every advisory those levels carry.
type TCB struct {
	Status     TCBStatus `json:"status"`
	Advisories []string  `json:"advisories,omitempty"`
}

type tcbPolicy bool

const (
	requireUpToDate tcbPolicy = false
	reportTCBStatus tcbPolicy = true
)

var ErrTCB = errors.New("attestation: the platform TCB is revoked or matches no status Intel's collateral names")

func (tcb tcbPolicy) judge(standing TCB, refused error) (TCB, error) {
	switch {
	case refused != nil && standing.Status == TCBUpToDate:
		return TCB{}, fmt.Errorf("%w: %w, yet the matched TCB levels are UpToDate", ErrQuote, refused)
	case tcb == requireUpToDate && standing.Status != TCBUpToDate:
		return TCB{}, fmt.Errorf("%w: the matched TCB levels are %s, not UpToDate", ErrQuote, standing.Status)
	}
	return standing, nil
}

const tdxModuleIDPrefix = "TDX_"

// platformTCB mirrors go-tdx-guest's unexported readTcbInfoTcbStatus and checkQeTcbStatus, which
// refuse below UpToDate instead of reporting the matched level.
func platformTCB(quote *pb.QuoteV4, fetched map[string][]byte) (TCB, error) {
	chain, err := verify.ExtractChainFromQuote(quote)
	if err != nil {
		return TCB{}, err
	}
	ext, err := pcs.PckCertificateExtensions(chain.PCKCertificate)
	if err != nil {
		return TCB{}, err
	}
	var tcbInfo pcs.TdxTcbInfo
	if err := unmarshalFetched(fetched, pcs.TcbInfoURL(ext.FMSPC), &tcbInfo); err != nil {
		return TCB{}, err
	}
	var qe pcs.QeIdentity
	if err := unmarshalFetched(fetched, pcs.QeIdentityURL(), &qe); err != nil {
		return TCB{}, err
	}
	body := quote.GetTdQuoteBody()
	platform, err := matchTCBLevel(tcbInfo.TcbInfo.TcbLevels, body.GetTeeTcbSvn(), ext.TCB)
	if err != nil {
		return TCB{}, err
	}
	levels := []pcs.TcbLevel{platform}
	if svn := body.GetTeeTcbSvn(); svn[1] > 0 {
		module, err := matchTDXModuleLevel(tcbInfo.TcbInfo.TdxModuleIdentities, svn)
		if err != nil {
			return TCB{}, err
		}
		levels = append(levels, module)
	}
	report := quote.GetSignedData().GetCertificationData().GetQeReportCertificationData().GetQeReport()
	i := slices.IndexFunc(qe.EnclaveIdentity.TcbLevels, func(l pcs.TcbLevel) bool { return l.Tcb.Isvsvn <= report.GetIsvSvn() })
	if i < 0 {
		return TCB{}, fmt.Errorf("no QE TCB level matches isvsvn %d", report.GetIsvSvn())
	}
	return worstTCB(append(levels, qe.EnclaveIdentity.TcbLevels[i]))
}

func unmarshalFetched(fetched map[string][]byte, url string, v any) error {
	body, ok := fetched[url]
	if !ok {
		return fmt.Errorf("the verifier fetched no %s", url)
	}
	return json.Unmarshal(body, v)
}

func matchTCBLevel(levels []pcs.TcbLevel, teeTcbSvn []byte, pck pcs.PckCertTCB) (pcs.TcbLevel, error) {
	for _, l := range levels {
		if svnsAtLeast(pck.CPUSvnComponents, l.Tcb.SgxTcbcomponents, 0) && pck.PCESvn >= l.Tcb.Pcesvn && svnsAtLeast(teeTcbSvn, l.Tcb.TdxTcbcomponents, tdxComponentsFrom(teeTcbSvn)) {
			return l, nil
		}
	}
	return pcs.TcbLevel{}, errors.New("no TCB level matches the platform")
}

// tdxComponentsFrom skips the two TEE TCB SVN bytes a TDX module identity measures on its own.
func tdxComponentsFrom(teeTcbSvn []byte) int {
	if teeTcbSvn[1] > 0 {
		return 2
	}
	return 0
}

func svnsAtLeast(have []byte, want []pcs.TcbComponent, from int) bool {
	if len(have) != len(want) {
		return false
	}
	for i := from; i < len(have); i++ {
		if have[i] < want[i].Svn {
			return false
		}
	}
	return true
}

func matchTDXModuleLevel(identities []pcs.TdxModuleIdentity, teeTcbSvn []byte) (pcs.TcbLevel, error) {
	id := tdxModuleIDPrefix + hex.EncodeToString(teeTcbSvn[1:2])
	for _, identity := range identities {
		if identity.ID != id {
			continue
		}
		for _, l := range identity.TcbLevels {
			if uint32(teeTcbSvn[0]) >= l.Tcb.Isvsvn {
				return l, nil
			}
		}
		return pcs.TcbLevel{}, fmt.Errorf("no %s TCB level matches isvsvn %d", id, teeTcbSvn[0])
	}
	return pcs.TcbLevel{}, fmt.Errorf("the TCB info names no TDX module identity %s", id)
}

func worstTCB(levels []pcs.TcbLevel) (TCB, error) {
	tcb := TCB{Status: TCBUpToDate}
	for _, l := range levels {
		status := TCBStatus(l.TcbStatus)
		rank := slices.Index(tcbStatusesCurrentToStale, status)
		if rank < 0 {
			return TCB{}, fmt.Errorf("%w: %q", ErrTCB, l.TcbStatus)
		}
		if rank > slices.Index(tcbStatusesCurrentToStale, tcb.Status) {
			tcb.Status = status
		}
		tcb.Advisories = append(tcb.Advisories, l.AdvisoryIDs...)
	}
	slices.Sort(tcb.Advisories)
	tcb.Advisories = slices.Compact(tcb.Advisories)
	return tcb, nil
}
