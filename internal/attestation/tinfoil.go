package attestation

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify"

	"morse/backend/internal/aci"
)

const (
	snpReportLen = abi.ReportSize
	genoaFamily  = 0x19
)

var (
	ErrSNPReport = errors.New("attestation: the SEV-SNP report does not verify under AMD's Genoa root")
	ErrSNPPolicy = errors.New("attestation: the SEV-SNP guest allows debugging or a migration agent")
	ErrSNPVCEK   = errors.New("attestation: the SEV-SNP report names a chip or TCB its VCEK was not issued for")
)

// SNPTCB is a reported TCB's security patch levels, as AMD's Genoa layout places them.
type SNPTCB struct {
	Bootloader uint8 `json:"bootloader"`
	TEE        uint8 `json:"tee"`
	SNP        uint8 `json:"snp"`
	Microcode  uint8 `json:"microcode"`
}

func (t SNPTCB) String() string {
	return fmt.Sprintf("bootloader %d, tee %d, snp %d, microcode %d", t.Bootloader, t.TEE, t.SNP, t.Microcode)
}

// below reports whether any patch level of t is under min's.
func (t SNPTCB) below(min SNPTCB) bool {
	return t.Bootloader < min.Bootloader || t.TEE < min.TEE || t.SNP < min.SNP || t.Microcode < min.Microcode
}

func snpTCB(v uint64) SNPTCB {
	return SNPTCB{Bootloader: uint8(v), TEE: uint8(v >> 8), SNP: uint8(v >> 48), Microcode: uint8(v >> 56)}
}

type TinfoilReport struct {
	Host        string
	Measurement string
	TLS         aci.SPKI
	HPKE        [32]byte
	ChipID      string
	TCB         SNPTCB
	Policy      uint64
	VMPL        uint32
	Endpoint    Endpoint[aci.SPKI]
	Provenance  Provenance
}

func (r TinfoilReport) Facts() []any {
	facts := []any{"endpoint", r.Endpoint.ID, "not_after", r.Endpoint.NotAfter.UTC().Format(time.RFC3339), "measurement", r.Measurement, "chip_id", r.ChipID, "tcb", r.TCB.String(), "policy", fmt.Sprintf("%#x", r.Policy), "vmpl", r.VMPL, "hpke_key", hex.EncodeToString(r.HPKE[:])}
	if rel, ok := r.Provenance.Release(); ok {
		facts = append(facts, "release_tag", rel.Tag)
	}
	return facts
}

var genoa = &spb.SevProduct{Name: spb.SevProduct_SEV_PRODUCT_GENOA}

func (p Policy) verifySNP(report *spb.Report, vcek []byte) (notAfter time.Time, err error) {
	if family, model, _ := abi.FmsFromCpuid1Eax(report.GetCpuid1EaxFms()); report.GetVersion() >= abi.ReportVersion3 && family != genoaFamily {
		return time.Time{}, fmt.Errorf("%w: %w: CPUID family %#x model %#x, not Genoa's family %#x", ErrSNPReport, ErrUnreadable, family, model, genoaFamily)
	}
	attested := &spb.Attestation{Report: report, CertificateChain: &spb.CertificateChain{VcekCert: vcek}, Product: genoa}
	if err := verify.SnpAttestation(attested, &verify.Options{DisableCertFetching: true, Now: p.now(), Product: genoa}); err != nil {
		return time.Time{}, fmt.Errorf("%w: %w", ErrSNPReport, err)
	}
	if err := refuseSNPPolicy(report.GetPolicy()); err != nil {
		return time.Time{}, err
	}
	vcekCert, err := x509.ParseCertificate(vcek)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %w", ErrSNPReport, err)
	}
	if err := vcekNamesReport(report, vcekCert); err != nil {
		return time.Time{}, err
	}
	return vcekCert.NotAfter, nil
}

// vcekNamesReport refuses a report whose REPORTED_TCB or CHIP_ID is not the TCB and HWID AMD issued
// the VCEK for. The VCEK's signature over the report does not bind those fields: a key issued for an
// older TCB could sign a report claiming a newer one, and min_tcb is judged on the claim.
func vcekNamesReport(report *spb.Report, vcek *x509.Certificate) error {
	exts, err := kds.VcekCertificateExtensions(vcek)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSNPVCEK, err)
	}
	if reported := kds.TCBVersion(report.GetReportedTcb()); reported != exts.TCBVersion {
		return fmt.Errorf("%w: REPORTED_TCB %s, VCEK TCB %s", ErrSNPVCEK, snpTCB(uint64(reported)), snpTCB(uint64(exts.TCBVersion)))
	}
	if chip := report.GetChipId(); !bytes.Equal(chip, exts.HWID) || bytes.Count(chip, []byte{0}) == len(chip) {
		return fmt.Errorf("%w: CHIP_ID %x, VCEK HWID %x", ErrSNPVCEK, chip, exts.HWID)
	}
	return nil
}

func tinfoilReport(host string, report *spb.Report, tls aci.SPKI, hpke [32]byte, notAfter time.Time) TinfoilReport {
	return TinfoilReport{
		Host:        host,
		Measurement: hex.EncodeToString(report.GetMeasurement()),
		TLS:         tls,
		HPKE:        hpke,
		ChipID:      hex.EncodeToString(report.GetChipId()),
		TCB:         snpTCB(report.GetReportedTcb()),
		Policy:      report.GetPolicy(),
		VMPL:        report.GetVmpl(),
		Endpoint:    Endpoint[aci.SPKI]{ID: host, NotAfter: notAfter, Keys: []aci.SPKI{tls}},
	}
}

// refuseSNPPolicy refuses a guest the host may read: one that allows debugging, or a migration agent
// that could move its memory to another machine.
func refuseSNPPolicy(policy uint64) error {
	p, err := abi.ParseSnpPolicy(policy)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSNPReport, err)
	}
	if p.Debug || p.MigrateMA {
		return fmt.Errorf("%w: policy %#x", ErrSNPPolicy, policy)
	}
	return nil
}
