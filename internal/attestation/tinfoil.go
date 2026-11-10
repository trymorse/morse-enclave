package attestation

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify"

	"morse/backend/internal/aci"
)

// Tinfoil's router runs in an AMD SEV-SNP guest and serves the report the guest's firmware signed
// at boot. REPORT_DATA binds the guest's two keys: bytes 0-31 are the sha256 of its TLS
// certificate's SubjectPublicKeyInfo, bytes 32-63 the X25519 key clients seal request bodies to
// (EHBP). The report binds no nonce, so it speaks for the boot: each boot makes both keys afresh,
// and the pins judge which release booted.

const (
	// TinfoilFormat is the only report format the router's well-known endpoint serves for SEV-SNP.
	TinfoilFormat  = "https://tinfoil.sh/predicate/sev-snp-guest/v2"
	snpReportLen   = abi.ReportSize
	maxTinfoilGzip = 64 << 10
	reportDataTLS  = 32
	reportDataHPKE = 32
)

var (
	ErrTinfoilBundle = errors.New("attestation: the Tinfoil bundle is not an SEV-SNP report with its VCEK and certificate")
	ErrSNPReport     = errors.New("attestation: the SEV-SNP report does not verify under AMD's Genoa root")
	ErrSNPPolicy     = errors.New("attestation: the SEV-SNP guest allows debugging or a migration agent")
	ErrSNPVCEK       = errors.New("attestation: the SEV-SNP report names a chip or TCB its VCEK was not issued for")
	ErrTinfoilTLS    = errors.New("attestation: REPORT_DATA does not bind the router certificate's key")
)

// TinfoilBundle is what the gate fetches for one router host, and what the app verifies itself:
// the report as the router serves it, the VCEK AMD issued for its chip and TCB, and the router's
// certificate.
type TinfoilBundle struct {
	Host        string `json:"host"`
	Format      string `json:"format"`
	Body        string `json:"body"`
	VCEK        string `json:"vcek"`
	Certificate string `json:"certificate"`
}

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
	// Provenance is what the router's code collateral proved about its release. A v2 bundle carries
	// none, so VerifyTinfoil leaves it zero and the gate fills it from a v3 document when it needs to.
	Provenance Provenance
}

func (r TinfoilReport) Facts() []any {
	facts := []any{"endpoint", r.Endpoint.ID, "not_after", r.Endpoint.NotAfter.UTC().Format(time.RFC3339), "measurement", r.Measurement, "chip_id", r.ChipID, "tcb", r.TCB.String(), "policy", fmt.Sprintf("%#x", r.Policy), "vmpl", r.VMPL, "hpke_key", hex.EncodeToString(r.HPKE[:])}
	if rel, ok := r.Provenance.Release(); ok {
		facts = append(facts, "release_tag", rel.Tag)
	}
	return facts
}

var genoa = &spb.SevProduct{Name: spb.SevProduct_SEV_PRODUCT_GENOA}

// VerifyTinfoil verifies one router's bundle for host: the report's signature by the VCEK, the
// VCEK's chain to AMD's Genoa root, a guest that allows neither debugging nor a migration agent,
// and REPORT_DATA binding the certificate's key. The HPKE key it returns is the one REPORT_DATA
// binds. Which release and platform may serve is the pins' question.
func (p Policy) VerifyTinfoil(_ context.Context, raw []byte, host string) (TinfoilReport, error) {
	var b TinfoilBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return TinfoilReport{}, fmt.Errorf("%w: %w", ErrTinfoilBundle, err)
	}
	if b.Host != host {
		return TinfoilReport{}, fmt.Errorf("%w: it is for host %q, not %q", ErrTinfoilBundle, b.Host, host)
	}
	if b.Format != TinfoilFormat {
		return TinfoilReport{}, fmt.Errorf("%w: format %q", ErrTinfoilBundle, b.Format)
	}
	report, err := snpReport(b.Body)
	if err != nil {
		return TinfoilReport{}, err
	}
	vcek, err := base64.StdEncoding.DecodeString(b.VCEK)
	if err != nil {
		return TinfoilReport{}, fmt.Errorf("%w: vcek is not base64: %w", ErrTinfoilBundle, err)
	}
	cert, err := leafCertificate(b.Certificate)
	if err != nil {
		return TinfoilReport{}, err
	}
	notAfter, err := p.verifySNP(report, vcek)
	if err != nil {
		return TinfoilReport{}, err
	}
	data := report.GetReportData()
	tls := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if !bytes.Equal(data[:reportDataTLS], tls[:]) {
		return TinfoilReport{}, fmt.Errorf("%w: REPORT_DATA %x, certificate SPKI %x", ErrTinfoilTLS, data[:reportDataTLS], tls)
	}
	var hpke [32]byte
	copy(hpke[:], data[reportDataTLS:reportDataTLS+reportDataHPKE])
	return tinfoilReport(host, report, aci.SPKI(tls), hpke, notAfter), nil
}

func (p Policy) verifySNP(report *spb.Report, vcek []byte) (notAfter time.Time, err error) {
	attested := &spb.Attestation{Report: report, CertificateChain: &spb.CertificateChain{VcekCert: vcek}, Product: genoa}
	if err := verify.SnpAttestation(attested, &verify.Options{DisableCertFetching: true, Now: p.now(), Product: genoa}); err != nil {
		return time.Time{}, fmt.Errorf("%w: %w", ErrSNPReport, err)
	}
	if err := refuseSNPPolicy(report.GetPolicy()); err != nil {
		return time.Time{}, err
	}
	vcekCert, err := x509.ParseCertificate(vcek)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %w", ErrTinfoilBundle, err)
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

// VCEKURL is AMD KDS's address of the VCEK for the chip and TCB that a router's report, as it
// serves it, names.
func VCEKURL(body string) (string, error) {
	report, err := snpReport(body)
	if err != nil {
		return "", err
	}
	return kds.VCEKCertURL(kds.ProductLine(genoa), report.GetChipId(), kds.TCBVersion(report.GetReportedTcb())), nil
}

// snpReport reads the report the router serves: base64 of the gzipped raw report.
func snpReport(body string) (*spb.Report, error) {
	gz, err := base64.StdEncoding.DecodeString(body)
	if err != nil || len(gz) > maxTinfoilGzip {
		return nil, fmt.Errorf("%w: body is not base64 of at most %d bytes", ErrTinfoilBundle, maxTinfoilGzip)
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, fmt.Errorf("%w: body is not gzip: %w", ErrTinfoilBundle, err)
	}
	raw, err := io.ReadAll(io.LimitReader(zr, snpReportLen+1))
	if err != nil || len(raw) != snpReportLen {
		return nil, fmt.Errorf("%w: the report is not %d bytes", ErrTinfoilBundle, snpReportLen)
	}
	report, err := abi.ReportToProto(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSNPReport, err)
	}
	return report, nil
}

func leafCertificate(pemText string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: certificate is not PEM", ErrTinfoilBundle)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTinfoilBundle, err)
	}
	return cert, nil
}
