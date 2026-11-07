package attestation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/google/go-sev-guest/abi"

	"morse/backend/internal/aci"
)

const (
	TinfoilNoncedFormat     = "https://tinfoil.sh/predicate/attestation/v3"
	tinfoilReportDataV1     = "https://tinfoil.sh/report-data/v1"
	tinfoilSNPEvidence      = "https://tinfoil.sh/format/sev-snp-report/v1"
	tinfoilCryptoMaterialV1 = "https://tinfoil.sh/crypto-material/v1"
	tinfoilSPKIFingerprint  = "https://tinfoil.sh/key/spki-fp-sha256/v1"
	tinfoilX25519HPKE       = "https://tinfoil.sh/key/x25519-hpke/v1"
	TinfoilVCEKCollateral   = "https://tinfoil.sh/collateral/amd-vcek/v1"
	TinfoilCRLCollateral    = "https://tinfoil.sh/collateral/amd-crl/v1"
)

var (
	ErrTinfoilNonced     = errors.New("attestation: the Tinfoil document is not a v3 SEV-SNP attestation with its VCEK")
	ErrTinfoilReportData = errors.New("attestation: REPORT_DATA does not bind the nonce and the document's crypto material")
)

// TinfoilNonced is Tinfoil's v3 attestation document, plus the host it was fetched from.
type TinfoilNonced struct {
	Host           string              `json:"host"`
	Format         string              `json:"format"`
	Challenge      TinfoilChallenge    `json:"challenge"`
	CPUEvidence    TinfoilCPUEvidence  `json:"cpu_evidence"`
	CryptoMaterial string              `json:"crypto_material"`
	DeviceEvidence string              `json:"device_evidence"`
	Collateral     []TinfoilCollateral `json:"collateral"`
}

type TinfoilChallenge struct {
	Nonce               string `json:"nonce"`
	ReportData          string `json:"report_data"`
	ReportDataAlgorithm string `json:"report_data_algorithm"`
}

type TinfoilCPUEvidence struct {
	Format       string          `json:"format"`
	ReportBase64 string          `json:"report_base64"`
	Endorsed     TinfoilEndorsed `json:"endorsed"`
}

type TinfoilEndorsed struct {
	CryptoMaterialHash string `json:"crypto_material_hash"`
	DeviceEvidenceHash string `json:"device_evidence_hash"`
}

type TinfoilCollateral struct {
	ID       string          `json:"id"`
	Role     string          `json:"role"`
	Format   string          `json:"format"`
	Subjects []string        `json:"subjects,omitempty"`
	Data     json.RawMessage `json:"data"`
}

// AMDCollateral reports whether c is AMD's VCEK or CRL.
func (c TinfoilCollateral) AMDCollateral() bool {
	return c.Format == TinfoilVCEKCollateral || c.Format == TinfoilCRLCollateral
}

// Relayed reports whether c is collateral Morse reads or relays: AMD's VCEK and CRL, and the Sigstore
// bundle of the router's release.
func (c TinfoilCollateral) Relayed() bool {
	return c.AMDCollateral() || c.Format == TinfoilCodeCollateral
}

// Code is the data of the document's sigstore-code collateral, or nil.
func (d TinfoilNonced) Code() json.RawMessage {
	i := slices.IndexFunc(d.Collateral, func(c TinfoilCollateral) bool { return c.Format == TinfoilCodeCollateral })
	if i < 0 {
		return nil
	}
	return d.Collateral[i].Data
}

// VCEK is the DER of the VCEK the document's AMD collateral carries.
func (d TinfoilNonced) VCEK() ([]byte, error) {
	i := slices.IndexFunc(d.Collateral, func(c TinfoilCollateral) bool { return c.Format == TinfoilVCEKCollateral })
	if i < 0 {
		return nil, fmt.Errorf("%w: no %s collateral", ErrTinfoilNonced, TinfoilVCEKCollateral)
	}
	var data struct {
		VCEK string `json:"vcek_der_base64"`
	}
	if err := json.Unmarshal(d.Collateral[i].Data, &data); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTinfoilNonced, err)
	}
	der, err := base64.StdEncoding.DecodeString(data.VCEK)
	if err != nil || len(der) == 0 {
		return nil, fmt.Errorf("%w: the VCEK is not base64 DER", ErrTinfoilNonced)
	}
	return der, nil
}

// VerifyTinfoilNonced verifies one router's v3 document for host and nonce: the report's signature by the
// VCEK the document carries, the VCEK's chain to AMD's Genoa root, a guest that allows neither debugging nor
// a migration agent, and REPORT_DATA binding the nonce and the crypto material whose TLS and HPKE keys it
// returns, and what the document's code collateral proves about the release. Which release and
// platform may serve is the pins' question.
func (p Policy) VerifyTinfoilNonced(_ context.Context, raw []byte, nonce Nonce, host string) (TinfoilReport, error) {
	var d TinfoilNonced
	if err := json.Unmarshal(raw, &d); err != nil {
		return TinfoilReport{}, fmt.Errorf("%w: %w", ErrTinfoilNonced, err)
	}
	switch {
	case d.Host != host:
		return TinfoilReport{}, fmt.Errorf("%w: it is for host %q, not %q", ErrTinfoilNonced, d.Host, host)
	case d.Format != TinfoilNoncedFormat:
		return TinfoilReport{}, fmt.Errorf("%w: format %q", ErrTinfoilNonced, d.Format)
	case d.Challenge.ReportDataAlgorithm != tinfoilReportDataV1:
		return TinfoilReport{}, fmt.Errorf("%w: report data algorithm %q", ErrTinfoilNonced, d.Challenge.ReportDataAlgorithm)
	case d.CPUEvidence.Format != tinfoilSNPEvidence:
		return TinfoilReport{}, fmt.Errorf("%w: cpu evidence format %q", ErrTinfoilNonced, d.CPUEvidence.Format)
	}
	rawReport, err := base64.StdEncoding.DecodeString(d.CPUEvidence.ReportBase64)
	if err != nil || len(rawReport) != snpReportLen {
		return TinfoilReport{}, fmt.Errorf("%w: the report is not base64 of %d bytes", ErrTinfoilNonced, snpReportLen)
	}
	report, err := abi.ReportToProto(rawReport)
	if err != nil {
		return TinfoilReport{}, fmt.Errorf("%w: %w", ErrSNPReport, err)
	}
	vcek, err := d.VCEK()
	if err != nil {
		return TinfoilReport{}, err
	}
	notAfter, err := p.verifySNP(report, vcek)
	if err != nil {
		return TinfoilReport{}, err
	}
	material, err := base64.StdEncoding.DecodeString(d.CryptoMaterial)
	if err != nil {
		return TinfoilReport{}, fmt.Errorf("%w: crypto_material is not base64", ErrTinfoilNonced)
	}
	device, err := base64.StdEncoding.DecodeString(d.DeviceEvidence)
	if err != nil {
		return TinfoilReport{}, fmt.Errorf("%w: device_evidence is not base64", ErrTinfoilNonced)
	}
	if want := tinfoilReportData(nonce, material, device); !bytes.Equal(report.GetReportData(), want[:]) {
		return TinfoilReport{}, fmt.Errorf("%w: REPORT_DATA %x, want %x", ErrTinfoilReportData, report.GetReportData(), want)
	}
	tls, hpke, err := tinfoilKeys(material)
	if err != nil {
		return TinfoilReport{}, err
	}
	r := tinfoilReport(host, report, tls, hpke, notAfter)
	r.Provenance = ProveRouterRelease(d.Code())
	return r, nil
}

func tinfoilReportData(nonce Nonce, material, device []byte) [64]byte {
	m, d := sha256.Sum256(material), sha256.Sum256(device)
	h := sha256.New()
	h.Write([]byte(tinfoilReportDataV1))
	h.Write(nonce[:])
	h.Write(m[:])
	h.Write(d[:])
	var out [64]byte
	copy(out[:], h.Sum(nil))
	return out
}

func tinfoilKeys(material []byte) (aci.SPKI, [32]byte, error) {
	var cm struct {
		Format string `json:"format"`
		Items  []struct {
			ID     string `json:"id"`
			Format string `json:"format"`
			Data   string `json:"data"`
		} `json:"items"`
	}
	if err := json.Unmarshal(material, &cm); err != nil || cm.Format != tinfoilCryptoMaterialV1 {
		return aci.SPKI{}, [32]byte{}, fmt.Errorf("%w: crypto_material is not %s", ErrTinfoilNonced, tinfoilCryptoMaterialV1)
	}
	keys := map[string][32]byte{}
	for _, item := range cm.Items {
		if _, seen := keys[item.ID]; seen {
			return aci.SPKI{}, [32]byte{}, fmt.Errorf("%w: crypto_material lists %q twice", ErrTinfoilNonced, item.ID)
		}
		var key [32]byte
		if want, ok := map[string]string{"tls": tinfoilSPKIFingerprint, "hpke": tinfoilX25519HPKE}[item.ID]; ok {
			if item.Format != want || len(item.Data) != hex.EncodedLen(len(key)) {
				return aci.SPKI{}, [32]byte{}, fmt.Errorf("%w: crypto_material's %s key is not %s", ErrTinfoilNonced, item.ID, want)
			}
			if _, err := hex.Decode(key[:], []byte(item.Data)); err != nil {
				return aci.SPKI{}, [32]byte{}, fmt.Errorf("%w: crypto_material's %s key is not hex", ErrTinfoilNonced, item.ID)
			}
		}
		keys[item.ID] = key
	}
	tls, hasTLS := keys["tls"]
	hpke, hasHPKE := keys["hpke"]
	if !hasTLS || !hasHPKE {
		return aci.SPKI{}, [32]byte{}, fmt.Errorf("%w: crypto_material lacks the tls or the hpke key", ErrTinfoilNonced)
	}
	return aci.SPKI(tls), hpke, nil
}
