package chat

import (
	"bytes"
	"encoding/json"

	"morse/backend/internal/catalog"
)

func (a Attestation) Reply(public string, tier catalog.Tier, speaks *Scheme, protocols, instances []string) []byte {
	var out bytes.Buffer
	out.WriteString(`{"object":"attestation","model":`)
	out.Write(jsonString(public))
	out.WriteString(`,"tier":`)
	out.Write(jsonString(tier.String()))
	out.WriteString(`,"aad_model":`)
	out.Write(jsonString(a.BindModel))
	if tier.Sealed() {
		out.WriteString(`,"e2ee_version":`)
		out.Write(jsonString(speaks.Version))
		out.WriteString(`,"e2ee_protocol":`)
		out.Write(jsonString(speaks.Name))
		if len(protocols) > 0 {
			out.WriteString(`,"e2ee_protocols":`)
			list, _ := json.Marshal(protocols)
			out.Write(list)
		}
	}
	out.WriteString(`,"report":`)
	out.Write(a.Report)
	if a.GPUVerdicts != nil {
		out.WriteString(`,"gpu_verdicts":`)
		out.Write(a.GPUVerdicts)
	}
	if a.VendorPins != nil {
		out.WriteString(`,"vendor_pins":`)
		pins, _ := json.Marshal(a.VendorPins)
		out.Write(pins)
	}
	out.WriteString(`,"instances":`)
	list, _ := json.Marshal(instances)
	out.Write(list)
	out.WriteString("}\n")
	return out.Bytes()
}

func jsonString(s string) []byte {
	b, _ := json.Marshal(s)
	return b
}
