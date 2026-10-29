package attestation

import (
	"fmt"
	"slices"
	"strings"

	"morse/backend/internal/aci"
)

type GatewayModelPins struct {
	Gateway WorkloadPins `json:"gateway"`
	Model   WorkloadPins `json:"model"`
}

type WorkloadPins struct {
	TDAttributes   string      `json:"td_attributes"`
	AppID          string      `json:"app_id"`
	KeyProviderIDs []string    `json:"key_provider_ids"`
	TCBStatuses    []TCBStatus `json:"tcb_statuses"`
	Composes       []Compose   `json:"composes"`
	Images         []OSImage   `json:"images"`
	Instances      []string    `json:"instances"`
}

type Compose struct {
	Name        string `json:"name"`
	ComposeHash string `json:"compose_hash"`
}

func (c Compose) String() string { return c.Name + " " + c.ComposeHash }

const (
	appIDField          = "app_id"
	keyProviderIDField  = "key_provider_id"
	keyProviderIDsField = "key_provider_ids"
	tcbStatusField      = "tcb_status"
	tcbStatusesField    = "tcb_statuses"
	composeHashField    = "compose_hash"
	composesField       = "composes"
	gatewayWorkload     = "gateway"
	modelWorkload       = "model"
)

func (p WorkloadPins) Check(w Workload) []Drift {
	drifts := imageDrift(p.Images, w.OSMeasurement)
	if p.TDAttributes != w.TDAttributes {
		drifts = append(drifts, Drift{Kind: DriftAnchor, Field: tdAttributesField, Pinned: p.TDAttributes, Observed: w.TDAttributes})
	}
	if p.AppID != w.AppID {
		drifts = append(drifts, Drift{Kind: DriftAnchor, Field: appIDField, Pinned: p.AppID, Observed: w.AppID})
	}
	if !slices.Contains(p.KeyProviderIDs, w.KeyProviderID) {
		drifts = append(drifts, Drift{Kind: DriftAnchor, Field: keyProviderIDField, Observed: w.KeyProviderID})
	}
	if !slices.Contains(p.TCBStatuses, w.TCB.Status) {
		drifts = append(drifts, Drift{Kind: DriftAnchor, Field: tcbStatusField, Observed: string(w.TCB.Status)})
	}
	if !slices.ContainsFunc(p.Composes, func(c Compose) bool { return c.ComposeHash == w.ComposeHash }) {
		pinned := make([]string, len(p.Composes))
		for i, c := range p.Composes {
			pinned[i] = c.String()
		}
		drifts = append(drifts, Drift{Kind: DriftRelease, Field: composeHashField, Pinned: strings.Join(pinned, ", "), Observed: w.ComposeHash})
	}
	return append(drifts, instanceDrift(p.Instances, w.InstanceID)...)
}

func (p GatewayModelPins) Judge(r NearReport) Verdicts[aci.SPKI] {
	v := Verdicts[aci.SPKI]{Refused: r.Refused}
	for _, m := range r.Models {
		drift := p.drifts(r.Gateway.Workload, m.Workload)
		if err := refuseAnchors(drift); err != nil {
			v.Refused = append(v.Refused, Refusal{EndpointID: m.Endpoint.ID, Err: err})
			continue
		}
		v.Endpoints = append(v.Endpoints, Judged[aci.SPKI]{Endpoint: m.Endpoint, Drift: drift, Verified: m})
	}
	return v
}

func (p GatewayModelPins) EnforceAnchorsBesidesImages(gateway NearGateway, m NearModel) error {
	var drifts []Drift
	for _, d := range p.drifts(gateway.Workload, m.Workload) {
		if d.Field != gatewayWorkload+"."+ImagesField && d.Field != modelWorkload+"."+ImagesField {
			drifts = append(drifts, d)
		}
	}
	return refuseAnchors(drifts)
}

func (p GatewayModelPins) drifts(gateway, model Workload) []Drift {
	return slices.Concat(scoped(gatewayWorkload, p.Gateway.Check(gateway)), scoped(modelWorkload, p.Model.Check(model)))
}

func scoped(workload string, drifts []Drift) []Drift {
	for i := range drifts {
		drifts[i].Field = workload + "." + drifts[i].Field
	}
	return drifts
}

func ParseNearPins(raw []byte) (GatewayModelPins, error) {
	var p GatewayModelPins
	if err := decodePins(raw, &p); err != nil {
		return GatewayModelPins{}, err
	}
	for name, w := range map[string]WorkloadPins{gatewayWorkload: p.Gateway, modelWorkload: p.Model} {
		if err := w.check(); err != nil {
			return GatewayModelPins{}, fmt.Errorf("%w: %s: %w", ErrPins, name, err)
		}
	}
	return p, nil
}

func (p WorkloadPins) check() error {
	switch {
	case p.TDAttributes == "":
		return fmt.Errorf("%s is missing", tdAttributesField)
	case p.AppID == "":
		return fmt.Errorf("%s is missing", appIDField)
	}
	if err := distinctNonEmpty(keyProviderIDsField, p.KeyProviderIDs); err != nil {
		return err
	}
	if err := distinctNonEmpty(instancesField, p.Instances); err != nil {
		return err
	}
	if len(p.TCBStatuses) == 0 {
		return fmt.Errorf("%s is missing", tcbStatusesField)
	}
	for i, s := range p.TCBStatuses {
		if !slices.Contains(tcbStatusesCurrentToStale, s) {
			return fmt.Errorf("%s names %q, which is not a status a verified quote can carry", tcbStatusesField, s)
		}
		if slices.Contains(p.TCBStatuses[:i], s) {
			return fmt.Errorf("%s repeats %s", tcbStatusesField, s)
		}
	}
	if len(p.Composes) == 0 {
		return fmt.Errorf("%s is missing", composesField)
	}
	for i, c := range p.Composes {
		if c.Name == "" || c.ComposeHash == "" {
			return fmt.Errorf("every %s entry needs a name and a %s", composesField, composeHashField)
		}
		if slices.ContainsFunc(p.Composes[:i], func(o Compose) bool { return o.ComposeHash == c.ComposeHash }) {
			return fmt.Errorf("%s repeats %s", composesField, c)
		}
	}
	return checkImages(p.Images)
}

func distinctNonEmpty(field string, values []string) error {
	if len(values) == 0 {
		return fmt.Errorf("%s is missing", field)
	}
	for i, v := range values {
		if v == "" {
			return fmt.Errorf("every %s entry needs a value", field)
		}
		if slices.Contains(values[:i], v) {
			return fmt.Errorf("%s repeats %s", field, v)
		}
	}
	return nil
}

func (p GatewayModelPins) Drifts(r NearReport) []Drift {
	drifts := scoped(gatewayWorkload, p.Gateway.Check(r.Gateway.Workload))
	for _, m := range r.Models {
		for _, d := range p.drifts(r.Gateway.Workload, m.Workload) {
			if !slices.Contains(drifts, d) {
				drifts = append(drifts, d)
			}
		}
	}
	return drifts
}

// NearWorkloads is each TD a NEAR report verified, by workload, so a later reader can judge each
// one against pins again.
type NearWorkloads struct {
	Gateway []Workload `json:"gateway"`
	Model   []Workload `json:"model"`
}

func VerifiedNearWorkloads(r NearReport) NearWorkloads {
	w := NearWorkloads{Gateway: []Workload{r.Gateway.Workload}}
	for _, m := range r.Models {
		w.Model = append(w.Model, m.Workload)
	}
	return w
}

func ObservedNear(r NearReport) GatewayModelPins {
	var o GatewayModelPins
	o.Gateway.observe(r.Gateway.Workload)
	for _, m := range r.Models {
		o.Model.observe(m.Workload)
	}
	return o
}

func (p *WorkloadPins) observe(w Workload) {
	p.TDAttributes, p.AppID = w.TDAttributes, w.AppID
	p.KeyProviderIDs = appendNew(p.KeyProviderIDs, w.KeyProviderID)
	p.TCBStatuses = appendNew(p.TCBStatuses, w.TCB.Status)
	p.Composes = appendNew(p.Composes, Compose{ComposeHash: w.ComposeHash})
	p.Images = appendNew(p.Images, OSImage{OSMeasurement: w.OSMeasurement})
	p.Instances = appendNew(p.Instances, w.InstanceID)
}

func appendNew[T comparable](s []T, v T) []T {
	if slices.Contains(s, v) {
		return s
	}
	return append(s, v)
}
