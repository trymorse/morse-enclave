package routes

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"morse/backend/internal/billing/money"
)

// VeilPrice reads privacy_veil.price from a routes file: what a key pays for the Privacy Veil's filter, a price per call
// and per million tokens it reads, which equals what the filter costs Morse. A file that names none prices
// the Veil at zero.
func VeilPrice(data []byte) (money.VeilRate, error) {
	var file struct {
		PrivacyVeil json.RawMessage `json:"privacy_veil"`
	}
	if err := json.Unmarshal(data, &file); err != nil || file.PrivacyVeil == nil {
		return money.VeilRate{}, err
	}
	var v struct {
		Price struct {
			MicrosPerCall       *int64 `json:"micros_per_call"`
			PromptMicrosPerMTok *int64 `json:"prompt_micros_per_mtok"`
		} `json:"price"`
	}
	dec := json.NewDecoder(bytes.NewReader(file.PrivacyVeil))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return money.VeilRate{}, fmt.Errorf("routes file: privacy_veil: %w", err)
	}
	call, mtok := v.Price.MicrosPerCall, v.Price.PromptMicrosPerMTok
	if call == nil || mtok == nil || *call < 0 || *mtok < 0 || *call == 0 && *mtok == 0 {
		return money.VeilRate{}, errors.New("routes file: privacy_veil.price needs micros_per_call and prompt_micros_per_mtok, neither negative and not both zero")
	}
	return money.VeilRate{PerCall: money.Micros(*call), PerMTok: money.Micros(*mtok)}, nil
}
