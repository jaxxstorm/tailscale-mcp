package aperture

import (
	"bytes"
	"encoding/json"
	"errors"
)

// Optional schema fields may be omitted, but their declared types exclude null.
// UnmarshalJSON runs only for present fields, unlike a pointer's nil value which
// cannot distinguish omission from an explicit null.
type optionalValue[T any] struct{ Value T }

func (v *optionalValue[T]) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return errors.New("optional field must not be null")
	}
	return json.Unmarshal(data, &v.Value)
}

// Pointer fields distinguish required values from omitted or null values.
// Return the original normalized JSON, not these validation-only structures,
// so decimal strings and configured adjustments remain unchanged.
type pricingRate struct {
	Source        *string                               `json:"source"`
	ResolvedModel *string                               `json:"resolved_model"`
	Adjustment    *float64                              `json:"resolver_adjustment"`
	Effective     map[string]json.RawMessage            `json:"effective_pricing"`
	Modes         optionalValue[map[string]pricingRate] `json:"modes"`
}

func validPricing(data []byte) bool {
	var catalog struct {
		Units map[string]*struct {
			Basis    *string `json:"basis"`
			Quantity *int64  `json:"quantity"`
		} `json:"units"`
		Models map[string]*struct {
			CostBases map[string]pricingRate `json:"cost_bases"`
		} `json:"models"`
		Adjustments struct {
			Providers map[string]*struct {
				CostBasis optionalValue[string] `json:"cost_basis"`
				Source    *string               `json:"cost_basis_source"`
				Rules     json.RawMessage       `json:"model_cost_map"`
			} `json:"providers"`
		} `json:"configured_adjustments"`
	}
	if json.Unmarshal(data, &catalog) != nil || catalog.Adjustments.Providers == nil {
		return false
	}
	for _, unit := range catalog.Units {
		if unit == nil || unit.Basis == nil || unit.Quantity == nil {
			return false
		}
	}
	for _, model := range catalog.Models {
		if model == nil || model.CostBases == nil {
			return false
		}
		for _, rate := range model.CostBases {
			if !validRate(rate) {
				return false
			}
			for _, mode := range rate.Modes.Value {
				if !validRate(mode) {
					return false
				}
			}
		}
	}
	for _, provider := range catalog.Adjustments.Providers {
		if provider == nil || provider.Source == nil || len(provider.Rules) == 0 {
			return false
		}
		var rules []*struct {
			Match      *string                `json:"match"`
			As         *string                `json:"as"`
			Adjustment optionalValue[float64] `json:"adjustment"`
		}
		if json.Unmarshal(provider.Rules, &rules) != nil {
			return false
		}
		for _, rule := range rules {
			if rule == nil || rule.Match == nil || rule.As == nil {
				return false
			}
		}
	}
	return true
}

func validRate(rate pricingRate) bool {
	if rate.Source == nil || rate.ResolvedModel == nil || rate.Adjustment == nil || rate.Effective == nil {
		return false
	}
	for field, value := range rate.Effective {
		if string(value) == "null" {
			return false
		}
		if field == "variable" {
			var b bool
			if json.Unmarshal(value, &b) != nil {
				return false
			}
		} else {
			var s string
			if json.Unmarshal(value, &s) != nil {
				return false
			}
		}
	}
	return true
}
