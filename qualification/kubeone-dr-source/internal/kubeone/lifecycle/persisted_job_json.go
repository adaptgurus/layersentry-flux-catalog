package lifecycle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// These are the existing flat writer contracts, not new operation authority.
// Decode into a fresh record so a failed read cannot expose a partial outcome.
func decodeLifecycleJob(raw []byte, out any) error {
	fields := "id cluster_id status requested_at updated_at evidence_label"
	var fresh any
	var publish func()
	switch target := out.(type) {
	case *WorkerReconcileJob:
		if target == nil {
			return fmt.Errorf("%w: nil lifecycle operation output", ErrValidation)
		}
		job := new(WorkerReconcileJob)
		fresh, publish = job, func() { *target = *job }
		fields += " ready_nodes expected_nodes"
	case *ControlPlaneReconcileJob:
		if target == nil {
			return fmt.Errorf("%w: nil lifecycle operation output", ErrValidation)
		}
		job := new(ControlPlaneReconcileJob)
		fresh, publish = job, func() { *target = *job }
		fields += " ready_control_planes expected_control_planes"
	case *ProvisionJob:
		if target == nil {
			return fmt.Errorf("%w: nil lifecycle operation output", ErrValidation)
		}
		job := new(ProvisionJob)
		fresh, publish = job, func() { *target = *job }
		fields += " ready_nodes expected_nodes"
	default:
		return fmt.Errorf("%w: unsupported lifecycle operation record", ErrValidation)
	}
	if err := applicationJSONFields(raw, fields+" message"); err != nil {
		return fmt.Errorf("%w: invalid lifecycle operation JSON: %v", ErrValidation, err)
	}
	if !lifecycleJSONSurrogates(raw) {
		return fmt.Errorf("%w: invalid lifecycle operation Unicode", ErrValidation)
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil {
		return err
	}
	for _, name := range strings.Fields(fields + " message") {
		value, present := values[name]
		if name == "message" && !present {
			continue
		}
		value = bytes.TrimSpace(value)
		if len(value) == 0 {
			return fmt.Errorf("%w: lifecycle operation field is missing", ErrValidation)
		}
		count := strings.HasPrefix(name, "ready_") || strings.HasPrefix(name, "expected_")
		if (!count && value[0] != '"') || (count && value[0] != '-' && (value[0] < '0' || value[0] > '9')) {
			return fmt.Errorf("%w: invalid lifecycle operation field type", ErrValidation)
		}
	}
	// Exact fields and a single object were checked above. Native decoding keeps
	// integer bounds and time.Time semantics unchanged.
	if err := json.Unmarshal(raw, fresh); err != nil {
		return fmt.Errorf("decode lifecycle operation state: %w", err)
	}
	publish()
	return nil
}

// Call only after JSON syntax validation. encoding/json otherwise replaces
// lone escaped surrogates, erasing the original malformed record's identity.
func lifecycleJSONSurrogates(raw []byte) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if raw[i] != 'u' {
			continue
		}
		n, _ := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		i += 4
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		} else if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
	}
	return true
}
