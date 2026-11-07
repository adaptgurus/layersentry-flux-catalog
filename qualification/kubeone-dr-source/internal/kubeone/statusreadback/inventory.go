// Package statusreadback validates selected native health response fields.
// It supplies no membership, version, operation attribution or authority proof.
package statusreadback

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

var errInventory = errors.New("invalid or ambiguous health inventory")

const maxBytes = 16 << 20
const maxDepth = 32
const maxTokens = 262144
const maxScalar = 1 << 20

type Node struct {
	Name                string
	Ready, ControlPlane bool
}

type Pod struct {
	Phase           string
	ContainersReady bool
}

// Bound ignored enrichment too. Reject invalid Unicode before encoding/json
// can replace distinct malformed identities with the same replacement rune.
func bounded(raw string) error {
	if len(raw) == 0 || len(raw) > maxBytes || !utf8.ValidString(raw) {
		return errInventory
	}
	inString := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return errInventory
		}
		if raw[i] != 'u' {
			continue
		}
		n, ok := hexUnit(raw, i+1)
		if !ok {
			return errInventory
		}
		i += 4
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return errInventory
			}
			low, ok := hexUnit(raw, i+3)
			if !ok || low < 0xdc00 || low > 0xdfff {
				return errInventory
			}
			i += 6
		} else if n >= 0xdc00 && n <= 0xdfff {
			return errInventory
		}
	}
	d := json.NewDecoder(strings.NewReader(raw))
	d.UseNumber()
	depth, tokens := 0, 0
	for {
		t, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errInventory
		}
		tokens++
		if tokens > maxTokens {
			return errInventory
		}
		switch v := t.(type) {
		case json.Delim:
			if v == '{' || v == '[' {
				depth++
				if depth > maxDepth {
					return errInventory
				}
			} else {
				depth--
			}
		case string:
			if len(v) > maxScalar {
				return errInventory
			}
		case json.Number:
			if len(v) > maxScalar {
				return errInventory
			}
		}
	}
	if depth != 0 {
		return errInventory
	}
	return nil
}

func hexUnit(raw string, at int) (uint16, bool) {
	if at+4 > len(raw) {
		return 0, false
	}
	var n uint16
	for _, b := range []byte(raw[at : at+4]) {
		n <<= 4
		switch {
		case b >= '0' && b <= '9':
			n += uint16(b - '0')
		case b >= 'a' && b <= 'f':
			n += uint16(b - 'a' + 10)
		case b >= 'A' && b <= 'F':
			n += uint16(b - 'A' + 10)
		default:
			return 0, false
		}
	}
	return n, true
}

func object(raw json.RawMessage, selected ...string) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return nil, errInventory
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return nil, errInventory
		}
		key, ok := t.(string)
		if !ok {
			return nil, errInventory
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, errInventory
		}
		for _, canonical := range selected {
			if !strings.EqualFold(key, canonical) {
				continue
			}
			if key != canonical {
				return nil, errInventory
			}
			if _, exists := out[key]; exists {
				return nil, errInventory
			}
			out[key] = value
		}
	}
	t, err = d.Token()
	if err != nil || t != json.Delim('}') {
		return nil, errInventory
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errInventory
	}
	return out, nil
}

func array(raw json.RawMessage) ([]json.RawMessage, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '[' {
		return nil, errInventory
	}
	var values []json.RawMessage
	if json.Unmarshal(raw, &values) != nil {
		return nil, errInventory
	}
	return values, nil
}

func text(raw json.RawMessage) (string, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '"' {
		return "", errInventory
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return "", errInventory
	}
	return value, nil
}

func list(raw string) ([]json.RawMessage, error) {
	if err := bounded(raw); err != nil {
		return nil, err
	}
	root, err := object(json.RawMessage(raw), "items")
	if err != nil {
		return nil, err
	}
	return array(root["items"])
}

func Nodes(raw string) ([]Node, error) {
	items, err := list(raw)
	if err != nil {
		return nil, err
	}
	out := make([]Node, 0, len(items))
	for _, raw := range items {
		item, err := object(raw, "metadata", "status")
		if err != nil {
			return nil, err
		}
		var node Node
		if raw, ok := item["metadata"]; ok {
			metadata, err := object(raw, "name", "labels")
			if err != nil {
				return nil, err
			}
			if raw, ok := metadata["name"]; ok {
				node.Name, err = text(raw)
				if err != nil {
					return nil, err
				}
			}
			if raw, ok := metadata["labels"]; ok {
				labels, err := object(raw, "node-role.kubernetes.io/control-plane", "node-role.kubernetes.io/master")
				if err != nil {
					return nil, err
				}
				for _, raw := range labels {
					if _, err := text(raw); err != nil {
						return nil, err
					}
					node.ControlPlane = true
				}
			}
		}
		if raw, ok := item["status"]; ok {
			status, err := object(raw, "conditions")
			if err != nil {
				return nil, err
			}
			if raw, ok := status["conditions"]; ok {
				conditions, err := array(raw)
				if err != nil {
					return nil, err
				}
				seenReady := false
				for _, raw := range conditions {
					condition, err := object(raw, "type", "status")
					if err != nil {
						return nil, err
					}
					kind, err := text(condition["type"])
					if err != nil {
						return nil, err
					}
					value, err := text(condition["status"])
					if err != nil {
						return nil, err
					}
					if kind == "Ready" {
						if seenReady {
							return nil, errInventory
						}
						seenReady = true
						node.Ready = value == "True"
					}
				}
			}
		}
		out = append(out, node)
	}
	return out, nil
}

func Pods(raw string) ([]Pod, error) {
	items, err := list(raw)
	if err != nil {
		return nil, err
	}
	out := make([]Pod, 0, len(items))
	for _, raw := range items {
		item, err := object(raw, "status")
		if err != nil {
			return nil, err
		}
		var pod Pod
		if raw, ok := item["status"]; ok {
			status, err := object(raw, "phase", "containerStatuses")
			if err != nil {
				return nil, err
			}
			if raw, ok := status["phase"]; ok {
				pod.Phase, err = text(raw)
				if err != nil {
					return nil, err
				}
			}
			if raw, ok := status["containerStatuses"]; ok {
				containers, err := array(raw)
				if err != nil {
					return nil, err
				}
				pod.ContainersReady = len(containers) > 0
				seen := map[string]bool{}
				for _, raw := range containers {
					container, err := object(raw, "name", "ready")
					if err != nil {
						return nil, err
					}
					name := ""
					if raw, ok := container["name"]; ok {
						name, err = text(raw)
						if err != nil {
							return nil, err
						}
					}
					ready, present := false, false
					if raw, ok := container["ready"]; ok {
						switch string(bytes.TrimSpace(raw)) {
						case "true":
							ready = true
						case "false":
						default:
							return nil, errInventory
						}
						present = true
					}
					if pod.Phase == "Running" {
						if name == "" || strings.TrimSpace(name) != name || seen[name] || !present {
							return nil, errInventory
						}
						seen[name] = true
					}
					pod.ContainersReady = pod.ContainersReady && ready
				}
			}
		}
		out = append(out, pod)
	}
	return out, nil
}
