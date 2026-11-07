package lifecycle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// These are authenticated source-only portal calls with the existing fake
// KubeOne runner. Malformed durable intent must not clear original ambiguity.
func TestPersistedLifecycleJSONCannotClearOriginalAmbiguity(t *testing.T) {
	mutations := []struct {
		name string
		edit func([]byte, string) []byte
	}{
		{"duplicate-status", func(raw []byte, state string) []byte {
			return bytes.Replace(raw, []byte(`"status":"`+state+`"`), []byte(`"status":"`+state+`","status":"SUCCEEDED"`), 1)
		}},
		{"escaped-duplicate-status", func(raw []byte, state string) []byte {
			return bytes.Replace(raw, []byte(`"status":"`+state+`"`), []byte(`"status":"`+state+`","st\u0061tus":"SUCCEEDED"`), 1)
		}},
		{"case-aliased-status", func(raw []byte, state string) []byte {
			return bytes.Replace(raw, []byte(`"status":"`+state+`"`), []byte(`"status":"`+state+`","Status":"SUCCEEDED"`), 1)
		}},
		{"invalid-utf8", func(raw []byte, state string) []byte {
			return append([]byte{'{', '"', 'm', 'e', 's', 's', 'a', 'g', 'e', '"', ':', '"', 0xff, '"', ','}, bytes.Replace(raw[1:], []byte(`"status":"`+state+`"`), []byte(`"status":"SUCCEEDED"`), 1)...)
		}},
		{"unpaired-surrogate", func(raw []byte, state string) []byte {
			raw = bytes.Replace(raw, []byte(`"status":"`+state+`"`), []byte(`"status":"SUCCEEDED"`), 1)
			return append([]byte(`{"message":"\ud800",`), raw[1:]...)
		}},
	}
	for _, pair := range [][2]string{{"worker", "control-plane"}, {"control-plane", "worker"}, {"provision", "worker"}, {"worker", "provision"}} {
		for _, state := range []string{"UNKNOWN", "RUNNING"} {
			for _, mutation := range mutations {
				t.Run(fmt.Sprintf("%s-to-%s/%s/%s", pair[0], pair[1], state, mutation.name), func(t *testing.T) {
					_, h, ws, runner := attributionFixture(t)
					path, raw := overlapJob(t, ws, pair[0], state)
					raw = mutation.edit(raw, state)
					if err := os.WriteFile(path, raw, 0600); err != nil {
						t.Fatal(err)
					}
					url := overlapEndpoint(t, ws, pair[1])
					runner.fail = true
					response := portalAdminRequest(t, h, http.MethodPost, url, "{}", ws.Tenant)
					if response.Code == http.StatusAccepted {
						waitPortalJob(t, h, url, ws.Tenant, "UNKNOWN")
					}
					after, err := os.ReadFile(path)
					target := workerJobPath(ws)
					if pair[1] == "control-plane" {
						target = controlPlaneJobPath(ws)
					} else if pair[1] == "provision" {
						target = provisionJobPath(ws)
					}
					_, targetErr := os.Lstat(target)
					t.Logf("SOURCE_ONLY response=%d fake_applies=%d original_bytes_unchanged=%t target_absent=%t native_execution=false", response.Code, runner.applies, bytes.Equal(raw, after), os.IsNotExist(targetErr))
					if response.Code != http.StatusInternalServerError || runner.applies != 0 || err != nil || !bytes.Equal(raw, after) || !os.IsNotExist(targetErr) {
						t.Fatal("malformed persisted lifecycle JSON crossed admission or changed original intent")
					}
				})
			}
		}
	}
}

func TestPersistedLifecycleJSONRecheckedAfterHealth(t *testing.T) {
	for _, kind := range []string{"worker", "control-plane"} {
		for _, suffix := range []string{`"status":"SUCCEEDED"`, `"st\u0061tus":"SUCCEEDED"`, `"Status":"SUCCEEDED"`, `"message":"\ud800"`} {
			t.Run(kind+"/"+suffix, func(t *testing.T) {
				_, h, ws, runner := attributionFixture(t)
				other, target := "worker", controlPlaneJobPath(ws)
				if kind == "worker" {
					other, target = "control-plane", workerJobPath(ws)
				}
				var path string
				var raw []byte
				runner.inner = &overlapStatusHook{Runner: runner.inner, hook: func() {
					path, raw = overlapJob(t, ws, other, "UNKNOWN")
					raw = append(append(raw[:len(raw)-1:len(raw)-1], ','), []byte(suffix+"}")...)
					if err := os.WriteFile(path, raw, 0600); err != nil {
						t.Fatal(err)
					}
				}}
				response := portalAdminRequest(t, h, http.MethodPost, overlapEndpoint(t, ws, kind), "{}", ws.Tenant)
				after, err := os.ReadFile(path)
				_, targetErr := os.Lstat(target)
				if response.Code != http.StatusInternalServerError || runner.applies != 0 || err != nil || !bytes.Equal(raw, after) || !os.IsNotExist(targetErr) {
					t.Fatalf("late malformed job crossed admission: response=%d applies=%d read=%v target=%v", response.Code, runner.applies, err, targetErr)
				}
			})
		}
	}
}

func TestPersistedLifecycleJSONFlatWriterShape(t *testing.T) {
	now := time.Now().UTC()
	jobs := []any{
		WorkerReconcileJob{ID: "original-worker", ClusterID: "cluster-a", Status: "UNKNOWN", RequestedAt: now, UpdatedAt: now, EvidenceLabel: "UNKNOWN"},
		ControlPlaneReconcileJob{ID: "original-control-plane", ClusterID: "cluster-a", Status: "UNKNOWN", RequestedAt: now, UpdatedAt: now, EvidenceLabel: "UNKNOWN"},
		ProvisionJob{ID: "original-provision", ClusterID: "cluster-a", Status: "UNKNOWN", RequestedAt: now, UpdatedAt: now, EvidenceLabel: "UNKNOWN"},
	}
	for _, original := range jobs {
		t.Run(fmt.Sprintf("%T", original), func(t *testing.T) {
			raw, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			check := func(t *testing.T, input []byte, valid bool) {
				t.Helper()
				// Start with a populated output: malformed reads cannot partially
				// replace the original record, even when later fields fail.
				out := reflect.New(reflect.TypeOf(original))
				out.Elem().Set(reflect.ValueOf(original))
				path := filepath.Join(t.TempDir(), "job.json")
				if err := os.WriteFile(path, input, 0600); err != nil {
					t.Fatal(err)
				}
				err := readBoundedJob(path, out.Interface())
				if (err == nil) != valid {
					t.Fatalf("valid=%t err=%v", valid, err)
				}
				if !valid && !reflect.DeepEqual(out.Elem().Interface(), original) {
					t.Fatal("failed read exposed a partially decoded record")
				}
			}
			t.Run("marshal-optional-message-absent", func(t *testing.T) { check(t, raw, true) })
			for name := range fields {
				for _, mode := range []string{"missing", "null", "wrong-type"} {
					t.Run(name+"/"+mode, func(t *testing.T) {
						changed := make(map[string]json.RawMessage, len(fields))
						for key, value := range fields {
							changed[key] = value
						}
						switch mode {
						case "missing":
							delete(changed, name)
						case "null":
							changed[name] = json.RawMessage("null")
						case "wrong-type":
							changed[name] = json.RawMessage("true")
						}
						input, err := json.Marshal(changed)
						if err != nil {
							t.Fatal(err)
						}
						check(t, input, false)
					})
				}
			}
			for label, input := range map[string][]byte{
				"root-null": []byte("null"), "root-array": []byte("[]"), "trailing": append(bytes.Clone(raw), []byte(" {}")...),
				"bad-timestamp":  bytes.Replace(raw, fields["updated_at"], []byte(`"invalid"`), 1),
				"case-only-key":  bytes.Replace(raw, []byte(`"status"`), []byte(`"Status"`), 1),
				"count-overflow": bytes.Replace(raw, []byte(`:0`), []byte(`:999999999999999999999999999999`), 1),
				"count-fraction": bytes.Replace(raw, []byte(`:0`), []byte(`:0.5`), 1),
				"message-null":   append(append(bytes.Clone(raw[:len(raw)-1]), ','), []byte(`"message":null}`)...),
				"low-surrogate":  append(append(bytes.Clone(raw[:len(raw)-1]), ','), []byte(`"message":"\udfff"}`)...),
			} {
				t.Run(label, func(t *testing.T) { check(t, input, false) })
			}
			for label, message := range map[string]string{
				"paired-surrogates": `"\ud83d\ude00"`, "literal-replacement": `"�"`, "unicode": `"नमस्ते"`, "escaped-backslash": `"\\ud800"`, "escaped-quote": `"\""`,
			} {
				t.Run(label, func(t *testing.T) {
					input := append(append(bytes.Clone(raw[:len(raw)-1]), ','), []byte(`"message":`+message+`}`)...)
					check(t, input, true)
				})
			}
			t.Run("unique-escaped-canonical-key", func(t *testing.T) {
				check(t, bytes.Replace(raw, []byte(`"status"`), []byte(`"st\u0061tus"`), 1), true)
			})
		})
	}
}

func TestPersistedLifecycleJSONFileBounds(t *testing.T) {
	root := t.TempDir()
	var job ProvisionJob
	for _, size := range []int{0, int(maxPortalBodyBytes) + 1} {
		t.Run(fmt.Sprintf("size-%d", size), func(t *testing.T) {
			path := filepath.Join(root, fmt.Sprint(size))
			if err := os.WriteFile(path, []byte(strings.Repeat(" ", size)), 0600); err != nil {
				t.Fatal(err)
			}
			if err := readBoundedJob(path, &job); err == nil {
				t.Fatal("invalid file size accepted")
			}
		})
	}
	path := filepath.Join(root, "link")
	if err := os.Symlink(filepath.Join(root, "0"), path); err != nil {
		t.Fatal(err)
	}
	if err := readBoundedJob(path, &job); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := readBoundedJob(root, &job); err == nil {
		t.Fatal("directory accepted")
	}
	if err := readBoundedJob(filepath.Join(root, "absent"), &job); !os.IsNotExist(err) {
		t.Fatal("genuine absence changed", err)
	}
}

func TestPersistedLifecycleJSONRejectsInvalidOutput(t *testing.T) {
	var worker *WorkerReconcileJob
	var controlPlane *ControlPlaneReconcileJob
	var provision *ProvisionJob
	for _, out := range []any{nil, worker, controlPlane, provision, new(map[string]any)} {
		if err := decodeLifecycleJob([]byte(`{}`), out); err == nil {
			t.Fatalf("unsupported or nil output accepted: %T", out)
		}
	}
}
