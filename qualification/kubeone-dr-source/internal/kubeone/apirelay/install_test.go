package apirelay

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestInstallerFenceRejectsEveryOtherOperation(t *testing.T) {
	valid := map[string]any{"id": originalJobID, "cluster_id": "kubeone-dc", "status": "UNKNOWN", "ready_nodes": 0, "expected_nodes": 4}
	raw, _ := json.Marshal(valid)
	if err := installJob(raw); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct {
		field string
		value any
	}{{"id", strings.Repeat("a", 32)}, {"cluster_id", "kubeone-dr"}, {"status", "NOT_STARTED"}, {"status", "RUNNING"}, {"status", "SUCCEEDED"}, {"ready_nodes", 1}, {"expected_nodes", 3}} {
		copy := map[string]any{}
		for k, v := range valid {
			copy[k] = v
		}
		copy[change.field] = change.value
		raw, _ := json.Marshal(copy)
		if installJob(raw) == nil {
			t.Fatalf("unsafe installer fence accepted: %s", change.field)
		}
	}
}

func TestRegistryPublicationTouchesOnlyBoundDCReference(t *testing.T) {
	original := []byte(`{"other":9007199254740993,"clusters":[{"tenant":"lab-dc","cluster_id":"kubeone-dc","directory":"lab-dc/kubeone-dc","manifest":"kubeone.yaml"},{"tenant":"foreign","cluster_id":"kubeone-dc","directory":"foreign"}]}`)
	desired, err := desiredRegistry(original)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(desired, &doc) != nil {
		t.Fatal("invalid resulting registry")
	}
	if string(doc["other"]) != "9007199254740993" {
		t.Fatal("unrelated native value lost precision")
	}
	var clusters []map[string]json.RawMessage
	_ = json.Unmarshal(doc["clusters"], &clusters)
	if string(clusters[0]["api_proxy_url"]) != `"socks5://127.0.0.1:19446"` || string(clusters[0]["api_proxy_credentials"]) != `"api-relay-credentials.json"` || clusters[1]["api_proxy_url"] != nil {
		t.Fatal("registry scope widened")
	}
	if strings.Contains(string(desired), "password") || strings.Contains(string(desired), "username") {
		t.Fatal("registry contains authentication data")
	}
	for _, bad := range []string{strings.Replace(string(original), "lab-dc/kubeone-dc", "foreign", 1), strings.Replace(string(original), `"manifest":"kubeone.yaml"`, `"api_proxy_url":"socks5://foreign:1080"`, 1), `{"clusters":[]}`} {
		if _, err = desiredRegistry([]byte(bad)); err == nil {
			t.Fatal("foreign registry plan admitted")
		}
	}
}

func installTestDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", ".relay-install-test-")
	if err != nil {
		t.Fatal(err)
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestAtomicPublisherPreservesForeignTargetsAndResumesOwnBytes(t *testing.T) {
	dir := installTestDir(t)
	path := filepath.Join(dir, "owned")
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	original, desired := []byte("original-native-value"), []byte("reviewed-new-value")
	if err := publishOwned(path, original, uid, gid, 0600); err != nil {
		t.Fatal(err)
	}
	if err := publishOwned(path, desired, uid, gid, 0600); err == nil {
		t.Fatal("foreign content overwritten")
	}
	if got, _ := os.ReadFile(path); string(got) != string(original) {
		t.Fatal("rejected mutation changed target")
	}
	if err := publishOwned(path, desired, uid, gid, 0600, digest(original)); err != nil {
		t.Fatal(err)
	}
	if err := publishOwned(path, desired, uid, gid, 0600); err != nil {
		t.Fatal("own publication was not resumable")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := publishOwned(link, desired, uid, gid, 0600); err == nil {
		t.Fatal("publication followed symlink")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("private publication mode differs")
	}
}

func TestInstallerReadinessUsesAuthenticationAndForeignDestinationDenial(t *testing.T) {
	f := &fakeTransport{}
	address, _, _ := relayFixture(t, f)
	if err := readiness(context.Background(), address, testCredential); err != nil {
		t.Fatal(err)
	}
	probes, opens, _ := f.snapshot()
	if len(probes)+len(opens) != 0 {
		t.Fatal("installer negative readback dispatched SSH")
	}
	wrong := testCredential
	wrong.Password = strings.Repeat("x", 32)
	if readiness(context.Background(), address, wrong) == nil {
		t.Fatal("installer accepted a differently authenticated listener")
	}
}

func TestInstallerReadinessRejectsUnauthenticatedForeignListener(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := listener.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		var b [3]byte
		_, _ = io.ReadFull(c, b[:])
		_, _ = c.Write([]byte{5, 0})
	}()
	if readiness(context.Background(), listener.Addr().String(), testCredential) == nil {
		t.Fatal("foreign unauthenticated listener adopted")
	}
	<-done
}

func TestNativeSocketReadbackRequiresExactUIDAndProcess(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portText)
	uid := uint32(os.Geteuid())
	if err = listenerOwnerAt(uid, os.Getpid(), false, uint16(port)); err != nil {
		t.Fatal(err)
	}
	if listenerOwnerAt(uid+1, os.Getpid(), false, uint16(port)) == nil {
		t.Fatal("foreign socket UID accepted")
	}
	if listenerOwnerAt(uid, 0, false, uint16(port)) == nil {
		t.Fatal("foreign socket process accepted")
	}
}

func TestAtomicPublisherRejectsExposedCredentialWithoutRewriting(t *testing.T) {
	dir := installTestDir(t)
	path := filepath.Join(dir, "credential.json")
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	raw := []byte("runtime-only-credential")
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := publishOwned(path, raw, uid, gid, 0600, digest(raw)); err == nil {
		t.Fatal("previously exposed credential reused")
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() != 0644 || !after.ModTime().Equal(before.ModTime()) || string(got) != string(raw) {
		t.Fatal("rejection rewrote exposed credential")
	}
}
