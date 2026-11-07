package lifecycle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKubeOneV1144IsPinnedCandidateNotAutomaticUpgrade(t *testing.T) {
	p, ok := KubeOneCandidateRelease("1.14.4")
	if !ok || p.SourceCommit != "a9a7416e9c50aff6d0021b561d6f485836469613" ||
		p.AssetSHA256 != "5b2217f13a888cefbb94b71b26883c9e96c096fda48e9cdb2b6fb7740b0691e7" ||
		p.BinarySHA256 != "3ee3427af6baddf21816effbf08d1aeaafb913acecd0299a87030c70af8b8a8a" {
		t.Fatal("official release asset/source identity drift")
	}
	for _, v := range []string{"1.14.3", "1.14.5", "latest", "", "v1.14.4"} {
		if _, ok := KubeOneCandidateRelease(v); ok {
			t.Fatal("unverified version admitted", v)
		}
	}
	root := t.TempDir()
	file := filepath.Join(root, "kubeone")
	if err := os.WriteFile(file, []byte(strings.Repeat("not-an-official-release", 100000)), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyKubeOneCandidate(file, "1.14.4"); err == nil {
		t.Fatal("fake release with same claimed version passed checksum")
	}
	if err := os.Symlink(file, filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyKubeOneCandidate(filepath.Join(root, "alias"), "1.14.4"); err == nil {
		t.Fatal("symlink candidate accepted")
	}
	if _, err := VerifyKubeOneCandidate(file, "1.14.5"); err == nil {
		t.Fatal("future unpinned release accepted")
	}
}

func TestOfficialV1144CandidateOnExplicitTestHost(t *testing.T) {
	path := os.Getenv("LAYERSENTRY_TEST_KUBEONE_V1144_BINARY")
	if path == "" {
		t.Skip("isolated official release candidate path not provided")
	}
	pin, err := VerifyKubeOneCandidate(path, "1.14.4")
	if err != nil || pin.Version != "1.14.4" {
		t.Fatal("official candidate verification failed", err)
	}
}
