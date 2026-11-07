package lifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// Official v1.14.4 candidate from Kubermatic's immutable October 6, 2026
// release. The zip digest was verified against upstream checksums.txt, then
// the extracted binary was independently hashed. This is NOT a qualification
// to upgrade any existing Kubernetes cluster or to change KubeOne's etcd PKI.
type KubeOneReleasePin struct {
	Version        string
	SourceTag      string
	SourceCommit   string
	AssetSHA256    string
	BinarySHA256   string
	SupportedMinor string
}

var kubeOneV1144 = KubeOneReleasePin{
	Version:        "1.14.4",
	SourceTag:      "v1.14.4",
	SourceCommit:   "a9a7416e9c50aff6d0021b561d6f485836469613",
	AssetSHA256:    "5b2217f13a888cefbb94b71b26883c9e96c096fda48e9cdb2b6fb7740b0691e7",
	BinarySHA256:   "3ee3427af6baddf21816effbf08d1aeaafb913acecd0299a87030c70af8b8a8a",
	SupportedMinor: "1.34,1.35,1.36",
}

func KubeOneCandidateRelease(version string) (KubeOneReleasePin, bool) {
	if version != kubeOneV1144.Version {
		return KubeOneReleasePin{}, false
	}
	return kubeOneV1144, true
}

// VerifyKubeOneCandidate is a nonmutating binary admission gate. Runtime
// activation is separate and requires a compatible, individually selected
// cluster. A string with the expected version is never enough to trust bytes.
func VerifyKubeOneCandidate(path, version string) (KubeOneReleasePin, error) {
	pin, ok := KubeOneCandidateRelease(version)
	if !ok || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return KubeOneReleasePin{}, fmt.Errorf("%w: KubeOne release not in qualified candidate registry", ErrValidation)
	}
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Mode()&0111 == 0 || st.Mode().Perm()&0022 != 0 || st.Size() < 1<<20 || st.Size() > 256<<20 {
		return KubeOneReleasePin{}, fmt.Errorf("%w: KubeOne candidate file or mode unavailable", ErrValidation)
	}
	native, ok := st.Sys().(*syscall.Stat_t)
	if !ok || native.Nlink != 1 || native.Uid != 0 {
		return KubeOneReleasePin{}, fmt.Errorf("%w: KubeOne binary owner or link count untrusted", ErrValidation)
	}
	f, err := os.Open(path)
	if err != nil {
		return KubeOneReleasePin{}, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(st, opened) {
		return KubeOneReleasePin{}, ErrValidation
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, 256<<20+1))
	if err != nil || n != st.Size() {
		return KubeOneReleasePin{}, errors.New("KubeOne release changed during digest verification")
	}
	if hex.EncodeToString(h.Sum(nil)) != pin.BinarySHA256 {
		return KubeOneReleasePin{}, fmt.Errorf("%w: KubeOne candidate digest differs from pinned release", ErrValidation)
	}
	return pin, nil
}
