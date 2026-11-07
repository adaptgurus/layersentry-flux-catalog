package lifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"time"
)

// A signed V2 proof also binds an independent fsynced storage marker to
// the exact restored PVC UID and the current signed fencing operation.
// This is NOT a storage probe implemented by the portal. The authorized,
// independent post-recovery verifier must write this versioned marker to
// a separate disposable path on the exact restored PVC, fsync, read it
// back, and independently sign the resulting proof and its observed time.
// Missing/old/replayed/foreign proofs fail closed.
var drKubernetesPVCUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func drStorageProbeChallengeDigest(v DRCompletionProof, w DRCompletedWorkload) string {
	challenge := fmt.Sprintf("layersentry-dr-storage-fsync/v1\n%s\n%s\n%s\n%s\n%d\n%s\n%s\n%s\n",
		v.OperationID, v.Direction, v.ActiveWriterClusterID, v.FencedClusterID,
		v.FenceEpoch, w.Namespace, w.PVCName, w.StorageProbePVCUID)
	sum := sha256.Sum256([]byte(challenge))
	return hex.EncodeToString(sum[:])
}

func validDRCompletedStorageProbe(v DRCompletionProof, job DRTransitionJob, w DRCompletedWorkload, now time.Time) bool {
	if v.Version != 2 {
		return true // V1 manual-only path, never auto-promoted.
	}
	if w.Kind != "STATEFUL" {
		// Stateless endpoint proof is attested separately; a fake PVC probe
		// must not mask a missing real stateful filesystem proof.
		return w.StorageProbePVCUID == "" && w.StorageProbeCompletedAt.IsZero() &&
			w.StorageProbeReadbackSHA256 == ""
	}
	if !drKubernetesPVCUUID.MatchString(w.StorageProbePVCUID) ||
		w.StorageProbeCompletedAt.IsZero() ||
		w.StorageProbeCompletedAt.Before(job.UpdatedAt) ||
		w.StorageProbeCompletedAt.After(v.IssuedAt) ||
		v.IssuedAt.Sub(w.StorageProbeCompletedAt) > 90*time.Second ||
		now.Before(w.StorageProbeCompletedAt) || now.Sub(w.StorageProbeCompletedAt) > 90*time.Second ||
		!isSHA256Hex(w.StorageProbeReadbackSHA256) {
		return false
	}
	return w.StorageProbeReadbackSHA256 == drStorageProbeChallengeDigest(v, w)
}
