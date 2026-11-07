//go:build linux

package lifecycle

import (
	"context"
	"errors"
	"net/http"
	"os"
	"reflect"
	"time"

	"github.com/layersentry/layersentry-platform/internal/kubeone/workspaceproof"
)

type nativeWorkspaceLease struct {
	dir  *os.File
	lock *workspaceOperationLock
}

func (l *nativeWorkspaceLease) Close() error {
	if l == nil {
		return nil
	}
	return errors.Join(l.lock.Close(), l.dir.Close())
}

func lockNativeWorkspace(w Workspace) (*nativeWorkspaceLease, error) {
	if !nativeWorkspaceSelected(w) {
		return nil, nil
	}
	if !nativeWorkspaceExact(w) {
		return nil, workspaceproof.ErrAdmission
	}
	d, e := workspaceproof.OpenDirectory(workspaceSuccessorRoot, workspaceproof.CallerID, workspaceproof.CallerID, 0700)
	if e != nil {
		return nil, e
	}
	l, e := acquireWorkspaceOperation(d, workspaceproof.CallerID, workspaceproof.CallerID)
	if e != nil {
		d.Close()
		return nil, e
	}
	if workspaceproof.DirectoryStillNamed(d, workspaceSuccessorRoot, workspaceproof.CallerID, workspaceproof.CallerID, 0700) != nil {
		l.Close()
		d.Close()
		return nil, workspaceproof.ErrAdmission
	}
	return &nativeWorkspaceLease{d, l}, nil
}

// Explicit server configuration only; paths and native proof authority cannot
// be supplied by a tenant request. Startup validates protected admission, while
// every operation reads it again and requires the live authenticated provider.
func (p *Portal) EnableNativeWorkspaceSuccessor() error {
	if p == nil {
		return workspaceproof.ErrAdmission
	}
	if _, e := loadWorkspaceSuccessor(); e != nil {
		return e
	}
	p.mu.Lock()
	p.nativeWorkspaceSuccessor = true
	p.mu.Unlock()
	return nil
}

func (p *Portal) workspaceSuccessorAction(w http.ResponseWriter, r *http.Request) {
	workspace, e := p.resolve(r)
	if e != nil {
		portalError(w, http.StatusNotFound, e)
		return
	}
	if !nativeWorkspaceExact(workspace) || !lifecycleAuthorized(r, workspace) {
		portalError(w, http.StatusForbidden, workspaceproof.ErrAdmission)
		return
	}
	action := r.PathValue("action")
	if action != "publish" && action != "reconcile" && action != "continue" {
		portalError(w, http.StatusBadRequest, workspaceproof.ErrAdmission)
		return
	}
	if e = emptyProvisionRequest(w, r); e != nil {
		portalError(w, http.StatusBadRequest, e)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.nativeWorkspaceSuccessor || p.running[registryKey(workspace.Tenant, workspace.ClusterID)] {
		portalError(w, http.StatusConflict, workspaceproof.ErrAdmission)
		return
	}
	lease, e := lockNativeWorkspace(workspace)
	if e != nil {
		portalError(w, http.StatusConflict, workspaceproof.ErrAdmission)
		return
	}
	defer lease.Close()
	s, e := loadWorkspaceSuccessor()
	if e != nil {
		portalError(w, http.StatusConflict, workspaceproof.ErrAdmission)
		return
	}
	// Up to three bounded provider calls surround the durable owner phases.
	// Native observations still retain their individual strict20s validity.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(450 * time.Second))
	ctx, cancel := context.WithTimeout(r.Context(), 420*time.Second)
	defer cancel()
	receipt, e := s.runLocked(ctx, lease.dir, action)
	if e != nil {
		portalError(w, http.StatusConflict, errors.New("workspace publication rejected or unknown; preserve intent and use explicit reconciliation"))
		return
	}
	portalJSON(w, http.StatusOK, map[string]any{"receipt": receipt})
}

// A historical VERIFIED receipt is insufficient to provision. Re-prove the
// exact desired file, original NOT_STARTED job and current native tuple while
// holding the very same operation lock that the apply goroutine will retain.
func (p *Portal) verifyNativeWorkspaceProvision(ctx context.Context, w Workspace, lease *nativeWorkspaceLease) error {
	if !nativeWorkspaceSelected(w) {
		return nil
	}
	if !p.nativeWorkspaceSuccessor || lease == nil || !nativeWorkspaceExact(w) {
		return workspaceproof.ErrAdmission
	}
	s, e := loadWorkspaceSuccessor()
	if e != nil {
		return e
	}
	r, e := s.readReceipt(lease.dir)
	if e != nil || r == nil || r.State != "VERIFIED" {
		return workspaceproof.ErrAdmission
	}
	if ahead, e := s.archivedAdvance(lease.dir, *r); e != nil || ahead != nil {
		return workspaceproof.ErrAdmission
	}
	if _, e = s.files(lease.dir, true); e != nil {
		return e
	}
	if e = s.preservation(lease.dir, false); e != nil {
		return e
	}
	request, proof, e := s.observe(ctx, workspaceproof.Postpublication)
	if e != nil {
		return e
	}
	current, e := s.readReceipt(lease.dir)
	if e != nil || current == nil || !reflect.DeepEqual(r, current) {
		return workspaceproof.ErrAdmission
	}
	if _, e = s.files(lease.dir, true); e != nil {
		return e
	}
	return s.fresh(request, proof)
}
