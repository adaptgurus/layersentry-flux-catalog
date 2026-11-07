//go:build !linux

package lifecycle

import (
	"context"
	"errors"
	"net/http"
)

type nativeWorkspaceLease struct{}

func (*nativeWorkspaceLease) Close() error { return nil }
func lockNativeWorkspace(w Workspace) (*nativeWorkspaceLease, error) {
	if nativeWorkspaceSelected(w) {
		return nil, ErrValidation
	}
	return nil, nil
}
func (*Portal) EnableNativeWorkspaceSuccessor() error {
	return errors.New("native workspace owner requires Linux")
}
func (*Portal) workspaceSuccessorAction(w http.ResponseWriter, r *http.Request) {
	portalError(w, http.StatusNotImplemented, ErrValidation)
}
func (*Portal) verifyNativeWorkspaceProvision(_ context.Context, w Workspace, _ *nativeWorkspaceLease) error {
	if nativeWorkspaceSelected(w) {
		return ErrValidation
	}
	return nil
}
