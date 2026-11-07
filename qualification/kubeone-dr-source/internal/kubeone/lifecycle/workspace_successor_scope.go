package lifecycle

import "path/filepath"

const workspaceSuccessorRoot = "/var/lib/layersentry/kubeone/lab-dc/kubeone-dc"

// Either identity or path selects the protected workspace. A renamed registry
// entry cannot evade its owner by presenting only one matching half.
func nativeWorkspaceSelected(w Workspace) bool {
	return w.Tenant == "lab-dc" && w.ClusterID == "kubeone-dc" || filepath.Clean(w.Directory) == workspaceSuccessorRoot
}

func nativeWorkspaceExact(w Workspace) bool {
	return w.Tenant == "lab-dc" && w.ClusterID == "kubeone-dc" && w.Directory == workspaceSuccessorRoot && w.Manifest == workspaceSuccessorRoot+"/kubeone.yaml" && w.Kubeconfig == workspaceSuccessorRoot+"/kubeconfig" && w.TFJSON == "" && w.Credentials == "" && w.ExpectedCPNodes == 3 && w.ExpectedNodes == 4 && w.Provisionable && w.SelfServiceLifecycle
}
