import copy
import importlib.util
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("validator", ROOT / "scripts" / "validate_catalog.py")
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class CatalogReauditTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / "catalog" / "v1" / "catalog.json").read_text())

    def reject(self, data):
        with self.assertRaises(validator.CatalogError):
            validator.validate(data)

    def test_authority_contract_is_pinned(self):
        bad = copy.deepcopy(self.data)
        bad["authority"]["compatibilityContract"] = "contracts/other.json"
        self.reject(bad)

    def test_gitops_customer_ownership_is_fail_closed(self):
        bad = copy.deepcopy(self.data)
        bad["gitOps"]["layerSentryConfiguresRepositories"] = True
        self.reject(bad)

    def test_immutable_chart_must_match_declared_repository_and_digest(self):
        bad = copy.deepcopy(self.data)
        version = bad["entries"][0]["supportedVersions"][0]
        version["chart"]["immutableRef"] = "oci://example.invalid/chart@" + version["chart"]["manifestDigest"]
        self.reject(bad)

    def test_installed_state_helm_identity_must_match_install(self):
        bad = copy.deepcopy(self.data)
        bad["entries"][0]["installedStateDetector"]["helmRelease"]["name"] = "other-release"
        self.reject(bad)

    def test_cluster_scoped_conflict_policy_is_typed(self):
        bad = copy.deepcopy(self.data)
        conflict = next(c for c in bad["entries"][0]["conflicts"] if c["kind"] == "cluster-scoped-api")
        conflict["policy"] = "ignore-existing-crds"
        self.reject(bad)

    def test_every_installed_crd_must_participate_in_cluster_scoped_conflict_inventory(self):
        bad = copy.deepcopy(self.data)
        entry = bad["entries"][0]
        conflict = next(c for c in entry["conflicts"] if c["kind"] == "cluster-scoped-api")
        conflict["resources"].remove(entry["installedStateDetector"]["crds"][0])
        self.reject(bad)

    def test_upstream_release_identity_must_match_supported_version(self):
        bad = copy.deepcopy(self.data)
        bad["entries"][0]["supportedVersions"][0]["upstreamRelease"]["tag"] = "v1.20.3"
        self.reject(bad)

    def test_airgap_chart_must_match_a_qualified_version(self):
        bad = copy.deepcopy(self.data)
        bad["entries"][0]["airGapArtifacts"]["chart"]["immutableRef"] = "oci://quay.io/example/other@sha256:" + "0" * 64
        self.reject(bad)

    def test_official_sources_must_be_https(self):
        bad = copy.deepcopy(self.data)
        bad["entries"][0]["officialSources"] = ["http://example.invalid/docs"]
        self.reject(bad)


if __name__ == "__main__":
    unittest.main()
