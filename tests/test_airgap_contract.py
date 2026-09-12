import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class AirGapAndConflictContractTests(unittest.TestCase):
    def setUp(self):
        data = json.loads((ROOT / "catalog" / "v1" / "catalog.json").read_text())
        self.entry = next(entry for entry in data["entries"] if entry["id"] == "cert-manager")

    def test_every_airgap_image_has_unique_repository_override_bound_to_digest(self):
        values = self.entry["install"]["values"]
        images = self.entry["airGapArtifacts"]["images"]
        keys = []
        for image in images:
            key = image["helmRepositoryValue"]
            self.assertTrue(key.endswith(".repository"))
            digest_key = key[: -len(".repository")] + ".digest"
            self.assertEqual(values[digest_key], image["digest"])
            keys.append(key)
        self.assertEqual(len(keys), 5)
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(
            set(keys),
            {
                "image.repository",
                "webhook.image.repository",
                "cainjector.image.repository",
                "acmesolver.image.repository",
                "startupapicheck.image.repository",
            },
        )

    def test_cluster_scoped_conflicts_cover_crds_and_cert_manager_webhooks(self):
        detector_crds = set(self.entry["installedStateDetector"]["crds"])
        conflict = next(item for item in self.entry["conflicts"] if item["kind"] == "cluster-scoped-api")
        resources = set(conflict["resources"])
        self.assertTrue(detector_crds.issubset(resources))
        # MutatingWebhookConfiguration and ValidatingWebhookConfiguration both
        # use the Helm-generated name cert-manager-webhook. Server inventory is
        # cluster-scoped and evaluates every observed resource with that name.
        self.assertIn("cert-manager-webhook", resources)
        self.assertIn("webhook configurations", self.entry["securityProvenance"]["clusterScopedEffects"])


if __name__ == "__main__":
    unittest.main()
