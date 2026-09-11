import json
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class RuntimeContractTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / "catalog" / "v1" / "catalog.json").read_text())
        self.entry = self.data["entries"][0]

    def test_airgap_chart_package_digest_is_pinned(self):
        chart = self.entry["airGapArtifacts"]["chart"]
        self.assertRegex(chart["packageDigest"], DIGEST)
        self.assertTrue(chart["verifyBeforeMirror"])

    def test_helm_floor_supports_retry_strategy(self):
        helm = next(item for item in self.entry["prerequisites"] if item["kind"] == "helm")
        self.assertEqual(helm["constraint"], ">=3.14.0")
        self.assertEqual(self.entry["upgradeRules"]["strategy"], "helm-upgrade-reset-then-reuse-values")


if __name__ == "__main__":
    unittest.main()
