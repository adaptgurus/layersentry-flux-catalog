import copy
import importlib.util
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("validator", ROOT / "scripts" / "validate_catalog.py")
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)

class CatalogValidationTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / "catalog" / "v1" / "catalog.json").read_text())

    def test_current_catalog_validates(self):
        validator.validate(self.data)

    def test_gitops_choice_is_exact(self):
        bad = copy.deepcopy(self.data)
        bad["gitOps"]["choices"].append("fleet")
        with self.assertRaises(validator.CatalogError):
            validator.validate(bad)

    def test_missing_installed_detector_is_rejected(self):
        bad = copy.deepcopy(self.data)
        del bad["entries"][0]["installedStateDetector"]
        with self.assertRaises(validator.CatalogError):
            validator.validate(bad)

    def test_unverified_entry_cannot_be_production_selectable(self):
        bad = copy.deepcopy(self.data)
        bad["entries"][0]["productionSelectable"] = True
        with self.assertRaises(validator.CatalogError):
            validator.validate(bad)

    def test_chart_must_be_immutable(self):
        bad = copy.deepcopy(self.data)
        bad["entries"][0]["supportedVersions"][0]["chart"]["immutableRef"] = "oci://quay.io/jetstack/charts/cert-manager:v1.21.1"
        with self.assertRaises(validator.CatalogError):
            validator.validate(bad)

    def test_customer_setup_is_not_ready(self):
        bad = copy.deepcopy(self.data)
        bad["entries"][0]["customerConfiguration"]["postInstallState"] = "READY"
        with self.assertRaises(validator.CatalogError):
            validator.validate(bad)

    def test_missing_cni_compatibility_is_rejected(self):
        bad = copy.deepcopy(self.data)
        del bad["entries"][0]["supportedVersions"][0]["cni"]
        with self.assertRaises(validator.CatalogError):
            validator.validate(bad)

    def test_missing_csi_context_is_rejected(self):
        bad = copy.deepcopy(self.data)
        del bad["entries"][0]["supportedVersions"][0]["csi"]
        with self.assertRaises(validator.CatalogError):
            validator.validate(bad)

    def test_safe_uninstall_requires_customer_resource_queries(self):
        bad = copy.deepcopy(self.data)
        del bad["entries"][0]["installedStateDetector"]["customerResourceQueries"]
        with self.assertRaises(validator.CatalogError):
            validator.validate(bad)

if __name__ == "__main__":
    unittest.main()
