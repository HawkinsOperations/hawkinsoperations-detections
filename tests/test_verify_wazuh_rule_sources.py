import copy
import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "verify_wazuh_rule_sources.py"
SPEC = importlib.util.spec_from_file_location("verify_wazuh_rule_sources", MODULE_PATH)
module = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(module)


class VerifyWazuhRuleSourcesTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        shutil.copytree(ROOT / "detections", self.root / "detections")

    def tearDown(self):
        self.tmpdir.cleanup()

    @property
    def registry_path(self):
        return self.root / "detections" / "wazuh" / "WAZUH_RULE_SOURCE_REGISTRY.yml"

    def load_registry(self):
        return yaml.safe_load(self.registry_path.read_text(encoding="utf-8"))

    def write_registry(self, data):
        self.registry_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")

    def test_valid_repository_registry_passes(self):
        entries = module.verify_repo(self.root, print_summary=False)
        ids = {entry["detection_id"] for entry in entries}
        self.assertIn("HO-DET-011", ids)
        self.assertIn("HO-DET-012", ids)

    def test_duplicate_wazuh_rule_id_fails(self):
        data = self.load_registry()
        duplicate = copy.deepcopy(next(item for item in data["entries"] if item["detection_id"] == "HO-DET-012"))
        duplicate["detection_id"] = "EX-DET-999"
        duplicate["detection_package"] = "detections/successor/ex-det-999"
        (self.root / "detections" / "successor" / "ex-det-999").mkdir(parents=True)
        duplicate["wazuh_rule_path"] = "detections/successor/ex-det-999/wazuh.xml"
        duplicate["expected_rule_ids"] = [910021]
        duplicate["expected_groups"] = ["ex-det-999"]
        duplicate["expected_mitre_ids"] = []
        (self.root / "detections" / "successor" / "ex-det-999" / "wazuh.xml").write_text(
            '<group name="ex-det-999,"><rule id="910021" level="5"><description>duplicate</description><group>ex-det-999,</group></rule></group>',
            encoding="utf-8",
        )
        data["entries"].append(duplicate)
        self.write_registry(data)
        with self.assertRaisesRegex(module.WazuhRuleSourceError, "duplicate Wazuh rule id"):
            module.verify_repo(self.root, print_summary=False)

    def test_missing_detection_package_fails(self):
        data = self.load_registry()
        data["entries"][0]["detection_package"] = "detections/successor/missing-det"
        self.write_registry(data)
        with self.assertRaisesRegex(module.WazuhRuleSourceError, "missing detection_package"):
            module.verify_repo(self.root, print_summary=False)

    def test_truthy_runtime_or_public_proof_claim_fails(self):
        data = self.load_registry()
        data["entries"][0]["runtime_status"] = "RUNTIME_ACTIVE"
        self.write_registry(data)
        with self.assertRaisesRegex(module.WazuhRuleSourceError, "runtime_status"):
            module.verify_repo(self.root, print_summary=False)

    def test_identity_detection_forced_to_wazuh_fails(self):
        data = self.load_registry()
        data["entries"].append(
            {
                "detection_id": "ID-DET-001",
                "mapping_lane": "wazuh_rule_source",
                "status": "SOURCE_EXISTS",
                "detection_package": "detections/identity/id-det-001",
                "wazuh_rule_path": None,
                "expected_rule_ids": [],
                "expected_groups": [],
                "expected_mitre_ids": [],
                "preferred_runtime": "wazuh",
                "runtime_status": False,
                "signal_status": False,
                "public_safe_status": "NOT_PUBLIC_SAFE",
                "notes": "bad forced identity mapping",
            }
        )
        self.write_registry(data)
        with self.assertRaisesRegex(module.WazuhRuleSourceError, "identity detections"):
            module.verify_repo(self.root, print_summary=False)


if __name__ == "__main__":
    unittest.main()
