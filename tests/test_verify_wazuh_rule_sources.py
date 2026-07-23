import copy
import importlib.util
import os
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

    def test_top_level_exact_duplicate_yaml_key_fails(self):
        original = self.registry_path.read_text(encoding="utf-8")
        duplicated = original.replace(
            "registry_status: WAZUH_RULE_SOURCE_CONTRACT_ENFORCED\n",
            "registry_status: WAZUH_RULE_SOURCE_CONTRACT_ENFORCED\n"
            "registry_status: WAZUH_RULE_SOURCE_CONTRACT_ENFORCED\n",
            1,
        )
        self.registry_path.write_text(duplicated, encoding="utf-8")

        with self.assertRaisesRegex(module.WazuhRuleSourceError, "duplicate YAML key"):
            module.verify_repo(self.root, print_summary=False)

    def test_nested_nfkc_casefold_duplicate_yaml_key_fails(self):
        original = self.registry_path.read_text(encoding="utf-8")
        duplicated = original.replace(
            "  - detection_id: HO-DET-001\n",
            "  - detection_id: HO-DET-001\n"
            "    ＤＥＴＥＣＴＩＯＮ＿ＩＤ: HO-DET-999\n",
            1,
        )
        self.registry_path.write_text(duplicated, encoding="utf-8")

        with self.assertRaisesRegex(
            module.WazuhRuleSourceError,
            "duplicate YAML key after NFKC/casefold normalization",
        ):
            module.verify_repo(self.root, print_summary=False)

    def test_unhashable_yaml_mapping_key_fails_closed(self):
        original = self.registry_path.read_text(encoding="utf-8")
        self.registry_path.write_text(
            "? [malformed, key]\n: rejected\n" + original,
            encoding="utf-8",
        )

        with self.assertRaisesRegex(module.WazuhRuleSourceError, "unhashable YAML mapping key"):
            module.verify_repo(self.root, print_summary=False)

    def test_non_mapping_registry_root_fails_closed(self):
        self.registry_path.write_text("- malformed\n- registry\n", encoding="utf-8")

        with self.assertRaisesRegex(
            module.WazuhRuleSourceError,
            "registry root must be a mapping",
        ):
            module.verify_repo(self.root, print_summary=False)

    def test_unknown_root_entry_and_dashboard_keys_fail_closed(self):
        original = self.load_registry()
        cases = (
            ("root", lambda data: data.__setitem__("extension", "unknown")),
            (
                "entry",
                lambda data: data["entries"][0].__setitem__("extension", "unknown"),
            ),
            (
                "dashboard",
                lambda data: data["dashboard_private_runtime_needs"][0].__setitem__(
                    "extension",
                    "unknown",
                ),
            ),
        )
        for label, mutate in cases:
            with self.subTest(label=label):
                data = copy.deepcopy(original)
                mutate(data)
                self.write_registry(data)
                with self.assertRaisesRegex(module.WazuhRuleSourceError, "unknown keys"):
                    module.verify_repo(self.root, print_summary=False)

    def test_nested_public_safe_and_ai_authority_promotions_fail_closed(self):
        original = self.load_registry()
        cases = (
            (
                "public_safe",
                {"extension": {"public_safe_status": "PUBLIC_SAFE"}},
                "authority promotion",
            ),
            (
                "ai_authority",
                {"metadata": {"ai_disposition_authority": True}},
                "authority promotion",
            ),
        )
        for label, payload, expected in cases:
            with self.subTest(label=label):
                data = copy.deepcopy(original)
                data["entries"][0].update(payload)
                self.write_registry(data)
                with self.assertRaisesRegex(module.WazuhRuleSourceError, expected):
                    module.verify_repo(self.root, print_summary=False)

    def test_registry_fields_require_exact_types(self):
        original = self.load_registry()
        cases = (
            (
                "boolean_as_integer",
                lambda data: data.__setitem__("schema_version", True),
                "schema_version must be int",
            ),
            (
                "string_rule_id",
                lambda data: data["entries"][1].__setitem__(
                    "expected_rule_ids",
                    ["910011"],
                ),
                "expected_rule_ids entries must be integers",
            ),
            (
                "string_runtime_status",
                lambda data: data["entries"][0].__setitem__(
                    "runtime_status",
                    "false",
                ),
                "runtime_status must be bool",
            ),
        )
        for label, mutate, expected in cases:
            with self.subTest(label=label):
                data = copy.deepcopy(original)
                mutate(data)
                self.write_registry(data)
                with self.assertRaisesRegex(module.WazuhRuleSourceError, expected):
                    module.verify_repo(self.root, print_summary=False)

    def test_detection_package_rejects_arbitrary_existing_file(self):
        data = self.load_registry()
        (self.root / "README.md").write_text("not a detection package\n", encoding="utf-8")
        data["entries"][0]["detection_package"] = "README.md"
        self.write_registry(data)
        with self.assertRaisesRegex(module.WazuhRuleSourceError, "canonical path"):
            module.verify_repo(self.root, print_summary=False)

    def test_detection_package_rejects_case_alias(self):
        data = self.load_registry()
        data["entries"][0]["detection_package"] = (
            "detections/successor/HO-DET-001"
        )
        self.write_registry(data)
        with self.assertRaisesRegex(module.WazuhRuleSourceError, "canonical path"):
            module.verify_repo(self.root, print_summary=False)

    def test_detection_package_rejects_symlink_escape_where_supported(self):
        data = self.load_registry()
        package = self.root / "detections" / "successor" / "ho-det-001"
        outside = self.root / "outside-package"
        shutil.copytree(package, outside)
        shutil.rmtree(package)
        try:
            os.symlink(outside, package, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"directory symlink unavailable: {exc}")
        self.write_registry(data)
        with self.assertRaisesRegex(
            module.WazuhRuleSourceError,
            "symlink or junction|escapes canonical package root",
        ):
            module.verify_repo(self.root, print_summary=False)

    def test_detection_package_metadata_id_must_match_registry(self):
        data = self.load_registry()
        status_path = (
            self.root
            / "detections"
            / "successor"
            / "ho-det-001"
            / "status.yml"
        )
        status = yaml.safe_load(status_path.read_text(encoding="utf-8"))
        status["detection_id"] = "HO-DET-999"
        status_path.write_text(
            yaml.safe_dump(status, sort_keys=False),
            encoding="utf-8",
        )
        self.write_registry(data)
        with self.assertRaisesRegex(module.WazuhRuleSourceError, "detection_id mismatch"):
            module.verify_repo(self.root, print_summary=False)

    def test_source_lane_rejects_rogue_copied_xml_path(self):
        data = self.load_registry()
        source_entry = next(
            item
            for item in data["entries"]
            if item["mapping_lane"] == "wazuh_rule_source"
        )
        source_xml = self.root / source_entry["wazuh_rule_path"]
        rogue_xml = self.root / "detections" / "wazuh" / "rogue.xml"
        shutil.copyfile(source_xml, rogue_xml)
        source_entry["wazuh_rule_path"] = "detections/wazuh/rogue.xml"
        self.write_registry(data)

        with self.assertRaisesRegex(
            module.WazuhRuleSourceError,
            "canonical package XML",
        ):
            module.verify_repo(self.root, print_summary=False)

    def test_source_lane_rejects_unexpected_extra_rule_id(self):
        data = self.load_registry()
        source_entry = next(
            item for item in data["entries"] if item["detection_id"] == "HO-DET-012"
        )
        xml_path = self.root / source_entry["wazuh_rule_path"]
        xml_path.write_text(
            xml_path.read_text(encoding="utf-8").replace(
                "\n</group>\n",
                '\n  <rule id="999999" level="5"><description>unowned extra</description><group>ho-det-012,</group></rule>\n</group>\n',
                1,
            ),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(module.WazuhRuleSourceError, "unexpected Wazuh rule ids"):
            module.verify_repo(self.root, print_summary=False)

    def test_expected_inventory_lists_reject_duplicates_and_aliases(self):
        original = self.load_registry()
        cases = (
            (
                "duplicate_rule_id",
                lambda entry: entry["expected_rule_ids"].append(
                    entry["expected_rule_ids"][0]
                ),
                "expected_rule_ids contains duplicate values",
            ),
            (
                "case_alias_group",
                lambda entry: entry["expected_groups"].append(
                    entry["expected_groups"][0].upper()
                ),
                "expected_groups contains duplicate normalized value",
            ),
        )
        for label, mutate, expected in cases:
            with self.subTest(label=label):
                data = copy.deepcopy(original)
                source_entry = next(
                    item
                    for item in data["entries"]
                    if item["mapping_lane"] == "wazuh_rule_source"
                )
                mutate(source_entry)
                self.write_registry(data)
                with self.assertRaisesRegex(module.WazuhRuleSourceError, expected):
                    module.verify_repo(self.root, print_summary=False)

    def test_unsupported_status_runtime_and_dashboard_authority_fail(self):
        original = self.load_registry()
        cases = (
            (
                "entry_status",
                lambda data: data["entries"][0].__setitem__(
                    "status",
                    "UNSUPPORTED",
                ),
                "invalid status",
            ),
            (
                "preferred_runtime",
                lambda data: data["entries"][0].__setitem__(
                    "preferred_runtime",
                    "unowned_runtime",
                ),
                "invalid preferred_runtime",
            ),
            (
                "dashboard_status",
                lambda data: data["dashboard_private_runtime_needs"][0].__setitem__(
                    "status",
                    "APPROVED",
                ),
                "invalid dashboard status",
            ),
            (
                "authority_anchor",
                lambda data: data["dashboard_private_runtime_needs"][0].__setitem__(
                    "authority_anchor",
                    "unowned authority",
                ),
                "invalid authority_anchor",
            ),
        )
        for label, mutate, expected in cases:
            with self.subTest(label=label):
                data = copy.deepcopy(original)
                mutate(data)
                self.write_registry(data)
                with self.assertRaisesRegex(module.WazuhRuleSourceError, expected):
                    module.verify_repo(self.root, print_summary=False)

    def test_dashboard_need_ids_reject_normalized_aliases(self):
        data = self.load_registry()
        duplicate = copy.deepcopy(data["dashboard_private_runtime_needs"][0])
        duplicate["need_id"] = duplicate["need_id"].lower()
        data["dashboard_private_runtime_needs"].append(duplicate)
        self.write_registry(data)

        with self.assertRaisesRegex(
            module.WazuhRuleSourceError,
            "not canonical|duplicate dashboard need_id",
        ):
            module.verify_repo(self.root, print_summary=False)

    def test_same_file_duplicate_wazuh_rule_id_fails(self):
        data = self.load_registry()
        source_entry = next(item for item in data["entries"] if item["detection_id"] == "HO-DET-012")
        xml_path = self.root / source_entry["wazuh_rule_path"]
        xml_path.write_text(
            xml_path.read_text(encoding="utf-8").replace(
                "\n</group>\n",
                '\n  <rule id="910021" level="5"><description>same file duplicate</description><group>ho-det-012,</group></rule>\n</group>\n',
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(module.WazuhRuleSourceError, "duplicate Wazuh rule id"):
            module.verify_repo(self.root, print_summary=False)

    def test_cross_detection_duplicate_wazuh_rule_id_fails(self):
        data = self.load_registry()
        duplicate = copy.deepcopy(next(item for item in data["entries"] if item["detection_id"] == "HO-DET-012"))
        duplicate["detection_id"] = "HO-DET-999"
        duplicate["detection_package"] = "detections/successor/ho-det-999"
        package = self.root / "detections" / "successor" / "ho-det-999"
        shutil.copytree(
            self.root / "detections" / "successor" / "ho-det-012",
            package,
        )
        for filename in module.PACKAGE_METADATA_FILES:
            metadata_path = package / filename
            metadata = yaml.safe_load(metadata_path.read_text(encoding="utf-8"))
            metadata["detection_id"] = "HO-DET-999"
            metadata_path.write_text(
                yaml.safe_dump(metadata, sort_keys=False),
                encoding="utf-8",
            )
        duplicate["wazuh_rule_path"] = "detections/successor/ho-det-999/wazuh.xml"
        duplicate["expected_rule_ids"] = [910021]
        duplicate["expected_groups"] = ["ho-det-999"]
        duplicate["expected_mitre_ids"] = []
        (package / "wazuh.xml").write_text(
            '<group name="ho-det-999,"><rule id="910021" level="5"><description>duplicate</description><group>ho-det-999,</group></rule></group>',
            encoding="utf-8",
        )
        data["entries"].append(duplicate)
        self.write_registry(data)
        with self.assertRaisesRegex(module.WazuhRuleSourceError, "duplicate Wazuh rule id"):
            module.verify_repo(self.root, print_summary=False)

    def test_missing_detection_package_fails(self):
        data = self.load_registry()
        shutil.rmtree(
            self.root / "detections" / "successor" / "ho-det-001",
        )
        self.write_registry(data)
        with self.assertRaisesRegex(module.WazuhRuleSourceError, "cannot be resolved"):
            module.verify_repo(self.root, print_summary=False)

    def test_runtime_signal_or_public_safe_promotion_fails(self):
        original = self.load_registry()
        cases = (
            ("runtime_status", "RUNTIME_ACTIVE", "runtime_status"),
            ("signal_status", "SIGNAL_OBSERVED_PRIVATE", "signal_status"),
            ("public_safe_status", "PUBLIC_SAFE", "public_safe_status"),
        )
        for field, value, expected_error in cases:
            with self.subTest(field=field):
                data = copy.deepcopy(original)
                data["entries"][0][field] = value
                self.write_registry(data)
                with self.assertRaisesRegex(module.WazuhRuleSourceError, expected_error):
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
