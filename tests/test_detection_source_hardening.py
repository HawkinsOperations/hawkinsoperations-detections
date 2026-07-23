import copy
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


matrix = load_module(
    "verify_detection_promotion_matrix_hardening",
    ROOT / "scripts" / "verify_detection_promotion_matrix.py",
)
contract = load_module(
    "verify_detection_contract_hardening",
    ROOT / "scripts" / "verify_detection_contract.py",
)


class DetectionSourceHardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.root = self.base / "hawkinsoperations-detections"
        shutil.copytree(ROOT / "detections", self.root / "detections")
        self.matrix_path = self.root / "detections" / "DETECTION_PROMOTION_MATRIX.yml"

    def tearDown(self):
        self.tmp.cleanup()

    def load_matrix(self):
        return yaml.safe_load(self.matrix_path.read_text(encoding="utf-8"))

    def write_matrix(self, data):
        self.matrix_path.write_text(
            yaml.safe_dump(data, sort_keys=False), encoding="utf-8"
        )

    def entry(self, data, detection_id="HO-DET-013"):
        return next(
            item for item in data["entries"] if item["detection_id"] == detection_id
        )

    def verify(self):
        return matrix.verify_repo(self.root, print_summary=False)

    def test_duplicate_yaml_key_fails_closed(self):
        text = self.matrix_path.read_text(encoding="utf-8")
        self.matrix_path.write_text(
            text.replace(
                "owner_repo: hawkinsoperations-detections",
                "owner_repo: hawkinsoperations-detections\n"
                "owner_repo: attacker-owned",
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(matrix.MatrixError, "duplicate YAML key"):
            self.verify()

    def test_unknown_root_or_entry_shape_fails_closed(self):
        for target in ("root", "entry"):
            with self.subTest(target=target):
                data = self.load_matrix()
                if target == "root":
                    data["extension_authority"] = {"ai_disposition_authority": False}
                else:
                    self.entry(data)["extension_authority"] = {}
                self.write_matrix(data)
                with self.assertRaisesRegex(matrix.MatrixError, "unsupported fields"):
                    self.verify()
                shutil.copy2(
                    ROOT / "detections" / "DETECTION_PROMOTION_MATRIX.yml",
                    self.matrix_path,
                )

    def test_cross_platform_and_encoded_package_paths_fail_closed(self):
        attacks = (
            r"C:\private\package",
            r"\\server\share\package",
            "/var/private/package",
            r"detections\successor/ho-det-013",
            "../hawkinsoperations-validation",
            "%2e%2e%2fhawkinsoperations-validation",
            "%252e%252e%255chawkinsoperations-validation",
        )
        for attack in attacks:
            with self.subTest(attack=attack):
                data = self.load_matrix()
                self.entry(data)["package_path"] = attack
                self.write_matrix(data)
                with self.assertRaises(matrix.MatrixError):
                    self.verify()
                shutil.copy2(
                    ROOT / "detections" / "DETECTION_PROMOTION_MATRIX.yml",
                    self.matrix_path,
                )

    def test_cross_platform_and_encoded_required_paths_fail_closed(self):
        attacks = (
            r"C:\private\rule.yml",
            r"\\server\share\rule.yml",
            "/tmp/rule.yml",
            r"nested\..\rule.yml",
            "%2e%2e%2frule.yml",
            "%252e%252e%255crule.yml",
        )
        for attack in attacks:
            with self.subTest(attack=attack):
                data = self.load_matrix()
                self.entry(data)["required_files"].append(attack)
                self.write_matrix(data)
                with self.assertRaises(matrix.MatrixError):
                    self.verify()
                shutil.copy2(
                    ROOT / "detections" / "DETECTION_PROMOTION_MATRIX.yml",
                    self.matrix_path,
                )

    def test_case_folded_id_alias_fails_closed(self):
        data = self.load_matrix()
        self.entry(data)["detection_id"] = "ho-det-013"
        self.write_matrix(data)
        with self.assertRaisesRegex(matrix.MatrixError, "canonical uppercase"):
            self.verify()

    def test_nested_authority_laundering_in_package_fails_closed(self):
        rule_path = (
            self.root / "detections" / "successor" / "ho-det-013" / "rule.yml"
        )
        rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
        rule["extensions"] = {
            "review": [{"nested": {"ai_disposition_authority": True}}]
        }
        rule_path.write_text(yaml.safe_dump(rule, sort_keys=False), encoding="utf-8")
        with self.assertRaisesRegex(matrix.MatrixError, "authority promotion"):
            self.verify()

    def test_duplicate_package_metadata_key_fails_closed(self):
        rule_path = (
            self.root / "detections" / "successor" / "ho-det-013" / "rule.yml"
        )
        rule_path.write_text(
            rule_path.read_text(encoding="utf-8")
            + "\ndetection_id: AWS-DET-001\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(matrix.MatrixError, "duplicate YAML key"):
            self.verify()

    def test_declared_backend_must_have_owned_source_file(self):
        rule_path = (
            self.root / "detections" / "successor" / "ho-det-013" / "rule.yml"
        )
        rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
        rule["backend_target"] = "cloudtrail_json_fixture"
        rule_path.write_text(yaml.safe_dump(rule, sort_keys=False), encoding="utf-8")
        with self.assertRaisesRegex(matrix.MatrixError, "requires cloudtrail.jsonpath"):
            self.verify()

    def test_canonical_backend_path_spoof_fails_closed(self):
        status_path = (
            self.root / "detections" / "successor" / "ho-det-013" / "status.yml"
        )
        status = yaml.safe_load(status_path.read_text(encoding="utf-8"))
        status["canonical_splunk_source"] = (
            "detections/successor/ho-det-012/splunk.spl"
        )
        status_path.write_text(
            yaml.safe_dump(status, sort_keys=False), encoding="utf-8"
        )
        with self.assertRaisesRegex(matrix.MatrixError, "must reference"):
            self.verify()

    def test_orphan_source_file_fails_closed(self):
        orphan = (
            self.root / "detections" / "successor" / "ho-det-013" / "wazuh.xml"
        )
        orphan.write_text("<group></group>\n", encoding="utf-8")
        with self.assertRaisesRegex(matrix.MatrixError, "omitted from required_files"):
            self.verify()

    def test_unknown_validation_owner_and_status_fail_closed(self):
        for field, value in (
            ("validation_expected_owner", "attacker-validation"),
            ("validation_status_if_known", "VALIDATED_BY_ASSERTION"),
        ):
            with self.subTest(field=field):
                data = self.load_matrix()
                self.entry(data)[field] = value
                self.write_matrix(data)
                with self.assertRaises(matrix.MatrixError):
                    self.verify()
                shutil.copy2(
                    ROOT / "detections" / "DETECTION_PROMOTION_MATRIX.yml",
                    self.matrix_path,
                )

    def make_validation_registry(self, entries):
        validation_root = self.base / "hawkinsoperations-validation"
        packages = []
        for entry in entries:
            status = entry["validation_status_if_known"]
            if status == "VALIDATION_PLANNED":
                continue
            detection_id = entry["detection_id"]
            slug = detection_id.casefold()
            package_dir = validation_root / "validation" / "packages" / slug
            report_dir = validation_root / "reports" / slug
            script_dir = validation_root / "scripts"
            package_dir.mkdir(parents=True, exist_ok=True)
            report_dir.mkdir(parents=True, exist_ok=True)
            script_dir.mkdir(parents=True, exist_ok=True)
            fixture = package_dir / "validation-cases.json"
            report_json = report_dir / "validation-result.json"
            report_md = report_dir / "validation-result.md"
            validator = script_dir / f"validate-{slug}.py"
            fixture.write_text("{}\n", encoding="utf-8")
            report_json.write_text("{}\n", encoding="utf-8")
            report_md.write_text("# result\n", encoding="utf-8")
            validator.write_text("# validator\n", encoding="utf-8")
            local = matrix.is_local_path(entry["package_path"])
            packages.append(
                {
                    "detection_id": detection_id,
                    "validation_kind": (
                        "visibility_contract"
                        if status
                        == "VALIDATION_CONTRACT_ENFORCED_IN_VALIDATION_REPO"
                        and detection_id == "HO-NDR-001"
                        else "controlled_validation"
                        if detection_id != "HOD-001"
                        else "baseline_contract"
                    ),
                    "validation_package_path": package_dir.relative_to(
                        validation_root
                    ).as_posix(),
                    "fixture_file": fixture.relative_to(validation_root).as_posix(),
                    "report_json": report_json.relative_to(
                        validation_root
                    ).as_posix(),
                    "report_markdown": report_md.relative_to(
                        validation_root
                    ).as_posix(),
                    "validator_script": validator.relative_to(
                        validation_root
                    ).as_posix(),
                    "public_safe_status": "NOT_PUBLIC_SAFE",
                    "runtime_status": False,
                    "signal_status": False,
                    "source_dependency_required": local and detection_id != "HOD-001",
                    "source_reference": (
                        f"hawkinsoperations-detections/{entry['package_path']}"
                        if local and detection_id != "HOD-001"
                        else None
                    ),
                }
            )
        registry = {
            "owner_repo": "hawkinsoperations-validation",
            "truth_surface": "controlled_validation",
            "human_review_required": True,
            "ai_disposition_authority": False,
            "source_authority_manifest": "validation/SOURCE_AUTHORITY_MANIFEST.json",
            "packages": packages,
        }
        source_packages = []
        for entry in entries:
            detection_id = entry["detection_id"]
            if (
                not matrix.is_local_path(entry["package_path"])
                or detection_id == "HOD-001"
            ):
                continue
            files = []
            for relative_name in entry["required_files"]:
                relative_path = f"{entry['package_path']}/{relative_name}"
                source_path = self.root / Path(*relative_path.split("/"))
                files.append(
                    {
                        "path": relative_path,
                        "git_blob_sha": matrix.git_blob_sha(
                            self.root, source_path, at_head=True
                        ),
                        "semantic_fingerprint": matrix.semantic_file_fingerprint(
                            source_path
                        ),
                        "semantic_fingerprint_method": (
                            matrix.semantic_fingerprint_method(source_path)
                        ),
                    }
                )
            source_packages.append(
                {
                    "detection_id": detection_id,
                    "package_path": entry["package_path"],
                    "required_files": sorted(
                        files, key=lambda item: item["path"].casefold()
                    ),
                }
            )
        matrix_path = (
            self.root / "detections" / "DETECTION_PROMOTION_MATRIX.yml"
        )
        manifest = {
            "schema_version": 1,
            "owner_repo": "hawkinsoperations-validation",
            "source_owner": "hawkinsoperations-detections",
            "truth_surface": "detection_to_validation_content_handoff",
            "matrix_path": "detections/DETECTION_PROMOTION_MATRIX.yml",
            "matrix_git_blob_sha": matrix.git_blob_sha(
                self.root, matrix_path, at_head=True
            ),
            "matrix_semantic_fingerprint": matrix.semantic_file_fingerprint(
                matrix_path
            ),
            "matrix_semantic_fingerprint_method": (
                matrix.semantic_fingerprint_method(matrix_path)
            ),
            "packages": sorted(
                source_packages, key=lambda item: item["detection_id"]
            ),
        }
        manifest_path = validation_root / "validation" / "SOURCE_AUTHORITY_MANIFEST.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        registry_path = validation_root / "validation" / "VALIDATION_REGISTRY.yml"
        registry_path.parent.mkdir(parents=True, exist_ok=True)
        registry_path.write_text(
            yaml.safe_dump(registry, sort_keys=False), encoding="utf-8"
        )
        return registry_path

    def make_proof_index(self, matrix_data):
        proof_root = self.base / "hawkinsoperations-proof"
        proof_entries = []
        proof_ids = set(
            matrix_data["detection_side_ledger_eligibility"]["proof_recorded"]
        )
        legacy_record = (
            proof_root
            / "proof"
            / "records"
            / "PROOF-HOD-001-2026-04-21-001.json"
        )
        legacy_record.parent.mkdir(parents=True, exist_ok=True)
        legacy_record.write_text(
            json.dumps(
                {
                    "proof_id": "PROOF-HOD-001-2026-04-21-001",
                    "created_at": "2026-04-21T11:10:31-05:00",
                    "detection": {"id": "HOD-001"},
                    "claim_boundary": "Historical baseline record only; not runtime or public proof.",
                }
            ),
            encoding="utf-8",
        )
        for detection_id in sorted(proof_ids):
            if detection_id == "HOD-001":
                continue
            record = proof_root / "proof" / "records" / f"{detection_id}.md"
            card = proof_root / "proof" / "cards" / f"{detection_id}.md"
            record.parent.mkdir(parents=True, exist_ok=True)
            card.parent.mkdir(parents=True, exist_ok=True)
            record.write_text(f"# {detection_id}\n", encoding="utf-8")
            card.write_text(f"# {detection_id}\n", encoding="utf-8")
            proof_entries.append(
                {
                    "detection_id": detection_id,
                    "source_truth_owner": "hawkinsoperations-detections",
                    "proof_record_path": record.relative_to(proof_root).as_posix(),
                    "proof_card_path": card.relative_to(proof_root).as_posix(),
                    "public_safe_status": "NOT_PUBLIC_SAFE",
                }
            )
        index = {
            "owner_repo": "hawkinsoperations-proof",
            "truth_surface": "proof_boundary_index",
            "entries": proof_entries,
        }
        index_path = (
            proof_root / "proof" / "indexes" / "DETECTION_PROOF_STATUS_INDEX.yml"
        )
        index_path.parent.mkdir(parents=True, exist_ok=True)
        index_path.write_text(
            yaml.safe_dump(index, sort_keys=False), encoding="utf-8"
        )
        return index_path

    def test_explicit_validation_and_proof_handoffs_pass(self):
        entries = self.verify()
        data = self.load_matrix()
        registry_path = self.make_validation_registry(entries)
        proof_path = self.make_proof_index(data)
        verified = matrix.verify_repo(
            self.root,
            print_summary=False,
            validation_registry_path=registry_path,
            proof_index_path=proof_path,
            require_sibling_handoffs=True,
        )
        self.assertEqual(len(verified), len(entries))

    def test_validation_handoff_path_forgery_fails_closed(self):
        entries = self.verify()
        registry_path = self.make_validation_registry(entries)
        proof_path = self.make_proof_index(self.load_matrix())
        registry = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
        package = next(
            item
            for item in registry["packages"]
            if item["detection_id"] == "HO-DET-013"
        )
        package["source_reference"] = (
            "hawkinsoperations-detections/detections/successor/ho-det-012"
        )
        registry_path.write_text(
            yaml.safe_dump(registry, sort_keys=False), encoding="utf-8"
        )
        with self.assertRaisesRegex(matrix.MatrixError, "source_reference mismatch"):
            matrix.verify_repo(
                self.root,
                print_summary=False,
                validation_registry_path=registry_path,
                proof_index_path=proof_path,
                require_sibling_handoffs=True,
            )

    def test_validation_content_manifest_forgery_fails_closed(self):
        entries = self.verify()
        registry_path = self.make_validation_registry(entries)
        proof_path = self.make_proof_index(self.load_matrix())
        manifest_path = (
            registry_path.parent / "SOURCE_AUTHORITY_MANIFEST.json"
        )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["packages"][0]["required_files"][0]["git_blob_sha"] = "0" * 40
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            matrix.MatrixError, "file identities are stale"
        ):
            matrix.verify_repo(
                self.root,
                print_summary=False,
                validation_registry_path=registry_path,
                proof_index_path=proof_path,
                require_sibling_handoffs=True,
            )

    def test_proof_handoff_owner_spoof_fails_closed(self):
        entries = self.verify()
        registry_path = self.make_validation_registry(entries)
        proof_path = self.make_proof_index(self.load_matrix())
        proof = yaml.safe_load(proof_path.read_text(encoding="utf-8"))
        proof["entries"][0]["source_truth_owner"] = "hawkinsoperations-detections-copy"
        proof_path.write_text(
            yaml.safe_dump(proof, sort_keys=False), encoding="utf-8"
        )
        with self.assertRaisesRegex(matrix.MatrixError, "spoofed source owner"):
            matrix.verify_repo(
                self.root,
                print_summary=False,
                validation_registry_path=registry_path,
                proof_index_path=proof_path,
                require_sibling_handoffs=True,
            )

    def test_duplicate_json_key_fails_closed(self):
        target = self.base / "duplicate.json"
        target.write_text('{"id":"A","id":"B"}\n', encoding="utf-8")
        original_root = contract.ROOT
        try:
            contract.ROOT = self.base
            with self.assertRaises(SystemExit):
                contract.parse_json(target)
        finally:
            contract.ROOT = original_root


if __name__ == "__main__":
    unittest.main()
