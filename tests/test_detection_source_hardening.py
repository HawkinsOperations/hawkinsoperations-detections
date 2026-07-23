import copy
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata
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


def run_workflow_vocabulary_guard(workflow_path: Path, files: dict[str, bytes]):
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    job = next(iter(workflow["jobs"].values()))
    step = next(
        item
        for item in job["steps"]
        if item.get("name") == "Reject retired fixture vocabulary"
    )
    source = step["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        subprocess.run(
            ["git", "init", "--quiet"],
            cwd=root,
            check=True,
            capture_output=True,
        )
        for relative, content in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        subprocess.run(
            ["git", "add", "--", *files],
            cwd=root,
            check=True,
            capture_output=True,
        )
        return subprocess.run(
            [sys.executable, "-c", source],
            cwd=root,
            capture_output=True,
            text=True,
        )


class DetectionSourceHardeningTests(unittest.TestCase):
    def test_required_ci_uses_exact_authority_shas_and_rejects_retired_vocabulary(
        self,
    ) -> None:
        workflow_path = ROOT / ".github/workflows/baseline-detection-contract.yml"
        workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
        job = workflow["jobs"]["baseline-hero-artifact-contract"]
        for env_name in ("VALIDATION_AUTHORITY_SHA", "PROOF_AUTHORITY_SHA"):
            self.assertRegex(job["env"][env_name], r"^[0-9a-f]{40}$")
        text = workflow_path.read_text(encoding="utf-8")
        action_refs = re.findall(r"^\s*uses:\s*[^@\s]+@([^\s#]+)", text, re.MULTILINE)
        self.assertTrue(action_refs)
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in action_refs))
        self.assertIn("PyYAML==6.0.2", text)
        self.assertIn('rev-parse HEAD)" = "$VALIDATION_AUTHORITY_SHA"', text)
        self.assertIn('rev-parse HEAD)" = "$PROOF_AUTHORITY_SHA"', text)
        self.assertIn('retired = "".join(("syn", "thetic"))', text)
        self.assertIn('unicodedata.normalize("NFKC"', text)
        self.assertIn('["git", "ls-files", "-z"]', text)
        self.assertIn('["git", "show", f":{relative}"]', text)
        self.assertIn("tracked non-binary content contains NUL", text)
        self.assertGreaterEqual(text.count("check=True"), 2)
        self.assertNotIn("git grep", text)
        self.assertNotIn("feature/hoxline-case-growth-convergence-v1", text)

    def test_required_vocabulary_guard_rejects_nfkc_utf16_and_git_errors(self) -> None:
        workflow_path = ROOT / ".github/workflows/baseline-detection-contract.yml"
        retired = "".join(("syn", "thetic"))
        fullwidth = "".join(chr(ord(character) + 0xFEE0) for character in retired)
        self.assertEqual(
            retired,
            unicodedata.normalize("NFKC", fullwidth).casefold(),
        )
        result = run_workflow_vocabulary_guard(
            workflow_path,
            {
                f"fixture-{fullwidth}.txt": b"controlled-test\n",
                "content-fixture.txt": f"{fullwidth}\n".encode(),
                "utf16-fixture.md": f"{retired}\n".encode("utf-16-le"),
            },
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("utf16-fixture.md", result.stderr + result.stdout)
        workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
        step = next(
            item
            for item in next(iter(workflow["jobs"].values()))["steps"]
            if item.get("name") == "Reject retired fixture vocabulary"
        )
        source = step["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        with tempfile.TemporaryDirectory() as temp:
            operational = subprocess.run(
                [sys.executable, "-c", source],
                cwd=temp,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(0, operational.returncode)

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

    def commit_repo(self, repo_root, message="fixture"):
        if not (repo_root / ".git").exists():
            subprocess.run(["git", "init"], cwd=repo_root, check=True, capture_output=True)
            subprocess.run(
                ["git", "config", "user.email", "controlled-fixture@example.invalid"],
                cwd=repo_root, check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Controlled Fixture"],
                cwd=repo_root, check=True,
            )
            subprocess.run(
                [
                    "git", "remote", "add", "origin",
                    f"https://github.com/HawkinsOperations/{repo_root.name}.git",
                ],
                cwd=repo_root, check=True,
            )
        subprocess.run(["git", "add", "."], cwd=repo_root, check=True)
        subprocess.run(
            ["git", "commit", "--allow-empty", "-m", message],
            cwd=repo_root, check=True, capture_output=True,
        )

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
        with self.assertRaisesRegex(
            matrix.MatrixError, "authority promotion|unsupported top-level fields"
        ):
            self.verify()

    def test_punctuation_and_whitespace_authority_aliases_fail_closed(self):
        attacks = (
            {"ai disposition authority": True},
            {"runtime.active": True},
            {"public safe status": "PUBLIC_SAFE"},
            {"metadata": {"production_active": True}},
            {"metadata": {"production_live": {"enabled": True}}},
            {"metadata": {"customer_deployment": True}},
            {"metadata": {"socaas_deployment": True}},
            {"metadata": {"runtime_status": "active"}},
            {"metadata": {"signal_status": "observed"}},
            {"metadata": {"approval_status": "approved"}},
            {"metadata": {"approval_state": True}},
            {"metadata": {"closure_status": "closed"}},
            {"metadata": {"case_status": "closed"}},
            {"metadata": {"case_state": True}},
            {"metadata": {"customer_state": True}},
            {"metadata": {"socaas_state": True}},
            {"metadata": {"production_state": True}},
            {"metadata": {"runtime_state": True}},
            {"metadata": {"public_safe_runtime": True}},
            {"metadata": {"final_authorized": True}},
            {"metadata": {"final_authority": True}},
            {"runtime": {"state": True}},
            {"signal": {"observed": True}},
            {"public": {"safe": True}},
            {"approval": {"status": True}},
            {"production": {"active": True}},
            {"customer": {"deployed": True}},
            {"socaas": {"deployed": True}},
            {"ai": {"authority": True}},
            {"analyst": {"approval": True}},
            {"review": {"disposition": "APPROVED"}},
            {"final": {"authorization": True}},
            {"case": {"closed": True}},
            {"extensions": [{"final": {"authorization": True}}]},
            {"runtime": {"metadata": {"state": True}}},
            {"final": {"review": {"authorization": True}}},
            {"ai": {"metadata": {"authority": True}}},
            {"customer": {"review": {"deployed": True}}},
            {"review": {"metadata": {"disposition": "APPROVED"}}},
            {"production_live": {"enabled": True}},
            {"ai_authority": {"enabled": True}},
            {"review_disposition": {"approved": True}},
            {"final_authorization": {"granted": True}},
            {"production_live": [True]},
            {"ai_authority": ["APPROVED"]},
            {"review_disposition": [True]},
            {"final_authorization": [1]},
            {"metadata": {"%70roduction_active": True}},
        )
        source_path = (
            ROOT / "detections" / "successor" / "ho-det-013" / "rule.yml"
        )
        for attack in attacks:
            with self.subTest(attack=attack):
                with self.assertRaises((matrix.MatrixError, SystemExit)):
                    matrix.scan_nested_authority(attack, "hostile")
                with self.assertRaises(SystemExit):
                    contract.verify_promotion_block(source_path, attack)

    def test_split_authority_paths_preserve_bounded_scalar_controls(self):
        source_path = ROOT / "detections/successor/ho-det-013/rule.yml"
        controls = (
            {"runtime": {"state": False}},
            {"signal": {"observed": False}},
            {"public": {"safe": "NOT_PUBLIC_SAFE"}},
            {"approval": {"status": "NOT_APPROVED"}},
            {"production": {"active": "BLOCKED"}},
            {"customer": {"deployed": False}},
            {"socaas": {"deployed": False}},
            {"ai": {"authority": False}},
            {"analyst": {"approval": "NOT_APPROVED"}},
            {"review": {"disposition": "NOT_APPROVED"}},
            {"final": {"authorization": "BLOCKED"}},
            {"case": {"closed": False}},
            {"extensions": [{"final": {"authorization": "BLOCKED"}}]},
            {"runtime_state": False},
            {"approval_state": "NOT_APPROVED"},
            {"production_state": "BLOCKED"},
            {"customer_state": False},
            {"socaas_state": False},
            {"final_authority": False},
            {"case_state": False},
            {"production_live": {"enabled": False}},
            {"ai_authority": {"enabled": False}},
            {"review_disposition": {"approved": "NOT_APPROVED"}},
            {"final_authorization": {"granted": "BLOCKED"}},
            {"production_live": [False]},
            {"ai_authority": ["BLOCKED"]},
            {"review_disposition": ["NOT_APPROVED"]},
            {"final_authorization": ["BLOCKED"]},
        )
        for control in controls:
            with self.subTest(control=control):
                matrix.scan_nested_authority(control, "bounded")
                contract.verify_promotion_block(source_path, control)

    def test_compound_owned_context_names_are_not_split_authority_paths(self):
        source_path = ROOT / "detections/successor/ho-det-013/rule.yml"
        value = {
            "socaas_pilot_receipt_flow": {
                "pilot_status": "EXISTING_FLOW_CANDIDATE",
                "customer_safe_summary_status": "PARTIAL",
            },
            "platform_case_packet_guardrail_status": (
                "SATISFIED_NON_PROMOTIONAL_BOUNDARY"
            ),
        }

        matrix.scan_nested_authority(value, "owned")
        contract.verify_promotion_block(source_path, value)

    def test_affirmative_authority_prose_fails_closed(self):
        attacks = (
            "customer deployment is active",
            "deployed to customer Acme",
            "customer environment deployed",
            "analyst approval granted",
            "analyst approved this disposition",
            "SOCaaS deployment is live",
            "SOCaaS is deployed",
            "public safe runtime proof established",
            "public safe for release",
            "production is live",
            "final authorization received",
            "case closure complete",
            "runtime is active",
            "signal was observed",
        )
        source_path = (
            ROOT / "detections" / "successor" / "ho-det-013" / "rule.yml"
        )
        for attack in attacks:
            with self.subTest(attack=attack):
                with self.assertRaises((matrix.MatrixError, SystemExit)):
                    matrix.scan_nested_authority({"notes": attack}, "hostile")
                with self.assertRaises(SystemExit):
                    contract.verify_promotion_block(
                        source_path, {"notes": attack}
                    )

    def test_negated_authority_prose_remains_bounded(self):
        value = {"notes": "customer deployment is not active and remains blocked"}
        matrix.scan_nested_authority(value, "bounded")
        contract.verify_promotion_block(
            ROOT / "detections" / "successor" / "ho-det-013" / "rule.yml",
            value,
        )

    def test_cross_clause_negation_cannot_launder_affirmative_claim(self):
        attacks = (
            "not public safe; customer deployment is active",
            "no signal observed; final authorization is granted",
            "unsupported here; case is closed",
            "runtime is blocked. analyst approval is granted",
            "pending documentation, production is live",
            "unsupported note — customer environment deployed",
            "future issue: signal was observed",
            "missing receipt while production is live",
            "no proof currently, customer environment deployed",
            "not approved / production is live",
        )
        source_path = (
            ROOT / "detections" / "successor" / "ho-det-013" / "rule.yml"
        )
        for attack in attacks:
            with self.subTest(attack=attack, verifier="matrix"):
                with self.assertRaises(matrix.MatrixError):
                    matrix.scan_nested_authority({"notes": attack}, "hostile")
            with self.subTest(attack=attack, verifier="contract"):
                with self.assertRaises(SystemExit):
                    contract.verify_promotion_block(source_path, {"notes": attack})

    def test_earlier_negation_cannot_launder_later_forbidden_claim_line(self):
        path = self.root / "claim-boundary.md"
        path.write_text(
            "No live claims are made here.\n"
            + "\n".join(f"bounded context {index}" for index in range(25))
            + "\nThe package is production-ready.\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(matrix.MatrixError, "unbounded blocked claim"):
            matrix.scan_claim_lines(path, self.root)

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

    def test_unknown_package_document_fields_fail_closed(self):
        for filename in ("rule.yml", "status.yml", "event-mapping.yml"):
            with self.subTest(filename=filename):
                target = (
                    self.root / "detections" / "successor" / "ho-det-013" / filename
                )
                data = yaml.safe_load(target.read_text(encoding="utf-8"))
                data["unsupported_authority_extension"] = {"decision": "granted"}
                target.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
                with self.assertRaisesRegex(matrix.MatrixError, "unsupported top-level fields"):
                    self.verify()
                shutil.copy2(
                    ROOT / "detections" / "successor" / "ho-det-013" / filename,
                    target,
                )

    def test_factory_index_rejects_casefolded_alias_row(self):
        index = self.root / "detections" / "DETECTION_FACTORY_INDEX.md"
        index.write_text(
            index.read_text(encoding="utf-8")
            + "\n| ho-det-009 | alias | alias | alias | alias | SOURCE_EXISTS |\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(matrix.MatrixError, "noncanonical detection ID"):
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
        self.commit_repo(validation_root)
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
        self.commit_repo(proof_root)
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
        self.commit_repo(registry_path.parents[1], "hostile source reference")
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
        self.commit_repo(registry_path.parents[1], "hostile source manifest")
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
        self.commit_repo(proof_path.parents[2], "hostile proof owner")
        with self.assertRaisesRegex(matrix.MatrixError, "spoofed source owner"):
            matrix.verify_repo(
                self.root,
                print_summary=False,
                validation_registry_path=registry_path,
                proof_index_path=proof_path,
                require_sibling_handoffs=True,
            )

    def test_external_owner_suffix_without_canonical_git_origin_fails(self):
        fake_root = self.base / "attacker" / "hawkinsoperations-validation"
        target = fake_root / "validation" / "VALIDATION_REGISTRY.yml"
        target.parent.mkdir(parents=True)
        target.write_text("owner_repo: hawkinsoperations-validation\n", encoding="utf-8")
        with self.assertRaisesRegex(matrix.MatrixError, "verifiable Git repository"):
            matrix.external_repo_root(
                target, "hawkinsoperations-validation", "validation registry"
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
