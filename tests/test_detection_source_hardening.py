import copy
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata
import unittest
from pathlib import Path
from unittest import mock

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
        self.assertIn("fetch-depth: 0", text)
        self.assertIn(
            'git diff --check "${{ github.event.pull_request.base.sha }}...'
            '${{ github.event.pull_request.head.sha }}"',
            text,
        )
        self.assertIn("git show --check --format= HEAD", text)

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

    def test_origin_rewrite_cannot_launder_wrong_stored_handoff_origin(self):
        validation_root = self.base / "hawkinsoperations-validation"
        registry_path = validation_root / "validation" / "VALIDATION_REGISTRY.yml"
        registry_path.parent.mkdir(parents=True)
        registry_path.write_text("owner_repo: hawkinsoperations-validation\n", encoding="utf-8")
        self.commit_repo(validation_root)
        canonical = (
            "https://github.com/HawkinsOperations/"
            "hawkinsoperations-validation.git"
        )
        wrong = "https://local.invalid/hawkinsoperations-validation.git"
        subprocess.run(
            ["git", "remote", "set-url", "origin", wrong],
            cwd=validation_root,
            check=True,
        )
        rewrite_env = {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": f"url.{canonical}.insteadOf",
            "GIT_CONFIG_VALUE_0": wrong,
        }
        with mock.patch.dict(os.environ, rewrite_env, clear=False):
            interpreted = subprocess.run(
                ["git", "remote", "get-url", "origin"],
                cwd=validation_root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            self.assertEqual(canonical, interpreted)
            with self.assertRaisesRegex(
                matrix.MatrixError, "repository origin is not canonical"
            ):
                matrix.external_repo_root(
                    registry_path,
                    "hawkinsoperations-validation",
                    "validation registry",
                )

    def test_git_environment_scrub_rejects_every_ambient_git_control(self):
        hostile = {
            "GIT_DIR": "decoy",
            "GIT_WORK_TREE": "decoy",
            "GIT_COMMON_DIR": "decoy",
            "GIT_INDEX_FILE": "decoy",
            "GIT_OBJECT_DIRECTORY": "decoy",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": "decoy",
            "GIT_CONFIG": "decoy",
            "GIT_CONFIG_GLOBAL": "decoy",
            "GIT_CONFIG_SYSTEM": "decoy",
            "GIT_CONFIG_NOSYSTEM": "0",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.repositoryformatversion",
            "GIT_CONFIG_VALUE_0": "1",
            "GIT_CEILING_DIRECTORIES": "decoy",
            "GIT_DISCOVERY_ACROSS_FILESYSTEM": "1",
            "GIT_SHALLOW_FILE": "decoy",
            "GIT_NAMESPACE": "decoy",
            "GIT_REPLACE_REF_BASE": "refs/decoy",
            "GIT_IMPLICIT_WORK_TREE": "1",
            "GIT_NO_REPLACE_OBJECTS": "0",
            "GIT_TERMINAL_PROMPT": "1",
        }
        with mock.patch.dict(os.environ, hostile, clear=False):
            sanitized = matrix.sanitized_git_environment()
        self.assertEqual("1", sanitized["GIT_NO_REPLACE_OBJECTS"])
        self.assertEqual("0", sanitized["GIT_TERMINAL_PROMPT"])
        self.assertEqual(
            {"git_no_replace_objects", "git_terminal_prompt"},
            {
                key.casefold()
                for key in sanitized
                if key.casefold().startswith("git_")
            },
        )

    def test_git_dir_decoy_cannot_redirect_handoff_origin_authority(self):
        validation_root = self.base / "hawkinsoperations-validation"
        registry_path = validation_root / "validation" / "VALIDATION_REGISTRY.yml"
        registry_path.parent.mkdir(parents=True)
        registry_path.write_text(
            "owner_repo: hawkinsoperations-validation\n", encoding="utf-8"
        )
        self.commit_repo(validation_root)
        canonical = (
            "https://github.com/HawkinsOperations/"
            "hawkinsoperations-validation.git"
        )
        wrong = "https://local.invalid/hawkinsoperations-validation.git"
        subprocess.run(
            ["git", "remote", "set-url", "origin", wrong],
            cwd=validation_root,
            check=True,
        )
        decoy = self.base / "decoy"
        decoy.mkdir()
        subprocess.run(
            ["git", "init", "--quiet"], cwd=decoy, check=True, capture_output=True
        )
        subprocess.run(
            ["git", "remote", "add", "origin", canonical],
            cwd=decoy,
            check=True,
        )
        raw_env = os.environ.copy()
        raw_env["GIT_DIR"] = str(decoy / ".git")
        interpreted = subprocess.run(
            [
                "git",
                "-C",
                str(validation_root),
                "config",
                "--local",
                "--get-all",
                "remote.origin.url",
            ],
            cwd=validation_root,
            check=True,
            capture_output=True,
            text=True,
            env=raw_env,
        ).stdout.strip()
        self.assertEqual(canonical, interpreted)
        with mock.patch.dict(
            os.environ, {"GIT_DIR": str(decoy / ".git")}, clear=False
        ):
            self.assertEqual(
                wrong,
                matrix.stored_repository_origin(
                    validation_root, "validation registry"
                ),
            )
            with self.assertRaisesRegex(
                matrix.MatrixError, "repository origin is not canonical"
            ):
                matrix.external_repo_root(
                    registry_path,
                    "hawkinsoperations-validation",
                    "validation registry",
                )

    def test_git_index_file_cannot_hide_staged_dirty_handoff_authority(self):
        validation_root = self.base / "hawkinsoperations-validation"
        registry_path = validation_root / "validation" / "VALIDATION_REGISTRY.yml"
        registry_path.parent.mkdir(parents=True)
        original = "owner_repo: hawkinsoperations-validation\n"
        registry_path.write_text(original, encoding="utf-8")
        self.commit_repo(validation_root)
        clean_index = self.base / "clean.index"
        alternate_env = os.environ.copy()
        alternate_env["GIT_INDEX_FILE"] = str(clean_index)
        subprocess.run(
            ["git", "read-tree", "HEAD"],
            cwd=validation_root,
            check=True,
            capture_output=True,
            env=alternate_env,
        )
        registry_path.write_text("owner_repo: attacker-owned\n", encoding="utf-8")
        subprocess.run(
            ["git", "add", "validation/VALIDATION_REGISTRY.yml"],
            cwd=validation_root,
            check=True,
        )
        registry_path.write_text(original, encoding="utf-8")
        hidden = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=validation_root,
            check=True,
            capture_output=True,
            text=True,
            env=alternate_env,
        ).stdout.strip()
        self.assertEqual("", hidden, "attack precondition: alternate index is clean")
        with mock.patch.dict(
            os.environ, {"GIT_INDEX_FILE": str(clean_index)}, clear=False
        ):
            with self.assertRaisesRegex(
                matrix.MatrixError, "tracked dirty state"
            ):
                matrix.external_repo_root(
                    registry_path,
                    "hawkinsoperations-validation",
                    "validation registry",
                )

    def test_missing_empty_or_multiple_stored_handoff_origins_fail_closed(self):
        for attack in ("missing", "empty", "multiple"):
            with self.subTest(attack=attack):
                validation_root = self.base / f"{attack}" / "hawkinsoperations-validation"
                registry_path = (
                    validation_root / "validation" / "VALIDATION_REGISTRY.yml"
                )
                registry_path.parent.mkdir(parents=True)
                registry_path.write_text(
                    "owner_repo: hawkinsoperations-validation\n", encoding="utf-8"
                )
                self.commit_repo(validation_root)
                subprocess.run(
                    ["git", "config", "--unset-all", "remote.origin.url"],
                    cwd=validation_root,
                    check=True,
                )
                if attack == "empty":
                    subprocess.run(
                        ["git", "config", "--add", "remote.origin.url", ""],
                        cwd=validation_root,
                        check=True,
                    )
                elif attack == "multiple":
                    subprocess.run(
                        [
                            "git",
                            "config",
                            "--add",
                            "remote.origin.url",
                            "https://github.com/HawkinsOperations/"
                            "hawkinsoperations-validation.git",
                        ],
                        cwd=validation_root,
                        check=True,
                    )
                    subprocess.run(
                        [
                            "git",
                            "config",
                            "--add",
                            "remote.origin.url",
                            "https://local.invalid/hawkinsoperations-validation.git",
                        ],
                        cwd=validation_root,
                        check=True,
                    )
                with self.assertRaisesRegex(
                    matrix.MatrixError, "exactly one nonempty local URL"
                ):
                    matrix.external_repo_root(
                        registry_path,
                        "hawkinsoperations-validation",
                        "validation registry",
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
            {"runtime": {"metadata": {"state": [True]}}},
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
            {"runtime": {"metadata": {"state": [False]}}},
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
        controls = (
            "customer deployment is not active and remains blocked",
            (
                "This does not prove runtime-active status, signal-observed "
                "status, production-ready status, public-safe status, "
                "AI-approved status, analyst-approved status, final "
                "authorization, or case closure."
            ),
            (
                "This does not prove customer deployment, public-safe status, "
                "final authorization, or case closure."
            ),
            (
                "Runtime, signal, public-safe, live IdP, production identity "
                "coverage, autonomous SOC, AI-approved disposition, and "
                "analyst-approved disposition claims remain blocked."
            ),
            "Café résumé – reviewer note.",
        )
        for control in controls:
            with self.subTest(control=control):
                value = {"notes": control}
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
            "does not prove runtime, customer deployment is active",
            "does not prove runtime, AI authority is enabled",
            "does not prove runtime, analyst approval granted",
            "does not prove runtime, public safe is confirmed",
            "does not prove runtime, final authorization received",
            "does not prove runtime, case closure approved",
            "does not prove runtime and customer deployment is active",
            "does not prove runtime plus public safe is confirmed",
            "does not prove runtime though case closure is approved",
            "public\u200b safe is confirmed",
            "case\u200b closure approved",
            "AI\u200b authority is enabled",
            "runtime\u200b is active",
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

    def test_combining_mark_obfuscation_in_nested_shapes_fails_closed(self):
        source_path = (
            ROOT / "detections" / "successor" / "ho-det-013" / "rule.yml"
        )
        templates = (
            "public\\u{code} safe is confirmed",
            "case\\u{code} closure approved",
            "runtime\\u{code} is active",
            "AI\\u{code} authority is enabled",
        )
        for code in ("034f", "0301", "fe0f", "0000", "0008", "001f", "007f"):
            for template in templates:
                value = json.loads(
                    '{"extensions":[{"notes":[{"deep":"'
                    + template.format(code=code)
                    + '"}]}]}'
                )
                with self.subTest(code=code, template=template, verifier="matrix"):
                    with self.assertRaises(matrix.MatrixError):
                        matrix.scan_nested_authority(value, "hostile")
                with self.subTest(code=code, template=template, verifier="contract"):
                    with self.assertRaises(SystemExit):
                        contract.verify_promotion_block(source_path, value)

        control = {
            "extensions": [
                {
                    "notes": [
                        "Café résumé – reviewer note.",
                        {"deep": "Reviewer 👩‍💻️ note."},
                        {"multiline": "Reviewer note.\n\tStill bounded."},
                    ]
                }
            ]
        }
        matrix.scan_nested_authority(control, "bounded")
        contract.verify_promotion_block(source_path, control)

    def test_connector_independent_affirmative_reset_fails_closed(self):
        source_path = (
            ROOT / "detections" / "successor" / "ho-det-013" / "rule.yml"
        )
        connectors = (
            ",",
            "and",
            "plus",
            "though",
            "because",
            "therefore",
            "meanwhile",
            "furthermore",
            "also",
            "nevertheless",
            "nonetheless",
            "except",
            "despite that",
            "in fact",
            "so",
            "consequently",
            "moreover",
            "then",
            "still",
            "even though",
        )
        for connector in connectors:
            attack = (
                f"does not prove runtime{connector} customer deployment is active"
                if connector == ","
                else f"does not prove runtime {connector} customer deployment is active"
            )
            with self.subTest(connector=connector, verifier="matrix"):
                with self.assertRaises(matrix.MatrixError):
                    matrix.scan_nested_authority({"notes": attack}, "hostile")
            with self.subTest(connector=connector, verifier="contract"):
                with self.assertRaises(SystemExit):
                    contract.verify_promotion_block(source_path, {"notes": attack})

    def test_trailing_negation_cannot_bound_prior_affirmative_state(self):
        attacks = (
            "customer deployment is active and not a typo",
            "runtime is active and not simulated",
            "final authorization received and no objections",
            "AI authority is enabled and not revoked",
            "public safe is confirmed and not disputed",
            "case closure approved and not provisional",
            "production is ready and not delayed",
            "signal is observed and not inferred",
            "customer deployment is active without ambiguity",
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
            record.write_text(
                f"# {detection_id}\ndetection_id: {detection_id}\n",
                encoding="utf-8",
            )
            card.write_text(
                f"# {detection_id} ProofCard\ncase_id: {detection_id}\n",
                encoding="utf-8",
            )
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

    def test_swapped_proof_handoff_identity_fails_closed(self):
        entries = self.verify()
        registry_path = self.make_validation_registry(entries)
        proof_path = self.make_proof_index(self.load_matrix())
        proof_index = yaml.safe_load(proof_path.read_text(encoding="utf-8"))
        by_id = {
            item["detection_id"]: item
            for item in proof_index["entries"]
        }
        by_id["HO-DET-011"]["proof_record_path"], by_id["HO-DET-012"][
            "proof_record_path"
        ] = (
            by_id["HO-DET-012"]["proof_record_path"],
            by_id["HO-DET-011"]["proof_record_path"],
        )
        proof_path.write_text(
            yaml.safe_dump(proof_index, sort_keys=False),
            encoding="utf-8",
        )
        self.commit_repo(proof_path.parents[2], "hostile swapped proof records")
        with self.assertRaisesRegex(matrix.MatrixError, "identity mismatch"):
            matrix.verify_repo(
                self.root,
                print_summary=False,
                validation_registry_path=registry_path,
                proof_index_path=proof_path,
                require_sibling_handoffs=True,
            )

    def test_rule_validation_and_claim_ceiling_must_match_status(self):
        for detection_id, field, value, message in (
            ("HO-DET-013", "validation_status", "VALIDATION_PLANNED", "validation status disagreement"),
            ("HO-DET-013", "claim_ceiling", "SOURCE_EXISTS", "claim ceiling disagreement"),
        ):
            with self.subTest(field=field):
                package = (
                    self.root
                    / "detections"
                    / "successor"
                    / detection_id.casefold()
                )
                rule_path = package / "rule.yml"
                rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
                rule[field] = value
                rule_path.write_text(
                    yaml.safe_dump(rule, sort_keys=False),
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(matrix.MatrixError, message):
                    matrix.verify_repo(self.root, print_summary=False)
                shutil.copy2(
                    ROOT / "detections" / "successor" / detection_id.casefold() / "rule.yml",
                    rule_path,
                )

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
