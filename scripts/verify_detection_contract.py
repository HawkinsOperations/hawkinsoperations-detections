#!/usr/bin/env python3
"""
Baseline detection contract check.

Current scope:
- Validates hero detection directories under detections/hero/
- Validates required baseline artifact paths for each hero detection
- Validates schema shape requirements from .github/contracts/detection-artifact.schema.json

Not covered yet:
- Non-hero detection families
- Full semantic validation of rule logic
- Cross-repository linkage to validation/proof artifacts
"""
import json
import os
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / ".github" / "contracts" / "detection-artifact.schema.json"
HERO_DIR = ROOT / "detections" / "hero"
COMMIT_RE = re.compile(r"^[0-9a-f]{7,40}$")
HERO_NAME_RE = re.compile(r"^(\d+)-")


def fail(msg: str) -> None:
    print(f"Baseline detection contract check failed: {msg}", file=sys.stderr)
    raise SystemExit(1)


def ensure_schema_loadable() -> dict:
    if not SCHEMA_PATH.exists():
        fail(f"missing schema file: {SCHEMA_PATH}")
    try:
        return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid schema JSON: {exc}")


def detection_id_from_dirname(dirname: str) -> str:
    m = HERO_NAME_RE.match(dirname)
    if not m:
        fail(f"hero detection directory name must start with numeric prefix: {dirname}")
    return f"HOD-{int(m.group(1)):03d}"


def build_contract(detection_dir: Path) -> dict:
    required_artifacts = [
        "rule.yml",
        "attack-mapping.json",
        "manifest.sha256",
        "tests/positive-event-sysmon-1.json",
        "tests/negative-event-sysmon-1.json",
    ]
    rel_root = detection_dir.relative_to(ROOT).as_posix()
    artifact_paths = [f"{rel_root}/{p}" for p in required_artifacts]

    commit = os.getenv("GITHUB_SHA", "0" * 40).lower()
    return {
        "detection_id": detection_id_from_dirname(detection_dir.name),
        "repository": "hawkinsoperations-detections",
        "commit": commit,
        "artifact_paths": artifact_paths,
        "attack_mapping_path": f"{rel_root}/attack-mapping.json",
        "manifest_path": f"{rel_root}/manifest.sha256",
    }


def validate_by_schema_shape(contract: dict, schema: dict) -> None:
    for key in schema.get("required", []):
        if key not in contract:
            fail(f"contract missing required key: {key}")

    if not isinstance(contract.get("detection_id"), str):
        fail("detection_id must be a string")
    if not isinstance(contract.get("repository"), str):
        fail("repository must be a string")
    if not isinstance(contract.get("artifact_paths"), list) or not contract["artifact_paths"]:
        fail("artifact_paths must be a non-empty array")
    if not COMMIT_RE.match(contract.get("commit", "")):
        fail(f"commit does not match required pattern: {contract.get('commit')}")


def validate_live_artifacts(contract: dict) -> None:
    for rel in contract["artifact_paths"]:
        p = ROOT / rel
        if not p.exists():
            fail(f"artifact path listed in contract is missing: {rel}")


def main() -> int:
    print("Scope: baseline hero detection artifacts only (detections/hero/*).")
    ensure_schema_loadable()
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    if not HERO_DIR.exists():
        fail(f"missing hero detection directory: {HERO_DIR}")

    hero_detection_dirs = sorted([p for p in HERO_DIR.iterdir() if p.is_dir()])
    if not hero_detection_dirs:
        fail("no hero detections found under detections/hero/")

    for d in hero_detection_dirs:
        contract = build_contract(d)
        validate_by_schema_shape(contract, schema)
        validate_live_artifacts(contract)
        print(f"OK: {contract['detection_id']} ({d.relative_to(ROOT).as_posix()})")

    print("Baseline detection contract check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
