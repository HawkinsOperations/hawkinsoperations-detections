#!/usr/bin/env python3
"""
Baseline detection contract check.

Current scope:
- Validates hero detection directories under detections/hero/
- Validates required baseline artifact paths for each hero detection
- Validates manifest.sha256 shape and reports hash drift for hero detections
- Validates schema shape requirements from .github/contracts/detection-artifact.schema.json
- Validates successor/cloud source package metadata and claim-boundary guardrails

Not covered:
- Full semantic validation of rule logic
- Cross-repository linkage to validation/proof artifacts
"""
import hashlib
import json
import os
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / ".github" / "contracts" / "detection-artifact.schema.json"
HERO_DIR = ROOT / "detections" / "hero"
SUCCESSOR_DIR = ROOT / "detections" / "successor"
CLOUD_DIR = ROOT / "detections" / "cloud"
COMMIT_RE = re.compile(r"^[0-9a-f]{7,40}$")
HERO_NAME_RE = re.compile(r"^(\d+)-")
MANIFEST_LINE_RE = re.compile(r"^([0-9a-fA-F]{64})\s+(.+)$")

FALSE_VALUES = {"false", "no", "0"}
SOURCE_EXISTS = "SOURCE_EXISTS"
NOT_PUBLIC_SAFE = "NOT_PUBLIC_SAFE"
REQUIRED_BLOCKED_CLAIMS = {
    "runtime-active",
    "signal-observed",
    "public-safe",
    "production-ready",
    "autonomous SOC",
    "AI-approved disposition",
    "analyst-approved disposition",
}
RULE_BOUNDARY_TERMS = {
    "runtime",
    "signal",
    "public-safe",
}

SUCCESSOR_PACKAGES = {
    "ho-det-001": {
        "detection_id": "HO-DET-001",
        "required": ["rule.yml", "splunk.spl", "status.yml"],
        "status_sidecar": True,
        "status_artifacts": {
            "splunk_source_status": "splunk.spl",
        },
    },
    "ho-det-011": {
        "detection_id": "HO-DET-011",
        "required": ["README.md", "rule.yml", "splunk.spl", "wazuh.xml", "event-mapping.yml", "status.yml"],
        "status_sidecar": True,
        "status_artifacts": {
            "sigma_source_status": "rule.yml",
            "splunk_source_status": "splunk.spl",
            "wazuh_source_status": "wazuh.xml",
            "event_mapping_status": "event-mapping.yml",
        },
    },
    "ho-det-012": {
        "detection_id": "HO-DET-012",
        "required": ["README.md", "rule.yml", "splunk.spl", "wazuh.xml", "event-mapping.yml", "status.yml"],
        "status_sidecar": True,
        "status_artifacts": {
            "sigma_source_status": "rule.yml",
            "splunk_source_status": "splunk.spl",
            "wazuh_source_status": "wazuh.xml",
            "event_mapping_status": "event-mapping.yml",
        },
    },
    "ho-pipe-001": {
        "artifact_id": "HO-PIPE-001",
        "required": ["cribl-pipeline.yml"],
        "pipeline_source": True,
    },
}

CLOUD_PACKAGES = {
    "aws-det-001": {
        "detection_id": "AWS-DET-001",
        "required": ["README.md", "rule.yml", "cloudtrail.jsonpath"],
    },
}


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


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def read_top_level_scalars(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in read_text(path).splitlines():
        if not raw_line or raw_line.startswith((" ", "\t", "#", "-")):
            continue
        if ":" not in raw_line:
            continue
        key, value = raw_line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if not key or not value or value in {">", ">-", "|", "|-"}:
            continue
        values[key] = value.strip("\"'")
    return values


def read_top_level_list(path: Path, section: str) -> list[str]:
    values: list[str] = []
    in_section = False
    for raw_line in read_text(path).splitlines():
        if raw_line.startswith(f"{section}:"):
            in_section = True
            continue
        if in_section and raw_line and not raw_line.startswith((" ", "\t", "-")):
            break
        if in_section:
            stripped = raw_line.strip()
            if stripped.startswith("- "):
                values.append(stripped[2:].strip().strip("\"'"))
    return values


def require_file(path: Path, label: str) -> None:
    if not path.exists():
        fail(f"missing {label}: {rel(path)}")


def require_scalar(metadata: dict[str, str], key: str, expected: str, label: str) -> None:
    actual = metadata.get(key)
    if actual != expected:
        fail(f"{label} {key} expected {expected}, got {actual!r}")


def require_false_value(metadata: dict[str, str], key: str, label: str) -> None:
    actual = metadata.get(key)
    if actual is None or actual.strip().lower() not in FALSE_VALUES:
        fail(f"{label} {key} must be false/NO, got {actual!r}")


def warn(msg: str) -> None:
    print(f"WARN: {msg}")


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


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_manifest(manifest_path: Path) -> None:
    manifest_dir = manifest_path.parent
    seen: set[str] = set()
    for line_number, line in enumerate(read_text(manifest_path).splitlines(), start=1):
        if not line.strip():
            continue
        match = MANIFEST_LINE_RE.match(line)
        if not match:
            fail(f"{rel(manifest_path)}:{line_number} invalid manifest line")
        listed_hash = match.group(1).lower()
        artifact_rel = match.group(2).strip()
        if artifact_rel in seen:
            fail(f"{rel(manifest_path)}:{line_number} duplicate manifest entry: {artifact_rel}")
        seen.add(artifact_rel)
        artifact_path = manifest_dir / artifact_rel
        if not artifact_path.exists():
            fail(f"{rel(manifest_path)}:{line_number} missing manifest artifact: {artifact_rel}")
        actual_hash = sha256_file(artifact_path)
        if listed_hash != actual_hash:
            warn(
                f"{rel(manifest_path)}:{line_number} stale hash for {artifact_rel}: "
                f"listed={listed_hash} actual={actual_hash}"
            )
    if not seen:
        fail(f"manifest has no entries: {rel(manifest_path)}")


def validate_rule_metadata(path: Path, detection_id: str) -> dict[str, str]:
    metadata = read_top_level_scalars(path)
    require_scalar(metadata, "detection_id", detection_id, rel(path))
    require_scalar(metadata, "public_safe_status", NOT_PUBLIC_SAFE, rel(path))
    require_false_value(metadata, "runtime_active", rel(path))
    require_false_value(metadata, "signal_observed", rel(path))
    blocked_claims = read_top_level_list(path, "blocked_claims")
    if not blocked_claims:
        fail(f"{rel(path)} must include blocked_claims")
    boundary_text = "\n".join(blocked_claims).lower() + "\n" + read_text(path).lower()
    missing_terms = sorted(term for term in RULE_BOUNDARY_TERMS if term not in boundary_text)
    if missing_terms:
        fail(f"{rel(path)} blocked boundary text missing terms: {', '.join(missing_terms)}")
    return metadata


def validate_status_sidecar(path: Path, package_dir: Path, config: dict) -> dict[str, str]:
    detection_id = str(config["detection_id"])
    metadata = read_top_level_scalars(path)
    require_scalar(metadata, "detection_id", detection_id, rel(path))
    require_scalar(metadata, "public_safe_status", NOT_PUBLIC_SAFE, rel(path))
    require_false_value(metadata, "runtime_active", rel(path))
    require_false_value(metadata, "signal_observed", rel(path))
    blocked_claims = set(read_top_level_list(path, "blocked_claims"))
    missing = sorted(REQUIRED_BLOCKED_CLAIMS - blocked_claims)
    if missing:
        fail(f"{rel(path)} blocked_claims missing required entries: {', '.join(missing)}")

    for field, artifact in config.get("status_artifacts", {}).items():
        if metadata.get(field) == SOURCE_EXISTS:
            require_file(package_dir / artifact, f"{field} artifact")
    return metadata


def validate_event_mapping(path: Path, detection_id: str) -> dict[str, str]:
    metadata = read_top_level_scalars(path)
    require_scalar(metadata, "detection_id", detection_id, rel(path))
    text = read_text(path).lower()
    for term in ["runtime-active", "signal-observed", "public-safe"]:
        if term not in text:
            fail(f"{rel(path)} missing blocked boundary term: {term}")
    return metadata


def report_lifecycle_drift(package_name: str, rule: dict[str, str], status: dict[str, str], event_mapping: dict[str, str]) -> None:
    for key in ["validation_status", "proof_level", "trust_class"]:
        status_value = status.get(key)
        rule_value = rule.get(key)
        if status_value and rule_value and status_value != rule_value:
            warn(f"{package_name}: status.yml {key}={status_value} differs from rule.yml {key}={rule_value}")
    status_validation = status.get("validation_status")
    mapping_validation = event_mapping.get("validation_status")
    if status_validation and mapping_validation and status_validation != mapping_validation:
        warn(
            f"{package_name}: status.yml validation_status={status_validation} "
            f"differs from event-mapping.yml validation_status={mapping_validation}"
        )


def validate_successor_package(package_name: str, config: dict) -> None:
    package_dir = SUCCESSOR_DIR / package_name
    require_file(package_dir, f"successor package directory {package_name}")
    for artifact in config["required"]:
        require_file(package_dir / artifact, f"{package_name} required artifact")

    if config.get("pipeline_source"):
        pipeline_path = package_dir / "cribl-pipeline.yml"
        metadata = read_top_level_scalars(pipeline_path)
        require_scalar(metadata, "artifact_id", str(config["artifact_id"]), rel(pipeline_path))
        require_scalar(metadata, "status", SOURCE_EXISTS, rel(pipeline_path))
        require_false_value(metadata, "public_safe", rel(pipeline_path))
        text = read_text(pipeline_path).lower()
        for term in ["does not", "runtime-active", "public-safe proof", "live splunk firing", "cribl-routed"]:
            if term not in text:
                fail(f"{rel(pipeline_path)} missing pipeline boundary term: {term}")
        print(f"OK: {config['artifact_id']} ({rel(package_dir)})")
        return

    detection_id = str(config["detection_id"])
    rule = validate_rule_metadata(package_dir / "rule.yml", detection_id)
    status = validate_status_sidecar(package_dir / "status.yml", package_dir, config)
    event_mapping = {}
    if (package_dir / "event-mapping.yml").exists():
        event_mapping = validate_event_mapping(package_dir / "event-mapping.yml", detection_id)
    report_lifecycle_drift(package_name, rule, status, event_mapping)
    print(f"OK: {detection_id} ({rel(package_dir)})")


def validate_cloud_package(family: str, package_name: str, config: dict) -> None:
    package_dir = CLOUD_DIR / family / package_name
    require_file(package_dir, f"cloud package directory {family}/{package_name}")
    for artifact in config["required"]:
        require_file(package_dir / artifact, f"{package_name} required artifact")
    validate_rule_metadata(package_dir / "rule.yml", str(config["detection_id"]))
    print(f"OK: {config['detection_id']} ({rel(package_dir)})")


def validate_source_packages() -> None:
    if not SUCCESSOR_DIR.exists():
        fail(f"missing successor detection directory: {rel(SUCCESSOR_DIR)}")
    for package_name, config in SUCCESSOR_PACKAGES.items():
        validate_successor_package(package_name, config)
    for package_name, config in CLOUD_PACKAGES.items():
        validate_cloud_package("aws", package_name, config)


def main() -> int:
    print("Scope: hero artifacts plus successor/cloud source package guardrails.")
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
        validate_manifest(d / "manifest.sha256")
        print(f"OK: {contract['detection_id']} ({d.relative_to(ROOT).as_posix()})")

    validate_source_packages()
    print("Baseline detection contract check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
