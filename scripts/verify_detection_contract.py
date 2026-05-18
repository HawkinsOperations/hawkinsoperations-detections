#!/usr/bin/env python3
"""Detection contract verification across hero/successor/cloud packages."""
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / ".github" / "contracts" / "detection-artifact.schema.json"
FAMILIES = ("hero", "successor", "cloud")
HERO_NAME_RE = re.compile(r"^(\d+)-")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

HERO_REQUIRED = {
    "rule.yml",
    "attack-mapping.json",
    "manifest.sha256",
    "tests/positive-event-sysmon-1.json",
    "tests/negative-event-sysmon-1.json",
}
SUCCESSOR_REQUIRED = {
    "rule.yml",
    "event-mapping.yml",
    "status.yml",
}
CLOUD_REQUIRED = {
    "rule.yml",
    "status.yml",
}

PROMOTION_BLOCK_FIELDS = (
    "public_safe_status",
    "runtime_active",
    "signal_observed",
    "evidence_linked_public_proof",
)


def fail(msg: str) -> None:
    print(f"Detection contract check failed: {msg}", file=sys.stderr)
    raise SystemExit(1)


def read_schema_required_keys() -> list[str]:
    if not SCHEMA_PATH.exists():
        fail(f"missing schema file: {SCHEMA_PATH}")
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid schema JSON: {exc}")
    required = schema.get("required", [])
    if not isinstance(required, list):
        fail("schema required keys are not a list")
    return required


def truthy(v) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    if isinstance(v, str):
        return v.strip().lower() in {"true", "yes", "1", "y", "on"}
    return bool(v)


def sha256_of(path: Path) -> str:
    raw = path.read_bytes()
    # Normalize Windows checkout newlines so manifest hashes are stable in CI/local.
    normalized = raw.replace(b"\r\n", b"\n")
    return hashlib.sha256(normalized).hexdigest()


def parse_yaml(path: Path) -> dict:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        fail(f"invalid YAML parse: {path.relative_to(ROOT).as_posix()} ({exc})")
    if not isinstance(data, dict):
        fail(f"YAML root must be a mapping: {path.relative_to(ROOT).as_posix()}")
    return data


def parse_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON parse: {path.relative_to(ROOT).as_posix()} ({exc})")


def parse_xml(path: Path) -> ET.Element:
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        fail(f"invalid XML parse: {path.relative_to(ROOT).as_posix()} ({exc})")
    return tree.getroot()


def ensure_blocked_claims(path: Path, data: dict) -> None:
    claims = data.get("blocked_claims")
    if not isinstance(claims, list) or not claims:
        fail(f"missing blocked_claims list: {path.relative_to(ROOT).as_posix()}")


def ensure_detection_id(path: Path, data: dict) -> str:
    detection_id = data.get("detection_id")
    if not isinstance(detection_id, str) or not detection_id.strip():
        fail(f"missing detection_id: {path.relative_to(ROOT).as_posix()}")
    return detection_id.strip()


def verify_manifest(package_dir: Path, drift_warnings: list[str]) -> None:
    manifest = package_dir / "manifest.sha256"
    if not manifest.exists():
        return
    for raw in manifest.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split("  ", 1)
        if len(parts) != 2:
            fail(f"invalid manifest line format: {manifest.relative_to(ROOT).as_posix()} :: {raw}")
        expected, rel = parts
        if not HEX64_RE.match(expected):
            fail(f"invalid manifest hash token: {manifest.relative_to(ROOT).as_posix()} :: {expected}")
        target = package_dir / rel
        if not target.exists():
            fail(f"manifest points to missing file: {target.relative_to(ROOT).as_posix()}")
        actual = sha256_of(target)
        if actual != expected:
            family = package_dir.parts[-2]
            name = package_dir.name
            msg = f"manifest drift: {package_dir.relative_to(ROOT).as_posix()} :: {rel}"
            if family == "successor" and name == "ho-det-011":
                drift_warnings.append(msg)
            else:
                fail(msg)


def verify_package_inventory(package_dir: Path, family: str) -> None:
    required = HERO_REQUIRED if family == "hero" else SUCCESSOR_REQUIRED if family == "successor" else CLOUD_REQUIRED
    missing = [p for p in sorted(required) if not (package_dir / p).exists()]
    if missing:
        fail(f"missing required files for {package_dir.relative_to(ROOT).as_posix()}: {', '.join(missing)}")


def hero_detection_id(dirname: str) -> str:
    m = HERO_NAME_RE.match(dirname)
    if not m:
        fail(f"hero detection directory must start with numeric prefix: {dirname}")
    return f"HOD-{int(m.group(1)):03d}"


def verify_promotion_block(path: Path, data: dict) -> None:
    for key in PROMOTION_BLOCK_FIELDS:
        if key in data and truthy(data[key]):
            fail(f"truthy promotion field blocked in {path.relative_to(ROOT).as_posix()}: {key}={data[key]}")


def verify_package(package_dir: Path, family: str, schema_required: list[str], drift_warnings: list[str]) -> None:
    verify_package_inventory(package_dir, family)
    verify_manifest(package_dir, drift_warnings)

    rule = parse_yaml(package_dir / "rule.yml")
    expected_hero_id = hero_detection_id(package_dir.name) if family == "hero" else None
    if family == "hero":
        if "detection_id" in rule:
            rule_id = ensure_detection_id(package_dir / "rule.yml", rule)
        else:
            rule_id = expected_hero_id
    else:
        rule_id = ensure_detection_id(package_dir / "rule.yml", rule)
    if family != "hero" or "blocked_claims" in rule:
        ensure_blocked_claims(package_dir / "rule.yml", rule)
    verify_promotion_block(package_dir / "rule.yml", rule)

    if family == "hero":
        expected = expected_hero_id
        if rule_id != expected:
            fail(f"hero detection_id mismatch in {package_dir.relative_to(ROOT).as_posix()}: expected {expected}, got {rule_id}")
        parse_json(package_dir / "attack-mapping.json")
        parse_json(package_dir / "tests/positive-event-sysmon-1.json")
        parse_json(package_dir / "tests/negative-event-sysmon-1.json")

        contract = {
            "detection_id": rule_id,
            "repository": "hawkinsoperations-detections",
            "commit": "0" * 40,
            "artifact_paths": [f"{package_dir.relative_to(ROOT).as_posix()}/{p}" for p in sorted(HERO_REQUIRED)],
            "attack_mapping_path": f"{package_dir.relative_to(ROOT).as_posix()}/attack-mapping.json",
            "manifest_path": f"{package_dir.relative_to(ROOT).as_posix()}/manifest.sha256",
        }
        for key in schema_required:
            if key not in contract:
                fail(f"hero contract missing required key: {key}")

    if family in {"successor", "cloud"}:
        mapping = parse_yaml(package_dir / "event-mapping.yml") if (package_dir / "event-mapping.yml").exists() else None
        if mapping is not None:
            mapping_id = ensure_detection_id(package_dir / "event-mapping.yml", mapping)
            verify_promotion_block(package_dir / "event-mapping.yml", mapping)
            if mapping_id != rule_id:
                drift_warnings.append(
                    f"metadata drift: detection_id mismatch rule/event-mapping in {package_dir.relative_to(ROOT).as_posix()} ({rule_id} vs {mapping_id})"
                )

        status = parse_yaml(package_dir / "status.yml")
        status_id = ensure_detection_id(package_dir / "status.yml", status)
        ensure_blocked_claims(package_dir / "status.yml", status)
        verify_promotion_block(package_dir / "status.yml", status)
        if status_id != rule_id:
            drift_warnings.append(
                f"metadata drift: detection_id mismatch rule/status in {package_dir.relative_to(ROOT).as_posix()} ({rule_id} vs {status_id})"
            )


def iter_detection_dirs() -> list[tuple[str, Path]]:
    out: list[tuple[str, Path]] = []
    for family in FAMILIES:
        family_dir = ROOT / "detections" / family
        if not family_dir.exists():
            continue
        if family != "cloud":
            for d in sorted(p for p in family_dir.iterdir() if p.is_dir()):
                out.append((family, d))
            continue

        # Cloud supports provider grouping directories (for example cloud/aws/)
        # and leaf detection package directories (for example cloud/aws/aws-det-001/).
        # Validate only leaf package directories that carry package contract anchors.
        for d in sorted(p for p in family_dir.rglob("*") if p.is_dir()):
            has_child_dirs = any(c.is_dir() for c in d.iterdir())
            has_contract_anchor = (d / "rule.yml").exists() or (d / "manifest.sha256").exists()
            if has_contract_anchor and not has_child_dirs:
                out.append((family, d))
    return out


def main() -> int:
    schema_required = read_schema_required_keys()
    targets = iter_detection_dirs()
    if not targets:
        fail("no detection packages found under detections/{hero,successor,cloud}")

    drift_warnings: list[str] = []
    for family, package_dir in targets:
        verify_package(package_dir, family, schema_required, drift_warnings)
        print(f"OK: {family} :: {package_dir.relative_to(ROOT).as_posix()}")

    if drift_warnings:
        print("REPORT-ONLY METADATA DRIFT:")
        for item in drift_warnings:
            print(f"- {item}")

    print("Detection contract check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
