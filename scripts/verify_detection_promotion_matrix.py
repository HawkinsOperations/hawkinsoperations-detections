#!/usr/bin/env python3
"""Verify the detection promotion matrix stays source-truth only."""
from __future__ import annotations

import copy
import re
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "detections" / "DETECTION_PROMOTION_MATRIX.yml"
INDEX_PATH = ROOT / "detections" / "DETECTION_FACTORY_INDEX.md"

REQUIRED_FIELDS = {
    "detection_id",
    "package_path",
    "detection_family",
    "required_files",
    "source_status",
    "validation_expected_owner",
    "validation_status_if_known",
    "runtime_active",
    "signal_observed",
    "public_safe_status",
    "proof_ceiling",
    "blocked_claims",
    "next_gate",
    "notes",
}

ALLOWED_SOURCE_STATUS = {
    "SOURCE_EXISTS",
    "VALIDATION_PLANNED",
    "BOUNDARY_CONTRACT_ONLY",
    "EXTERNAL_BOUNDARY_CONTRACT",
}

ALLOWED_PROOF_CEILING = {
    "SOURCE_EXISTS",
    "VALIDATION_PLANNED",
    "BOUNDARY_CONTRACT_ONLY",
}

ALLOWED_LEDGER_ELIGIBILITY_STATUS = {
    "APPENDED",
    "DRY_RUN_READY",
    "VALIDATION_READY",
    "PROOF_RECORDED",
    "BLOCKED",
    "NEEDS_TELEMETRY_CONTRACT",
    "FUTURE_CANDIDATE",
}

LEDGER_ELIGIBILITY_BUCKETS = {
    "appended": "APPENDED",
    "dry_run_ready": "DRY_RUN_READY",
    "validation_ready": "VALIDATION_READY",
    "proof_recorded": "PROOF_RECORDED",
    "blocked": "BLOCKED",
    "needs_telemetry_contract": "NEEDS_TELEMETRY_CONTRACT",
    "future_candidate": "FUTURE_CANDIDATE",
}

REVIEWER_EXPANSION_REQUIRED_FIELDS = {
    "detection_id",
    "ledger_eligibility_status",
    "reviewer_lane",
    "reviewer_summary",
    "next_reviewer_action",
}

LOCAL_SOURCE_STATUSES = {"SOURCE_EXISTS", "BOUNDARY_CONTRACT_ONLY"}
PLANNED_OR_EXTERNAL_STATUSES = {"VALIDATION_PLANNED", "EXTERNAL_BOUNDARY_CONTRACT"}

PACKAGE_FAMILIES = {"hero", "successor", "identity", "cloud"}
HERO_ID_RE = re.compile(r"^(\d+)-")
INDEX_ID_RE = re.compile(r"^(?:HOD|HO-DET|ID-DET|AWS-DET|HO-NDR|HO-PIPE)-\d+$")
FORBIDDEN_CLAIM_TERMS = (
    "runtime-active public proof",
    "signal-observed public proof",
    "public-safe proof",
    "live IdP proof",
    "live SIEM proof",
    "live Splunk proof",
    "live Wazuh proof",
    "live Cribl proof",
    "live Security Onion proof",
    "production-ready",
    "fleet-wide",
    "autonomous SOC",
    "AI-approved disposition",
    "analyst-approved disposition",
)
ALLOWED_CLAIM_CONTEXT_RE = re.compile(
    r"(?i)(blocked|blocked_claims|blocked claims|not claimed|not_claimed_here|not-claimed|"
    r"does not|does_not_support|does-not-prove|not proof|not public-safe|not runtime|not signal|"
    r"out of scope|excluded|without claiming|must not|no live|no .*claim|proof remains|"
    r"not promote|does not promote|source-only|source truth only)"
)
POSITIVE_PROMOTION_RE = re.compile(r"(?i)\b(now has|has|is|are|supports|promotes|promoted)\b")


class MatrixError(Exception):
    """Raised when the promotion matrix is not enforceable."""


def fail(message: str) -> None:
    raise MatrixError(message)


def truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "1", "y", "on", "promoted", "runtime_active"}
    return bool(value)


def rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def load_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        fail(f"invalid YAML parse: {rel(path, ROOT)} ({exc})")


def ensure_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be a mapping")
    return value


def ensure_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        fail(f"{label} must be a list")
    return value


def read_detection_id_from_yaml(path: Path, root: Path) -> str | None:
    data = load_yaml(path)
    if isinstance(data, dict):
        detection_id = data.get("detection_id")
        if isinstance(detection_id, str) and detection_id.strip():
            return detection_id.strip()
        artifact_id = data.get("artifact_id")
        if isinstance(artifact_id, str) and artifact_id.strip():
            return artifact_id.strip()
    return None


def hero_detection_id(path: Path) -> str:
    match = HERO_ID_RE.match(path.name)
    if not match:
        fail(f"hero package name must start with numeric prefix: {path.as_posix()}")
    return f"HOD-{int(match.group(1)):03d}"


def iter_package_dirs(root: Path) -> list[tuple[str, Path]]:
    targets: list[tuple[str, Path]] = []
    detections_root = root / "detections"
    for family in PACKAGE_FAMILIES:
        family_root = detections_root / family
        if not family_root.exists():
            continue
        if family == "cloud":
            candidates = sorted(p for p in family_root.rglob("*") if p.is_dir())
        else:
            candidates = sorted(p for p in family_root.iterdir() if p.is_dir())
        for candidate in candidates:
            if (candidate / "rule.yml").exists():
                targets.append((family, candidate))
    return targets


def package_detection_id(family: str, package_dir: Path, root: Path) -> str:
    if family == "hero":
        rule_id = read_detection_id_from_yaml(package_dir / "rule.yml", root)
        return rule_id or hero_detection_id(package_dir)
    for name in ("rule.yml", "status.yml", "event-mapping.yml"):
        path = package_dir / name
        if path.exists():
            detection_id = read_detection_id_from_yaml(path, root)
            if detection_id:
                return detection_id
    fail(f"could not determine detection_id for package: {rel(package_dir, root)}")


def package_ids(root: Path) -> dict[str, Path]:
    out: dict[str, Path] = {}
    for family, package_dir in iter_package_dirs(root):
        detection_id = package_detection_id(family, package_dir, root)
        if detection_id in out:
            fail(f"duplicate package detection_id {detection_id}: {rel(out[detection_id], root)} and {rel(package_dir, root)}")
        out[detection_id] = package_dir
    return out


def factory_index_ids(root: Path) -> set[str]:
    if not (root / INDEX_PATH.relative_to(ROOT)).exists():
        fail("missing detections/DETECTION_FACTORY_INDEX.md")
    ids: set[str] = set()
    for raw in (root / INDEX_PATH.relative_to(ROOT)).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line.startswith("|"):
            continue
        parts = [p.strip().strip("`") for p in line.strip("|").split("|")]
        if not parts:
            continue
        candidate = parts[0]
        if INDEX_ID_RE.match(candidate):
            ids.add(candidate)
    return ids


def is_local_path(package_path: str) -> bool:
    return "://" not in package_path


def scan_claim_lines(path: Path, root: Path) -> None:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for index, line in enumerate(lines):
        lower = line.lower()
        for term in FORBIDDEN_CLAIM_TERMS:
            term_index = lower.find(term.lower())
            if term_index == -1:
                continue
            promotion_prefix = line[max(0, term_index - 80) : term_index]
            if POSITIVE_PROMOTION_RE.search(promotion_prefix) and not ALLOWED_CLAIM_CONTEXT_RE.search(line):
                fail(f"unbounded blocked claim term in {rel(path, root)}:{index + 1}: {term}")
            context = " ".join(lines[max(0, index - 25) : index + 1])
            if not ALLOWED_CLAIM_CONTEXT_RE.search(context):
                fail(f"unbounded blocked claim term in {rel(path, root)}:{index + 1}: {term}")


def scan_source_only_claims(package_dir: Path, root: Path) -> None:
    text_files = [
        p
        for p in package_dir.rglob("*")
        if p.is_file() and p.suffix.lower() in {".md", ".yml", ".yaml", ".spl", ".xml", ".jsonpath"}
    ]
    for path in text_files:
        scan_claim_lines(path, root)


def scan_global_metadata_claims(root: Path) -> None:
    for relative_path in (MATRIX_PATH.relative_to(ROOT), INDEX_PATH.relative_to(ROOT)):
        path = root / relative_path
        if not path.exists():
            fail(f"missing global metadata file: {relative_path.as_posix()}")
        scan_claim_lines(path, root)


def verify_entry(entry: dict[str, Any], root: Path) -> tuple[str, str]:
    missing = sorted(REQUIRED_FIELDS.difference(entry))
    detection_id = entry.get("detection_id", "<unknown>")
    if missing:
        fail(f"matrix entry {detection_id} missing required fields: {', '.join(missing)}")
    if not isinstance(detection_id, str) or not detection_id.strip():
        fail("matrix entry detection_id must be a non-empty string")
    detection_id = detection_id.strip()

    package_path = entry["package_path"]
    if not isinstance(package_path, str) or not package_path.strip():
        fail(f"{detection_id} package_path must be a non-empty string")
    package_path = package_path.strip()

    required_files = ensure_list(entry["required_files"], f"{detection_id}.required_files")
    if any(not isinstance(item, str) or not item.strip() for item in required_files):
        fail(f"{detection_id}.required_files must contain only non-empty strings")

    source_status = entry["source_status"]
    if source_status not in ALLOWED_SOURCE_STATUS:
        fail(f"{detection_id} source_status not allowed: {source_status}")
    if entry["proof_ceiling"] not in ALLOWED_PROOF_CEILING:
        fail(f"{detection_id} proof_ceiling not allowed: {entry['proof_ceiling']}")
    if entry["public_safe_status"] != "NOT_PUBLIC_SAFE":
        fail(f"{detection_id} public_safe_status must be NOT_PUBLIC_SAFE")
    if truthy(entry["runtime_active"]):
        fail(f"{detection_id} runtime_active must remain false")
    if truthy(entry["signal_observed"]):
        fail(f"{detection_id} signal_observed must remain false")
    if not isinstance(entry["validation_expected_owner"], str) or not entry["validation_expected_owner"].strip():
        fail(f"{detection_id} validation_expected_owner must be a non-empty string")
    if not isinstance(entry["validation_status_if_known"], str) or not entry["validation_status_if_known"].strip():
        fail(f"{detection_id} validation_status_if_known must be a non-empty string")
    if not isinstance(entry["next_gate"], str) or not entry["next_gate"].strip():
        fail(f"{detection_id} next_gate must be a non-empty string")
    if not isinstance(entry["notes"], str) or not entry["notes"].strip():
        fail(f"{detection_id} notes must be a non-empty string")

    blocked_claims = ensure_list(entry["blocked_claims"], f"{detection_id}.blocked_claims")
    if not blocked_claims or any(not isinstance(item, str) or not item.strip() for item in blocked_claims):
        fail(f"{detection_id}.blocked_claims must contain non-empty blocked claim strings")

    if is_local_path(package_path):
        package_dir = root / package_path
        if not package_dir.exists():
            if source_status in LOCAL_SOURCE_STATUSES:
                fail(f"{detection_id} package path missing: {package_path}")
        elif not package_dir.is_dir():
            fail(f"{detection_id} package path is not a directory: {package_path}")

        if package_dir.exists():
            for required in required_files:
                if not (package_dir / required).exists():
                    fail(f"{detection_id} required file missing: {package_path}/{required}")
            ids_seen: set[str] = set()
            for name in ("rule.yml", "status.yml", "event-mapping.yml", "cribl-pipeline.yml"):
                path = package_dir / name
                if path.exists():
                    found = read_detection_id_from_yaml(path, root)
                    if found:
                        ids_seen.add(found)
            if not ids_seen and "hero/" in package_path:
                ids_seen.add(hero_detection_id(package_dir))
            mismatches = sorted(item for item in ids_seen if item != detection_id)
            if mismatches:
                fail(f"{detection_id} metadata detection_id mismatch in {package_path}: {', '.join(mismatches)}")
            scan_source_only_claims(package_dir, root)
    elif source_status not in PLANNED_OR_EXTERNAL_STATUSES:
        fail(f"{detection_id} non-local package paths must be planned or external")

    return detection_id, package_path


def verify_ledger_eligibility_map(matrix: dict[str, Any], detection_ids: set[str]) -> dict[str, str]:
    configured_status_values = ensure_list(
        matrix.get("ledger_eligibility_status_values"),
        "matrix.ledger_eligibility_status_values",
    )
    if set(configured_status_values) != ALLOWED_LEDGER_ELIGIBILITY_STATUS:
        fail("matrix.ledger_eligibility_status_values must match the allowed ledger eligibility statuses")

    eligibility = ensure_mapping(
        matrix.get("detection_side_ledger_eligibility"),
        "matrix.detection_side_ledger_eligibility",
    )
    missing_buckets = sorted(set(LEDGER_ELIGIBILITY_BUCKETS) - set(eligibility))
    if missing_buckets:
        fail(f"matrix.detection_side_ledger_eligibility missing buckets: {', '.join(missing_buckets)}")
    extra_buckets = sorted(set(eligibility) - set(LEDGER_ELIGIBILITY_BUCKETS))
    if extra_buckets:
        fail(f"matrix.detection_side_ledger_eligibility has unapproved buckets: {', '.join(extra_buckets)}")

    id_to_status: dict[str, str] = {}
    for bucket, status in LEDGER_ELIGIBILITY_BUCKETS.items():
        values = ensure_list(eligibility[bucket], f"matrix.detection_side_ledger_eligibility.{bucket}")
        for detection_id in values:
            if not isinstance(detection_id, str) or not detection_id.strip():
                fail(f"matrix.detection_side_ledger_eligibility.{bucket} must contain non-empty detection IDs")
            detection_id = detection_id.strip()
            if detection_id not in detection_ids:
                fail(f"ledger eligibility references unknown detection_id: {detection_id}")
            if detection_id in id_to_status:
                fail(f"ledger eligibility classifies {detection_id} more than once")
            id_to_status[detection_id] = status

    missing_ids = sorted(detection_ids - set(id_to_status))
    if missing_ids:
        fail(f"ledger eligibility missing detection IDs: {', '.join(missing_ids)}")
    return id_to_status


def verify_reviewer_expansion_map(matrix: dict[str, Any], id_to_status: dict[str, str]) -> None:
    reviewer_map = ensure_list(matrix.get("reviewer_expansion_map"), "matrix.reviewer_expansion_map")
    seen: set[str] = set()
    for raw_entry in reviewer_map:
        entry = ensure_mapping(raw_entry, "reviewer expansion map entry")
        missing = sorted(REVIEWER_EXPANSION_REQUIRED_FIELDS.difference(entry))
        detection_id = entry.get("detection_id", "<unknown>")
        if missing:
            fail(f"reviewer expansion map entry {detection_id} missing required fields: {', '.join(missing)}")
        if not isinstance(detection_id, str) or not detection_id.strip():
            fail("reviewer expansion map detection_id must be a non-empty string")
        detection_id = detection_id.strip()
        if detection_id not in id_to_status:
            fail(f"reviewer expansion map references unknown detection_id: {detection_id}")
        if detection_id in seen:
            fail(f"reviewer expansion map duplicates detection_id: {detection_id}")
        seen.add(detection_id)
        ledger_status = entry["ledger_eligibility_status"]
        if ledger_status not in ALLOWED_LEDGER_ELIGIBILITY_STATUS:
            fail(f"{detection_id} ledger_eligibility_status not allowed: {ledger_status}")
        if ledger_status != id_to_status[detection_id]:
            fail(f"{detection_id} ledger_eligibility_status does not match bucketed eligibility map")
        for field in ("reviewer_lane", "reviewer_summary", "next_reviewer_action"):
            value = entry[field]
            if not isinstance(value, str) or not value.strip():
                fail(f"{detection_id}.{field} must be a non-empty string")

    missing_ids = sorted(set(id_to_status) - seen)
    if missing_ids:
        fail(f"reviewer expansion map missing detection IDs: {', '.join(missing_ids)}")


def verify_repo(root: Path = ROOT, print_summary: bool = True) -> list[dict[str, Any]]:
    matrix_path = root / MATRIX_PATH.relative_to(ROOT)
    if not matrix_path.exists():
        fail("missing detections/DETECTION_PROMOTION_MATRIX.yml")
    matrix = ensure_mapping(load_yaml(matrix_path), "matrix root")
    entries = ensure_list(matrix.get("entries"), "matrix.entries")
    if not entries:
        fail("matrix.entries must not be empty")

    seen: dict[str, str] = {}
    normalized_entries: list[dict[str, Any]] = []
    for raw_entry in entries:
        entry = ensure_mapping(raw_entry, "matrix entry")
        detection_id, package_path = verify_entry(entry, root)
        if detection_id in seen:
            fail(f"duplicate detection_id in matrix: {detection_id}")
        seen[detection_id] = package_path
        normalized_entries.append(copy.deepcopy(entry))

    id_to_status = verify_ledger_eligibility_map(matrix, set(seen))
    verify_reviewer_expansion_map(matrix, id_to_status)
    scan_global_metadata_claims(root)

    packages = package_ids(root)
    missing_from_matrix = sorted(set(packages) - set(seen))
    if missing_from_matrix:
        fail(f"detection package missing from matrix: {', '.join(missing_from_matrix)}")

    local_matrix_paths = {
        detection_id: root / package_path
        for detection_id, package_path in seen.items()
        if is_local_path(package_path) and (root / package_path).exists()
    }
    package_paths = {path.resolve() for path in packages.values()}
    extra_local = sorted(
        detection_id
        for detection_id, path in local_matrix_paths.items()
        if path.resolve() not in package_paths and normalized_entries[[e["detection_id"] for e in normalized_entries].index(detection_id)]["source_status"] not in PLANNED_OR_EXTERNAL_STATUSES
    )
    if extra_local:
        fail(f"matrix local source entry missing from package tree: {', '.join(extra_local)}")

    index_ids = factory_index_ids(root)
    missing_index_ids = sorted(index_ids - set(seen))
    if missing_index_ids:
        fail(f"factory index IDs missing from matrix: {', '.join(missing_index_ids)}")

    if print_summary:
        print("DETECTION_PROMOTION_MATRIX=pass")
        print(f"MATRIX_ENTRIES={len(normalized_entries)}")
        print(f"PACKAGE_TREE_ENTRIES={len(packages)}")
        print(f"FACTORY_INDEX_IDS={len(index_ids)}")
        for entry in normalized_entries:
            print(
                "OK: {detection_id} source={source_status} validation={validation_status_if_known} "
                "runtime={runtime_active} signal={signal_observed} public={public_safe_status}".format(**entry)
            )
    return normalized_entries


def main() -> int:
    try:
        verify_repo(ROOT, print_summary=True)
    except MatrixError as exc:
        print(f"Detection promotion matrix check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
