#!/usr/bin/env python3
"""Verify Wazuh rule-source registry boundaries and XML metadata."""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "detections" / "wazuh" / "WAZUH_RULE_SOURCE_REGISTRY.yml"

FALSEY = {False, None, "", "false", "no", "not_proven", "not_claimed", "blocked"}
ALLOWED_REGISTRY_STATUS = "WAZUH_RULE_SOURCE_CONTRACT_ENFORCED"
ALLOWED_PROOF_CEILING = "SOURCE_AND_STATIC_CI_ONLY_NOT_RUNTIME_PROOF"
ALLOWED_MAPPING_LANES = {
    "wazuh_rule_source",
    "wazuh_rule_source_planned",
    "wazuh_rule_source_conditional",
    "private_runtime_design_only",
}
ALLOWED_DASHBOARD_TILES = {
    "Endpoint Health",
    "Detection Noise",
    "MITRE Signal",
    "HO-VICTUS-01 Onboarding",
    "Runner/CI Signal",
    "Cribl Pipeline Signal",
    "Rule Tuning Backlog",
    "HawkinsOperations Detection Mapping",
}


class WazuhRuleSourceError(Exception):
    """Wazuh source registry violation."""


def fail(message: str) -> None:
    raise WazuhRuleSourceError(message)


def truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() not in FALSEY
    return value not in FALSEY


def rel_path(root: Path, value: str, field: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        fail(f"{field} must be repo-relative: {value}")
    return root / path


def load_registry(path: Path = REGISTRY_PATH) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"missing Wazuh rule source registry: {path}")
    except yaml.YAMLError as exc:
        fail(f"invalid Wazuh rule source registry YAML: {exc}")
    if not isinstance(data, dict):
        fail("Wazuh rule source registry root must be a mapping")
    return data


def parse_wazuh_xml(path: Path) -> list[dict[str, Any]]:
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        fail(f"invalid Wazuh XML parse: {path.relative_to(ROOT).as_posix()} ({exc})")

    rules = []
    for rule in root.iter("rule"):
        try:
            rule_id = int(str(rule.attrib.get("id", "")).strip())
        except ValueError:
            fail(f"Wazuh rule has non-integer id in {path.relative_to(ROOT).as_posix()}")
        groups: set[str] = set()
        for group in rule.findall("group"):
            if group.text:
                groups.update(item.strip() for item in group.text.split(",") if item.strip())
        mitre_ids = {node.text.strip() for node in rule.findall(".//id") if node.text and node.text.strip().startswith("T")}
        rules.append({"id": rule_id, "groups": groups, "mitre_ids": mitre_ids})
    if not rules:
        fail(f"Wazuh XML has no rule elements: {path.relative_to(ROOT).as_posix()}")
    return rules


def require_false_boundary(entry: dict[str, Any], label: str) -> None:
    for field in ("runtime_status", "signal_status"):
        if truthy(entry.get(field)):
            fail(f"{label} {field} must remain false or blocked")
    if str(entry.get("public_safe_status", "")).strip() != "NOT_PUBLIC_SAFE":
        fail(f"{label} public_safe_status must be NOT_PUBLIC_SAFE")


def verify_entry(root: Path, entry: dict[str, Any], seen_rule_ids: dict[int, str]) -> dict[str, Any]:
    detection_id = str(entry.get("detection_id", "")).strip()
    if not detection_id:
        fail("registry entry missing detection_id")
    label = detection_id
    if detection_id.startswith("ID-DET-") and str(entry.get("preferred_runtime", "")).lower().startswith("wazuh"):
        fail("identity detections must not be forced to Wazuh without identity telemetry normalization")

    lane = entry.get("mapping_lane")
    if lane not in ALLOWED_MAPPING_LANES:
        fail(f"{label} invalid mapping_lane: {lane}")
    require_false_boundary(entry, label)

    package = entry.get("detection_package")
    if not isinstance(package, str) or not rel_path(root, package, "detection_package").exists():
        fail(f"{label} missing detection_package: {package}")

    xml_path = entry.get("wazuh_rule_path")
    expected_rule_ids = [int(value) for value in entry.get("expected_rule_ids") or []]
    expected_groups = {str(value) for value in entry.get("expected_groups") or []}
    expected_mitre_ids = {str(value) for value in entry.get("expected_mitre_ids") or []}

    if lane == "wazuh_rule_source":
        if not isinstance(xml_path, str) or not xml_path:
            fail(f"{label} wazuh_rule_path is required for source entries")
        full_xml_path = rel_path(root, xml_path, "wazuh_rule_path")
        if not full_xml_path.exists():
            fail(f"{label} missing wazuh_rule_path: {xml_path}")
        rules = parse_wazuh_xml(full_xml_path)
        actual_rule_ids = {rule["id"] for rule in rules}
        missing_rule_ids = set(expected_rule_ids) - actual_rule_ids
        if missing_rule_ids:
            fail(f"{label} expected Wazuh rule ids missing: {sorted(missing_rule_ids)}")
        actual_groups = set().union(*(rule["groups"] for rule in rules))
        missing_groups = expected_groups - actual_groups
        if missing_groups:
            fail(f"{label} expected Wazuh groups missing: {sorted(missing_groups)}")
        actual_mitre_ids = set().union(*(rule["mitre_ids"] for rule in rules))
        missing_mitre = expected_mitre_ids - actual_mitre_ids
        if missing_mitre:
            fail(f"{label} expected MITRE ids missing: {sorted(missing_mitre)}")
        normalized_group = detection_id.lower()
        if normalized_group not in actual_groups:
            fail(f"{label} Wazuh groups must include normalized detection id {normalized_group}")
        for rule_id in actual_rule_ids:
            owner = seen_rule_ids.get(rule_id)
            if owner and owner != detection_id:
                fail(f"duplicate Wazuh rule id {rule_id}: {owner} and {detection_id}")
            seen_rule_ids[rule_id] = detection_id
    else:
        if xml_path:
            fail(f"{label} non-source entries must not reference wazuh_rule_path")
        if expected_rule_ids:
            fail(f"{label} non-source entries must not declare expected_rule_ids")
    return entry


def verify_dashboard_needs(registry: dict[str, Any]) -> None:
    needs = registry.get("dashboard_private_runtime_needs", [])
    if not isinstance(needs, list):
        fail("dashboard_private_runtime_needs must be a list")
    seen: set[str] = set()
    for need in needs:
        if not isinstance(need, dict):
            fail("dashboard_private_runtime_needs entries must be mappings")
        need_id = str(need.get("need_id", "")).strip()
        if not need_id:
            fail("dashboard need missing need_id")
        if need_id in seen:
            fail(f"duplicate dashboard need_id: {need_id}")
        seen.add(need_id)
        tile = need.get("dashboard_tile")
        if tile not in ALLOWED_DASHBOARD_TILES:
            fail(f"{need_id} invalid dashboard_tile: {tile}")
        if not need.get("authority_anchor"):
            fail(f"{need_id} missing authority_anchor")
        require_false_boundary(need, need_id)


def verify_repo(root: Path = ROOT, print_summary: bool = True) -> list[dict[str, Any]]:
    registry = load_registry(root / "detections" / "wazuh" / "WAZUH_RULE_SOURCE_REGISTRY.yml")
    if registry.get("registry_status") != ALLOWED_REGISTRY_STATUS:
        fail("registry_status must be WAZUH_RULE_SOURCE_CONTRACT_ENFORCED")
    if registry.get("proof_ceiling") != ALLOWED_PROOF_CEILING:
        fail("proof_ceiling must preserve source/static CI boundary")
    require_false_boundary(registry, "registry")
    entries = registry.get("entries")
    if not isinstance(entries, list) or not entries:
        fail("registry entries must be a non-empty list")
    seen_detection_ids: set[str] = set()
    seen_rule_ids: dict[int, str] = {}
    verified = []
    for entry in entries:
        if not isinstance(entry, dict):
            fail("registry entries must be mappings")
        detection_id = str(entry.get("detection_id", "")).strip()
        if detection_id in seen_detection_ids:
            fail(f"duplicate detection_id: {detection_id}")
        seen_detection_ids.add(detection_id)
        verified.append(verify_entry(root, entry, seen_rule_ids))
    verify_dashboard_needs(registry)
    if print_summary:
        print(f"WAZUH_RULE_SOURCE_REGISTRY=pass entries={len(verified)} wazuh_rule_ids={len(seen_rule_ids)}")
    return verified


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify HawkinsOperations Wazuh rule source registry.")
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        verify_repo(args.root)
    except WazuhRuleSourceError as exc:
        print(f"WAZUH_RULE_SOURCE_REGISTRY=fail: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
