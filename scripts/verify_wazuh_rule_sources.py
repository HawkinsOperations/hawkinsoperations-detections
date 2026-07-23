#!/usr/bin/env python3
"""Verify Wazuh rule-source registry boundaries and XML metadata."""

from __future__ import annotations

import argparse
import copy
import re
import sys
import unicodedata
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
ALLOWED_ENTRY_LANE_CONTRACTS = {
    "wazuh_rule_source": (
        "SOURCE_EXISTS",
        "wazuh_candidate_after_controlled_fixture",
    ),
    "wazuh_rule_source_planned": (
        "WAZUH_SOURCE_NEEDED",
        "wazuh_candidate_after_controlled_fixture",
    ),
    "wazuh_rule_source_conditional": (
        "CONDITIONAL_SOURCE_PLANNED",
        "wazuh_candidate_after_telemetry_normalization",
    ),
    "private_runtime_design_only": (
        "DESIGN_ONLY",
        "cribl_splunk_preferred_wazuh_host_context_only",
    ),
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
ALLOWED_DASHBOARD_STATUS = "PRIVATE_DASHBOARD_DESIGN_ONLY"
ALLOWED_AUTHORITY_ANCHORS = frozenset(
    {
        "Wazuh audit tuning backlog",
        "HO-PIPE-001",
        "ho-runner-01 private runtime need",
        "2026-06-01 private Wazuh audit",
    }
)
ROOT_KEYS = frozenset(
    {
        "schema_version",
        "registry_status",
        "proof_ceiling",
        "public_safe_status",
        "runtime_status",
        "signal_status",
        "entries",
        "dashboard_private_runtime_needs",
    }
)
ENTRY_KEYS = frozenset(
    {
        "detection_id",
        "mapping_lane",
        "status",
        "detection_package",
        "wazuh_rule_path",
        "expected_rule_ids",
        "expected_groups",
        "expected_mitre_ids",
        "preferred_runtime",
        "runtime_status",
        "signal_status",
        "public_safe_status",
        "notes",
    }
)
DASHBOARD_NEED_KEYS = frozenset(
    {
        "need_id",
        "dashboard_tile",
        "authority_anchor",
        "status",
        "runtime_status",
        "signal_status",
        "public_safe_status",
        "notes",
    }
)
BOUNDARY_FIELD_SUFFIXES = (
    "runtimestatus",
    "runtimeactive",
    "runtimeproof",
    "signalstatus",
    "signalobserved",
    "signalproof",
    "publicsafestatus",
    "publicsafe",
    "publicsaferuntime",
    "aidispositionauthority",
    "aiauthority",
    "aiapproval",
    "aiapproved",
    "analystdispositionauthority",
    "analystapproval",
    "analystapproved",
    "finalauthorization",
    "finalauthority",
    "caseclosure",
    "caseclosed",
    "productionready",
    "productionactive",
    "customerdeployment",
    "customerdeployed",
    "socaasdeployment",
    "socaasdeployed",
)
AFFIRMATIVE_CLAIM_PATTERNS = (
    re.compile(r"\bpublic[\s_-]*safe(?:[\s_-]*(?:approved|true|yes))?\b"),
    re.compile(r"\bruntime[\s_-]*active\b"),
    re.compile(r"\bsignal[\s_-]*observed\b"),
    re.compile(r"\bproduction[\s_-]*ready\b"),
    re.compile(r"\bcustomer[\s_-]*(?:deployed|deployment)\b"),
    re.compile(r"\bsocaas[\s_-]*(?:deployed|deployment)\b"),
    re.compile(r"\bai[\s_-]*approved\b"),
    re.compile(r"\banalyst[\s_-]*approved\b"),
    re.compile(r"\bfinal[\s_-]*authori[sz](?:ation|ed)\b"),
    re.compile(r"\bcase[\s_-]*(?:closed|closure)\b"),
)
BOUNDED_AUTHORITY_STRINGS = frozenset(
    {
        "",
        "blocked",
        "disabled",
        "false",
        "no",
        "none",
        "not claimed",
        "not proven",
        "not public safe",
        "not_public_safe",
        "null",
    }
)
PACKAGE_METADATA_FILES = ("status.yml", "rule.yml", "event-mapping.yml")


class WazuhRuleSourceError(Exception):
    """Wazuh source registry violation."""


def fail(message: str) -> None:
    raise WazuhRuleSourceError(message)


def truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() not in FALSEY
    return value not in FALSEY


def normalized_key(value: str) -> str:
    return re.sub(
        r"[^a-z0-9]",
        "",
        unicodedata.normalize("NFKC", value).casefold(),
    )


def is_bounded_authority_value(value: Any) -> bool:
    if value is False or value is None:
        return True
    if type(value) is str:
        normalized = unicodedata.normalize("NFKC", value).strip().casefold()
        return normalized in BOUNDED_AUTHORITY_STRINGS
    return False


def scan_authority_boundaries(
    value: Any,
    label: str = "registry",
    key_path: tuple[str, ...] = (),
) -> None:
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                fail(f"{label} mapping keys must be strings")
            token = normalized_key(key)
            item_key_path = (*key_path, token)
            joined_path = "".join(item_key_path[-4:])
            if any(joined_path.endswith(suffix) for suffix in BOUNDARY_FIELD_SUFFIXES):
                if not is_bounded_authority_value(item):
                    fail(f"{label}.{key} contains unsupported authority promotion")
            scan_authority_boundaries(item, f"{label}.{key}", item_key_path)
        return
    if type(value) is list:
        for index, item in enumerate(value):
            scan_authority_boundaries(item, f"{label}[{index}]", key_path)
        return
    if type(value) is str:
        normalized = unicodedata.normalize("NFKC", value).strip().casefold()
        if is_bounded_authority_value(value):
            return
        if any(pattern.search(normalized) for pattern in AFFIRMATIVE_CLAIM_PATTERNS):
            fail(f"{label} contains unsupported affirmative authority claim")


def require_exact_keys(value: dict[Any, Any], expected: frozenset[str], label: str) -> None:
    non_string = [key for key in value if type(key) is not str]
    if non_string:
        fail(f"{label} keys must be strings: {non_string!r}")
    actual = set(value)
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if missing:
        fail(f"{label} missing required keys: {missing}")
    if unknown:
        fail(f"{label} contains unknown keys: {unknown}")


def require_exact_type(value: Any, expected: type, label: str) -> None:
    if type(value) is not expected:
        fail(f"{label} must be {expected.__name__}")


def require_string_list(value: Any, label: str) -> list[str]:
    require_exact_type(value, list, label)
    if any(type(item) is not str for item in value):
        fail(f"{label} entries must be strings")
    seen: dict[str, str] = {}
    for item in value:
        if item.strip() != item or unicodedata.normalize("NFKC", item) != item:
            fail(f"{label} entries must use canonical text: {item!r}")
        normalized = unicodedata.normalize("NFKC", item).casefold()
        prior = seen.get(normalized)
        if prior is not None:
            fail(f"{label} contains duplicate normalized value: {prior!r} and {item!r}")
        seen[normalized] = item
    return value


def require_integer_list(value: Any, label: str) -> list[int]:
    require_exact_type(value, list, label)
    if any(type(item) is not int for item in value):
        fail(f"{label} entries must be integers")
    if len(set(value)) != len(value):
        fail(f"{label} contains duplicate values")
    return value


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects exact and normalized duplicate keys."""


UniqueKeyLoader.yaml_implicit_resolvers = copy.deepcopy(
    yaml.SafeLoader.yaml_implicit_resolvers
)
for resolver_key, resolvers in list(UniqueKeyLoader.yaml_implicit_resolvers.items()):
    UniqueKeyLoader.yaml_implicit_resolvers[resolver_key] = [
        resolver
        for resolver in resolvers
        if resolver[0] != "tag:yaml.org,2002:timestamp"
    ]


def _construct_unique_mapping(
    loader: UniqueKeyLoader, node: yaml.nodes.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    normalized_string_keys: dict[str, str] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError:
            fail(f"unhashable YAML mapping key at line {key_node.start_mark.line + 1}")
        if duplicate:
            fail(f"duplicate YAML key {key!r} at line {key_node.start_mark.line + 1}")
        if isinstance(key, str):
            normalized = unicodedata.normalize("NFKC", key).casefold()
            prior = normalized_string_keys.get(normalized)
            if prior is not None:
                fail(
                    "duplicate YAML key after NFKC/casefold normalization "
                    f"{key!r} aliases {prior!r} at line {key_node.start_mark.line + 1}"
                )
            normalized_string_keys[normalized] = key
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def rel_path(root: Path, value: str, field: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        fail(f"{field} must be repo-relative: {value}")
    return root / path


def load_registry(path: Path = REGISTRY_PATH) -> dict[str, Any]:
    try:
        data = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    except FileNotFoundError:
        fail(f"missing Wazuh rule source registry: {path}")
    except yaml.YAMLError as exc:
        fail(f"invalid Wazuh rule source registry YAML: {exc}")
    if not isinstance(data, dict):
        fail("Wazuh rule source registry root must be a mapping")
    return data


def load_package_metadata(path: Path, label: str) -> dict[str, Any]:
    try:
        data = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    except (OSError, UnicodeError) as exc:
        fail(f"{label} could not be read: {exc}")
    except yaml.YAMLError as exc:
        fail(f"{label} is invalid YAML: {exc}")
    if type(data) is not dict:
        fail(f"{label} must be a mapping")
    return data


def verify_detection_package(root: Path, detection_id: str, value: str) -> Path:
    if (
        unicodedata.normalize("NFKC", detection_id) != detection_id
        or re.fullmatch(r"HO-(?:DET|PIPE)-[0-9]{3}", detection_id) is None
    ):
        fail(f"{detection_id or 'registry entry'} detection_id is not canonical")
    slug = detection_id.casefold()
    expected_relative = f"detections/successor/{slug}"
    if value != expected_relative:
        fail(
            f"{detection_id} detection_package must equal canonical path "
            f"{expected_relative}: {value}"
        )

    successor_root = root / "detections" / "successor"
    package_path = root / Path(expected_relative)
    try:
        successor_resolved = successor_root.resolve(strict=True)
        package_resolved = package_path.resolve(strict=True)
    except OSError as exc:
        fail(f"{detection_id} detection_package cannot be resolved: {exc}")
    if package_path.is_symlink():
        fail(f"{detection_id} detection_package must not be a symlink or junction")
    if not package_path.is_dir():
        fail(f"{detection_id} detection_package must be a directory")
    if package_resolved.parent != successor_resolved or package_resolved.name != slug:
        fail(f"{detection_id} detection_package escapes canonical package root")

    for filename in PACKAGE_METADATA_FILES:
        metadata_path = package_path / filename
        try:
            metadata_resolved = metadata_path.resolve(strict=True)
        except OSError as exc:
            fail(f"{detection_id} missing package metadata {filename}: {exc}")
        if metadata_path.is_symlink():
            fail(f"{detection_id} package metadata must not be a symlink: {filename}")
        if not metadata_path.is_file() or metadata_resolved.parent != package_resolved:
            fail(f"{detection_id} package metadata escapes package: {filename}")
        metadata = load_package_metadata(
            metadata_path,
            f"{detection_id} {filename}",
        )
        metadata_id = metadata.get("detection_id")
        if type(metadata_id) is not str or metadata_id != detection_id:
            fail(
                f"{detection_id} package metadata detection_id mismatch in {filename}: "
                f"{metadata_id!r}"
            )
    return package_path


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
    require_exact_keys(entry, ENTRY_KEYS, "registry entry")
    for field in (
        "detection_id",
        "mapping_lane",
        "status",
        "detection_package",
        "preferred_runtime",
        "public_safe_status",
        "notes",
    ):
        require_exact_type(entry[field], str, f"registry entry {field}")
    for field in ("runtime_status", "signal_status"):
        require_exact_type(entry[field], bool, f"registry entry {field}")
    if entry["wazuh_rule_path"] is not None and type(entry["wazuh_rule_path"]) is not str:
        fail("registry entry wazuh_rule_path must be a string or null")
    expected_rule_ids = require_integer_list(
        entry["expected_rule_ids"],
        "registry entry expected_rule_ids",
    )
    expected_groups = set(
        require_string_list(entry["expected_groups"], "registry entry expected_groups")
    )
    expected_mitre_ids = set(
        require_string_list(
            entry["expected_mitre_ids"],
            "registry entry expected_mitre_ids",
        )
    )

    detection_id = entry["detection_id"]
    if detection_id.strip() != detection_id:
        fail("registry entry detection_id is not canonical")
    if not detection_id:
        fail("registry entry missing detection_id")
    label = detection_id
    if detection_id.startswith("ID-DET-") and str(entry.get("preferred_runtime", "")).lower().startswith("wazuh"):
        fail("identity detections must not be forced to Wazuh without identity telemetry normalization")

    lane = entry.get("mapping_lane")
    if lane not in ALLOWED_MAPPING_LANES:
        fail(f"{label} invalid mapping_lane: {lane}")
    expected_status, expected_runtime = ALLOWED_ENTRY_LANE_CONTRACTS[lane]
    if entry["status"] != expected_status:
        fail(f"{label} invalid status for {lane}: {entry['status']}")
    if entry["preferred_runtime"] != expected_runtime:
        fail(
            f"{label} invalid preferred_runtime for {lane}: "
            f"{entry['preferred_runtime']}"
        )
    require_false_boundary(entry, label)

    package = entry["detection_package"]
    package_path = verify_detection_package(root, detection_id, package)

    xml_path = entry.get("wazuh_rule_path")

    if lane == "wazuh_rule_source":
        if not isinstance(xml_path, str) or not xml_path:
            fail(f"{label} wazuh_rule_path is required for source entries")
        expected_xml_path = f"{package}/wazuh.xml"
        if xml_path != expected_xml_path:
            fail(
                f"{label} wazuh_rule_path must equal canonical package XML "
                f"{expected_xml_path}: {xml_path}"
            )
        full_xml_path = package_path / "wazuh.xml"
        try:
            package_resolved = package_path.resolve(strict=True)
            xml_resolved = full_xml_path.resolve(strict=True)
        except OSError as exc:
            fail(f"{label} missing wazuh_rule_path: {exc}")
        if full_xml_path.is_symlink():
            fail(f"{label} wazuh_rule_path must not be a symlink or junction")
        if not full_xml_path.is_file() or xml_resolved.parent != package_resolved:
            fail(f"{label} wazuh_rule_path escapes canonical detection package")
        rules = parse_wazuh_xml(full_xml_path)
        actual_rule_ids = [rule["id"] for rule in rules]
        duplicate_rule_ids = sorted(
            rule_id for rule_id in set(actual_rule_ids) if actual_rule_ids.count(rule_id) > 1
        )
        if duplicate_rule_ids:
            fail(f"{label} duplicate Wazuh rule id in {xml_path}: {duplicate_rule_ids}")
        actual_rule_id_set = set(actual_rule_ids)
        expected_rule_id_set = set(expected_rule_ids)
        missing_rule_ids = expected_rule_id_set - actual_rule_id_set
        unexpected_rule_ids = actual_rule_id_set - expected_rule_id_set
        if missing_rule_ids:
            fail(f"{label} expected Wazuh rule ids missing: {sorted(missing_rule_ids)}")
        if unexpected_rule_ids:
            fail(f"{label} unexpected Wazuh rule ids present: {sorted(unexpected_rule_ids)}")
        actual_groups = set().union(*(rule["groups"] for rule in rules))
        missing_groups = expected_groups - actual_groups
        if missing_groups:
            fail(f"{label} expected Wazuh groups missing: {sorted(missing_groups)}")
        actual_mitre_ids = set().union(*(rule["mitre_ids"] for rule in rules))
        missing_mitre = expected_mitre_ids - actual_mitre_ids
        if missing_mitre:
            fail(f"{label} expected MITRE ids missing: {sorted(missing_mitre)}")
        unexpected_mitre = actual_mitre_ids - expected_mitre_ids
        if unexpected_mitre:
            fail(f"{label} unexpected MITRE ids present: {sorted(unexpected_mitre)}")
        normalized_group = detection_id.lower()
        if normalized_group not in actual_groups:
            fail(f"{label} Wazuh groups must include normalized detection id {normalized_group}")
        for rule_id in actual_rule_id_set:
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
    needs = registry["dashboard_private_runtime_needs"]
    require_exact_type(needs, list, "dashboard_private_runtime_needs")
    seen: set[str] = set()
    for need in needs:
        if type(need) is not dict:
            fail("dashboard_private_runtime_needs entries must be mappings")
        require_exact_keys(need, DASHBOARD_NEED_KEYS, "dashboard need")
        for field in (
            "need_id",
            "dashboard_tile",
            "authority_anchor",
            "status",
            "public_safe_status",
            "notes",
        ):
            require_exact_type(need[field], str, f"dashboard need {field}")
        for field in ("runtime_status", "signal_status"):
            require_exact_type(need[field], bool, f"dashboard need {field}")
        need_id = need["need_id"]
        if (
            need_id.strip() != need_id
            or unicodedata.normalize("NFKC", need_id) != need_id
            or re.fullmatch(r"[A-Z0-9]+(?:-[A-Z0-9]+)+", need_id) is None
        ):
            fail(f"dashboard need_id is not canonical: {need_id!r}")
        if not need_id:
            fail("dashboard need missing need_id")
        normalized_need_id = normalized_key(need_id)
        if normalized_need_id in seen:
            fail(f"duplicate dashboard need_id: {need_id}")
        seen.add(normalized_need_id)
        tile = need.get("dashboard_tile")
        if tile not in ALLOWED_DASHBOARD_TILES:
            fail(f"{need_id} invalid dashboard_tile: {tile}")
        if need["status"] != ALLOWED_DASHBOARD_STATUS:
            fail(f"{need_id} invalid dashboard status: {need['status']}")
        if need["authority_anchor"] not in ALLOWED_AUTHORITY_ANCHORS:
            fail(f"{need_id} invalid authority_anchor: {need['authority_anchor']}")
        require_false_boundary(need, need_id)


def verify_repo(root: Path = ROOT, print_summary: bool = True) -> list[dict[str, Any]]:
    registry = load_registry(root / "detections" / "wazuh" / "WAZUH_RULE_SOURCE_REGISTRY.yml")
    scan_authority_boundaries(registry)
    require_exact_keys(registry, ROOT_KEYS, "registry")
    require_exact_type(registry["schema_version"], int, "registry schema_version")
    for field in (
        "registry_status",
        "proof_ceiling",
        "public_safe_status",
    ):
        require_exact_type(registry[field], str, f"registry {field}")
    for field in ("runtime_status", "signal_status"):
        require_exact_type(registry[field], bool, f"registry {field}")
    require_exact_type(registry["entries"], list, "registry entries")
    require_exact_type(
        registry["dashboard_private_runtime_needs"],
        list,
        "registry dashboard_private_runtime_needs",
    )
    if registry["schema_version"] != 1:
        fail("registry schema_version must be 1")
    if registry.get("registry_status") != ALLOWED_REGISTRY_STATUS:
        fail("registry_status must be WAZUH_RULE_SOURCE_CONTRACT_ENFORCED")
    if registry.get("proof_ceiling") != ALLOWED_PROOF_CEILING:
        fail("proof_ceiling must preserve source/static CI boundary")
    require_false_boundary(registry, "registry")
    entries = registry.get("entries")
    if not entries:
        fail("registry entries must be a non-empty list")
    seen_detection_ids: set[str] = set()
    seen_rule_ids: dict[int, str] = {}
    verified = []
    for entry in entries:
        if type(entry) is not dict:
            fail("registry entries must be mappings")
        detection_id = entry.get("detection_id")
        if type(detection_id) is not str:
            fail("registry entry detection_id must be str")
        detection_id = detection_id.strip()
        normalized_detection_id = normalized_key(detection_id)
        if normalized_detection_id in seen_detection_ids:
            fail(f"duplicate detection_id: {detection_id}")
        seen_detection_ids.add(normalized_detection_id)
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
