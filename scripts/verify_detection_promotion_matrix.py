#!/usr/bin/env python3
"""Verify and inventory the detection promotion matrix as source truth."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import unicodedata
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import unquote

import yaml

ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "detections" / "DETECTION_PROMOTION_MATRIX.yml"
INDEX_PATH = ROOT / "detections" / "DETECTION_FACTORY_INDEX.md"
def sanitized_git_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.casefold().startswith("git_")
    }
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment["GIT_TERMINAL_PROMPT"] = "0"
    return environment

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

EXPECTED_STATUS_VALIDATION = {
    "CONTROLLED_TEST_VALIDATED_IN_VALIDATION_REPO": "CONTROLLED_TEST_VALIDATED",
    "VALIDATION_CONTRACT_ENFORCED_IN_VALIDATION_REPO": "VALIDATION_CONTRACT_ENFORCED",
    "VALIDATION_PLANNED": "VALIDATION_PLANNED",
}

ROOT_FIELDS = {
    "schema_version",
    "owner_repo",
    "truth_surface",
    "enforcement_status",
    "human_review_required",
    "claim_boundary",
    "allowed_status_values",
    "ledger_boundary",
    "ledger_eligibility_status_values",
    "detection_side_ledger_eligibility",
    "reviewer_expansion_map",
    "entries",
}

EXPECTED_OWNER_REPO = "hawkinsoperations-detections"
EXPECTED_VALIDATION_OWNER = "hawkinsoperations-validation"
EXPECTED_PROOF_OWNER = "hawkinsoperations-proof"
EXPECTED_TRUTH_SURFACE = "detection_source"

CANONICAL_ID_RE = re.compile(
    r"^(?:HOD|HO-DET|ID-DET|AWS-DET|HO-NDR|HO-PIPE)-\d{3}$"
)
URI_RE = re.compile(r"^(planned|external)://([a-z0-9-]+)/(.+)$")
ENCODED_PATH_TOKEN_RE = re.compile(r"%(?:2e|2f|5c|25)", re.IGNORECASE)
WINDOWS_DRIVE_RE = re.compile(r"^[a-zA-Z]:")

STATUS_SOURCE_FIELDS = {
    "canonical_detection_source": "rule.yml",
    "canonical_rule_source": "rule.yml",
    "canonical_sigma_source": "rule.yml",
    "canonical_splunk_source": "splunk.spl",
    "canonical_wazuh_source": "wazuh.xml",
    "canonical_event_mapping": "event-mapping.yml",
}

BACKEND_REQUIRED_FILES = {
    "generic_yaml_source_record": {"rule.yml"},
    "cloudtrail_json_fixture": {"rule.yml", "cloudtrail.jsonpath"},
}

SOURCE_CONTRACT_FILENAMES = {
    "rule.yml",
    "status.yml",
    "event-mapping.yml",
    "splunk.spl",
    "wazuh.xml",
    "cloudtrail.jsonpath",
    "cribl-pipeline.yml",
    "field-preservation-matrix.yml",
}

DOCUMENT_ALLOWED_FIELDS = {
    "rule.yml": {
        "allowed_claim", "approval_status", "author", "backend_target",
        "blocked_claims", "claim_ceiling", "core_argument", "current_scope",
        "data_source", "date", "description", "detection", "detection_id",
        "evidence_linked", "evidence_linked_public_proof", "falsepositives",
        "future_gated_phases", "id", "level", "logic_summary", "logsource",
        "mapped_fields", "mitre_attack", "modified", "name", "next_proof_gate",
        "next_validation_gate", "not_claimed_here", "objective",
        "promotion_boundaries", "proof_level", "proof_status",
        "public_safe_status", "references", "related_reference",
        "runtime_active", "signal_observed", "socaas_pilot_decomposition",
        "source_assumptions", "status", "supported_claim", "tags", "title",
        "trust_class", "tuning_guidance", "validation_fixture_boundary",
        "validation_status",
    },
    "status.yml": {
        "allowed_claims", "aws_live_proof", "blocked_claims",
        "canonical_case_packet", "canonical_claim_boundary_scanner",
        "canonical_detection_source", "canonical_event_mapping",
        "canonical_platform_case_packet_sample",
        "canonical_platform_case_packet_schema",
        "canonical_platform_case_packet_verifier", "canonical_proof_record",
        "canonical_readme", "canonical_result_parity_verifier",
        "canonical_rule_source", "canonical_sigma_source",
        "canonical_splunk_source", "canonical_validation_cases",
        "canonical_validation_report", "canonical_validation_result",
        "canonical_validation_script", "canonical_validation_workflow",
        "canonical_wazuh_source", "canonical_wazuh_static_contract_lab",
        "canonical_wazuh_static_contract_verifier", "claim_ceiling",
        "cloudtrail_live_proof", "cribl_status", "current_scope",
        "detection_id", "event_mapping_status", "evidence_linked_public_proof",
        "false_positive_negative_count", "fixtures_in_detections_repo",
        "future_gated_phases", "human_review_required",
        "matched_positive_count", "missed_positive_count", "mitre_attack",
        "negative_count", "next_gate", "not_claimed_here",
        "planned_platform_case_packet_guardrail", "planned_proof_record",
        "planned_validation_fixture_set", "planned_validation_repo_scope",
        "planned_website_surface", "platform_case_packet_guardrail_status",
        "positive_count", "proof_level", "proof_record_path",
        "proof_record_pending", "proof_status", "public_or_routed_signal_status",
        "public_route_pending", "public_safe_status", "rule_source_status",
        "runtime_active", "runtime_active_status", "runtime_evidence_status",
        "sigma_source_status", "signal_observed", "socaas_pilot_receipt_flow",
        "socaas_receipt_source_truth", "source_refs", "source_status",
        "splunk_source_status", "splunk_status", "supported_claims",
        "telemetry_sources", "trust_class", "truth_surface", "tuning_focus",
        "tuning_status", "validation_contract", "validation_count",
        "validation_enforcement_merge_commit", "validation_enforcement_pr",
        "validation_enforcement_status", "validation_false_positive_negatives",
        "validation_matched_positive_count", "validation_missed_positives",
        "validation_negative_cases", "validation_positive_cases",
        "validation_result", "validation_scope", "validation_status",
        "validation_total_cases", "wazuh_source_status", "wazuh_status",
    },
    "event-mapping.yml": {
        "adapter_fields", "adapter_result_labels", "backend_notes",
        "blocked_claims", "claim_boundary", "description", "detection_id",
        "fields", "mapping_scope", "mapping_status", "mitre_attack",
        "normalized_fields", "proof_boundary", "required_preserved_fields",
        "service_and_process_targets", "source_family", "sources",
        "splunk_fields", "tamper_categories", "telemetry_boundary",
        "telemetry_correction", "telemetry_sources", "truth_surface",
        "tuning_fields", "validation_fixture_boundary", "validation_status",
        "wazuh_fields",
    },
}

NESTED_FALSE_ONLY_FIELDS = {
    "runtime_active",
    "signal_observed",
    "ai_disposition_authority",
    "ai_decided_disposition",
    "analyst_approved",
    "analyst_disposition_authority",
    "final_authorization",
    "case_closed",
    "case_closure",
}

NESTED_NOT_PUBLIC_SAFE_FIELDS = {"public_safe_status"}

AFFIRMATIVE_AUTHORITY_CLAIM_RE = re.compile(
    r"(?:"
    r"\b(?:customer|socaas)\b.{0,48}\bdeploy(?:ed|ment|ing)?\b"
    r"|\bdeploy(?:ed|ment|ing)?\b.{0,48}\b(?:customer|socaas)\b"
    r"|\bproduction\b.{0,32}\b(?:active|confirmed|deployed|live|ready)\b"
    r"|\b(?:ai|analyst)\b.{0,40}\b(?:approval|authority|disposition)\b.{0,24}\b(?:approved|enabled|granted)\b"
    r"|\b(?:ai|analyst)\b.{0,40}\b(?:approved|authori[sz]ed)\b.{0,24}\b(?:case|decision|disposition)\b"
    r"|\bfinal\s+authori[sz]ation\b.{0,32}\b(?:approved|complete|granted|received)\b"
    r"|\bcase\s+closure\b.{0,32}\b(?:approved|complete|granted|received)\b"
    r"|\bcase\b.{0,16}\b(?:is|was)?\s*closed\b"
    r"|\bpublic[\s_-]*safe\b.{0,32}\b(?:approved|confirmed|established|release|runtime\s+proof)\b"
    r"|\bruntime\b.{0,24}\b(?:active|live)\b"
    r"|\bsignal\b.{0,24}\b(?:active|observed)\b"
    r")",
    re.IGNORECASE,
)
NEGATED_AUTHORITY_CONTEXT_RE = re.compile(
    r"\b(?:blocked|denied|false|future|not|never|no|pending|prohibited|"
    r"reject(?:ed|s)?|requires?\s+separate|remain(?:s)?\s+(?:a\s+)?separate|unsupported|without)\b",
    re.IGNORECASE,
)
AUTHORITY_STRONG_CLAUSE_SPLIT_RE = re.compile(
    r"[;:/\r\n—–]+|\b(?:but|however|although|yet|while|whereas)\b|(?<=[.!?])\s+",
    re.IGNORECASE,
)
NEGATIVE_LIST_INTRO_RE = re.compile(
    r"\b(?:does|do|did|must|is|are|was|were|can|cannot|could|should|will|would)\s+not\s+"
    r"(?:prove|establish|claim|promote|authorize|assert)\b|\bwithout\s+claiming\b",
    re.IGNORECASE,
)
AFFIRMATIVE_STATE_AFTER_NEGATIVE_LIST_RE = re.compile(
    r"(?:"
    r"\b(?:customer|socaas)\b.{0,32}\b(?:deployment\s+)?(?:is|was)\s+"
    r"(?:active|confirmed|deployed|live|ready)\b"
    r"|\b(?:customer|socaas)\b.{0,32}\b(?:is|was)\s+deployed\b"
    r"|\bproduction\b.{0,24}\b(?:is|was)\s+(?:active|live|ready)\b"
    r"|\bruntime\b.{0,16}\b(?:is|was)\s+active\b"
    r"|\bsignal\b.{0,16}\b(?:is|was)\s+observed\b"
    r"|\bpublic[\s_-]*safe\b.{0,24}\b(?:is|was)\s+"
    r"(?:approved|confirmed|established|ready|released)\b"
    r"|\b(?:ai|analyst)\b.{0,32}\b(?:(?:is|was)\s+approved|approval\s+(?:is\s+)?granted|authority\s+(?:is\s+)?enabled)\b"
    r"|\bfinal\s+authori[sz]ation\b.{0,16}\b(?:is|was)?\s*(?:approved|granted|received)\b"
    r"|\bcase\s+closure\b.{0,16}\b(?:is|was)?\s*(?:approved|complete|granted|received)\b"
    r"|\bcase\b.{0,16}\b(?:is|was)\s+closed\b"
    r")",
    re.IGNORECASE,
)
NEGATIVE_LIST_SUFFIX_RE = re.compile(
    r"\bclaims?\s+(?:remain|remains|are|is)\s+(?:blocked|unsupported|not\s+approved)\.?$",
    re.IGNORECASE,
)
EXACT_BOUNDED_AUTHORITY_PROSE = {
    "dry-run reviewer proof/ledger route without claiming live idp, runtime, or public-safe proof.",
    "dry-run reviewer proof/ledger route without claiming live idp, runtime, completeness, or public-safe proof.",
}


def normalize_authority_security_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value).translate(
        {ord("\t"): " ", ord("\n"): " ", ord("\r"): " "}
    )
    return "".join(
        character
        for character in normalized
        if not unicodedata.category(character).startswith(("C", "M"))
    )


def contains_unnegated_affirmative_state(value: str) -> bool:
    return any(
        not NEGATED_AUTHORITY_CONTEXT_RE.search(value[:match.start()])
        for match in AFFIRMATIVE_STATE_AFTER_NEGATIVE_LIST_RE.finditer(value)
    )


def contains_unsupported_affirmative_authority_claim(value: str) -> bool:
    """Bind negation to the same clause as the authority wording it bounds."""
    normalized = normalize_authority_security_text(value)
    if normalized.strip().casefold() in EXACT_BOUNDED_AUTHORITY_PROSE:
        return False
    for segment in AUTHORITY_STRONG_CLAUSE_SPLIT_RE.split(normalized):
        if not segment.strip():
            continue
        intro = NEGATIVE_LIST_INTRO_RE.search(segment)
        suffix = NEGATIVE_LIST_SUFFIX_RE.search(segment)
        if suffix:
            if AFFIRMATIVE_STATE_AFTER_NEGATIVE_LIST_RE.search(
                segment[:suffix.start()]
            ):
                return True
            continue
        if intro:
            if (
                AFFIRMATIVE_STATE_AFTER_NEGATIVE_LIST_RE.search(
                    segment[intro.end():]
                )
            ):
                return True
            continue
        clauses = segment.split(",")
        if any(
            contains_unnegated_affirmative_state(clause)
            or (
                AFFIRMATIVE_AUTHORITY_CLAIM_RE.search(clause)
                and not NEGATED_AUTHORITY_CONTEXT_RE.search(clause)
            )
            for clause in clauses
            if clause.strip()
        ):
            return True
    return False


def contains_unbounded_forbidden_claim_term(value: str) -> bool:
    """Require blocked claim terms to be bounded inside their own semantic clause."""
    normalized = normalize_authority_security_text(value)
    if normalized.strip().casefold() in EXACT_BOUNDED_AUTHORITY_PROSE:
        return False
    return any(
        any(term.casefold() in clause.casefold() for term in FORBIDDEN_CLAIM_TERMS)
        and not ALLOWED_CLAIM_CONTEXT_RE.search(clause)
        for clause in AUTHORITY_STRONG_CLAUSE_SPLIT_RE.split(normalized)
        if clause.strip()
    )


def is_safe_blocked_claim_leaf(value: str) -> bool:
    return not re.search(
        r"\b(?:is|was|has|enabled|granted|received)\b",
        unicodedata.normalize("NFKC", value),
        re.IGNORECASE,
    )

VALIDATION_STATUS_VALUES = {
    "CONTROLLED_TEST_VALIDATED_IN_VALIDATION_REPO",
    "VALIDATION_CONTRACT_ENFORCED_IN_VALIDATION_REPO",
    "VALIDATION_PLANNED",
}

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
    r"does not|do not|did not|does_not_support|does-not-prove|"
    r"not proof|not public-safe|not runtime|not signal|no proof|no public-safe|no runtime|no signal|"
    r"out of scope|excluded|without claiming|must not|no live|no .*claim|proof remains|"
    r"not promote|does not promote|source-only|source truth only)"
)
POSITIVE_PROMOTION_RE = re.compile(r"(?i)\b(now has|has|is|are|supports|promotes|promoted)\b")


class MatrixError(Exception):
    """Raised when the promotion matrix is not enforceable."""


def fail(message: str) -> None:
    raise MatrixError(message)


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that fails rather than silently replacing duplicate keys."""


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
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError:
            fail(f"unhashable YAML mapping key at line {key_node.start_mark.line + 1}")
        if duplicate:
            fail(f"duplicate YAML key {key!r} at line {key_node.start_mark.line + 1}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def semantic_fingerprint(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def git_output(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        check=False,
        env=sanitized_git_environment(),
    )
    return result.stdout.strip() if result.returncode == 0 else "UNRESOLVED"


def git_blob_sha(root: Path, path: Path, *, at_head: bool) -> str:
    relative = rel(path, root)
    if at_head:
        return git_output(root, "rev-parse", f"HEAD:{relative}")
    return git_output(root, "hash-object", f"--path={relative}", relative)


def semantic_file_fingerprint(path: Path) -> str:
    suffix = path.suffix.casefold()
    if suffix in {".yml", ".yaml"}:
        return semantic_fingerprint(load_yaml(path))
    if suffix == ".json":
        try:
            value = json.loads(
                path.read_text(encoding="utf-8"),
                object_pairs_hook=_unique_json_pairs,
            )
        except (json.JSONDecodeError, UnicodeError, ValueError) as exc:
            fail(f"invalid JSON for semantic fingerprint {path.name}: {exc}")
        return semantic_fingerprint(value)
    normalized = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(normalized).hexdigest()


def semantic_fingerprint_method(path: Path) -> str:
    return (
        "canonical-json-sha256"
        if path.suffix.casefold() in {".yml", ".yaml", ".json"}
        else "normalized-lf-bytes-sha256"
    )


def _unique_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def repository_state(root: Path) -> dict[str, str]:
    """Return source revision metadata without mutating repository state."""

    status = git_output(root, "status", "--porcelain")
    status_lines = [] if status == "UNRESOLVED" else status.splitlines()
    meaningful_status = [
        line for line in status_lines
        if "__pycache__/" not in line.replace("\\", "/") and not line.rstrip().endswith(".pyc")
    ]
    worktree_clean = not meaningful_status if status != "UNRESOLVED" else False
    return {
        "repository": "hawkinsoperations-detections",
        "authority_role": "detection_source",
        "resolved_ref": git_output(root, "branch", "--show-current"),
        "source_commit_sha": git_output(root, "rev-parse", "HEAD"),
        "worktree_clean": worktree_clean,
        "source_freshness_state": "CURRENT" if worktree_clean else "WORKTREE_MODIFIED_OR_UNRESOLVED",
    }


def decode_path(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        fail(f"{label} must be a non-empty string")
    decoded = value.strip()
    for _ in range(4):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    if ENCODED_PATH_TOKEN_RE.search(decoded):
        fail(f"{label} contains unresolved encoded path syntax")
    if "\x00" in decoded:
        fail(f"{label} contains a NUL byte")
    return decoded


def canonical_relative_path(value: str, label: str) -> str:
    decoded = decode_path(value, label)
    if "\\" in decoded:
        fail(f"{label} must use canonical forward slashes")
    if (
        decoded.startswith(("/", "\\"))
        or decoded.startswith("//")
        or WINDOWS_DRIVE_RE.match(decoded)
        or PureWindowsPath(decoded).is_absolute()
        or PurePosixPath(decoded).is_absolute()
    ):
        fail(f"{label} must remain repository-relative")
    parts = decoded.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        fail(f"{label} contains a traversal or empty path segment")
    return "/".join(parts)


def repo_relative_path(root: Path, value: str, label: str) -> Path:
    """Resolve a repository-owned path and fail closed on escape attempts."""
    canonical = canonical_relative_path(value, label)
    path = Path(*canonical.split("/"))
    resolved_root = root.resolve()
    resolved = (resolved_root / path).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError:
        fail(f"{label} escapes the detections repository")
    return resolved


def package_ownership_key(root: Path, package_path: str) -> str:
    """Normalize path aliases using Windows ownership semantics."""
    if is_local_path(package_path):
        canonical = canonical_relative_path(package_path, "package_path")
        repo_relative_path(root, canonical, "package_path")
        return canonical.casefold()
    scheme, owner, relative = parse_authority_uri(package_path, "package_path")
    return f"{scheme}://{owner}/{relative}".casefold()


def parse_authority_uri(value: str, label: str) -> tuple[str, str, str]:
    decoded = decode_path(value, label)
    if "\\" in decoded:
        fail(f"{label} URI must use canonical forward slashes")
    match = URI_RE.fullmatch(decoded)
    if not match:
        fail(f"{label} must be a canonical planned:// or external:// URI")
    scheme, owner, relative = match.groups()
    relative = canonical_relative_path(relative, label)
    return scheme, owner, relative


def load_yaml(path: Path) -> Any:
    try:
        return yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    except yaml.YAMLError as exc:
        try:
            display = rel(path, ROOT)
        except ValueError:
            display = path.name
        fail(f"invalid YAML parse: {display} ({exc})")


def ensure_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be a mapping")
    return value


def ensure_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        fail(f"{label} must be a list")
    return value


def ensure_bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        fail(f"{label} must be a boolean")
    return value


def ensure_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        fail(f"{label} must be a non-empty string")
    return value.strip()


def ensure_exact_keys(
    value: dict[str, Any],
    required: set[str],
    label: str,
    *,
    optional: set[str] | None = None,
) -> None:
    optional = optional or set()
    missing = sorted(required - set(value))
    unknown = sorted(set(value) - required - optional)
    if missing:
        fail(f"{label} missing required fields: {', '.join(missing)}")
    if unknown:
        fail(f"{label} contains unsupported fields: {', '.join(unknown)}")


def normalize_authority_key(value: str) -> str:
    decoded = value
    for _ in range(4):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return re.sub(r"[^a-z0-9]", "", unicodedata.normalize("NFKC", decoded).casefold())


def is_compositional_promotion_key(key: str) -> bool:
    return (
        ("production" in key and any(part in key for part in ("active", "live", "ready", "deploy", "state", "status")))
        or (any(part in key for part in ("customer", "socaas")) and any(part in key for part in ("active", "deploy", "state", "status")))
        or ("runtime" in key and any(part in key for part in ("active", "state", "status")))
        or ("signal" in key and any(part in key for part in ("observed", "state", "status")))
        or ("publicsafe" in key and "count" not in key)
        or ("final" in key and any(part in key for part in ("authoriz", "authority")))
        or ("case" in key and "count" not in key and any(part in key for part in ("closed", "closure", "state", "status")))
        or any(part in key for part in ("approvalstate", "approvalstatus", "closurestatus", "casestate", "casestatus"))
        or (
            key.startswith(("ai", "analyst"))
            and any(part in key for part in ("approved", "approval", "authority", "disposition"))
        )
        or ("review" in key and "disposition" in key)
    )


def is_explicitly_bounded_authority_value(value: Any) -> bool:
    if isinstance(value, list) and len(value) == 1:
        return is_explicitly_bounded_authority_value(value[0])
    if value is False or value is None or value == 0:
        return True
    if not isinstance(value, str):
        return False
    normalized = normalize_authority_key(value)
    return normalized in {
        "blocked",
        "false",
        "humanreviewrequired",
        "missing",
        "none",
        "notapproved",
        "notauthorized",
        "notclosed",
        "notproven",
        "notpublicsafe",
        "notruntimeactive",
        "open",
        "partial",
        "pending",
        "existingflowcandidate",
        "privateruntimeboundarycontextonly",
        "privateruntimeevidencecaptured",
        "privateruntimeevidencecapturedlocalwindowsonly",
        "runtimeevidenceverifiedprivate",
        "runtimeactiveprivate",
        "signalobservedprivate",
        "satisfiednonpromotionalboundary",
        "sourceexists",
        "unsupported",
    }


def scan_nested_authority(
    value: Any,
    label: str,
    normalized_path: tuple[str, ...] = (),
    promotion_context: bool = False,
) -> None:
    """Reject hidden authority promotion at any depth in structured source metadata."""
    if isinstance(value, dict):
        for raw_key, nested in value.items():
            if not isinstance(raw_key, str):
                fail(f"{label} contains a non-string mapping key")
            key = normalize_authority_key(raw_key)
            nested_label = f"{label}.{raw_key}"
            child_normalized_path = (*normalized_path, key)
            cumulative_keys = {key}
            cumulative_keys.update(
                f"{segment}{key}"
                for segment in normalized_path
                if segment
                in {
                    "runtime",
                    "signal",
                    "public",
                    "approval",
                    "production",
                    "customer",
                    "socaas",
                    "ai",
                    "analyst",
                    "review",
                    "final",
                    "case",
                }
            )
            child_promotion_context = promotion_context or any(
                is_compositional_promotion_key(candidate)
                for candidate in cumulative_keys
            )
            if (
                not isinstance(nested, (dict, list))
                and child_promotion_context
                and not is_explicitly_bounded_authority_value(nested)
            ):
                fail(f"{nested_label} attempts compositional authority promotion")
            if (
                not isinstance(nested, (dict, list))
                and key
                in {normalize_authority_key(item) for item in NESTED_FALSE_ONLY_FIELDS}
            ):
                allowed_false = nested is False or nested == [False]
                if not allowed_false:
                    fail(f"{nested_label} attempts unsupported authority promotion")
            if (
                not isinstance(nested, (dict, list))
                and key
                in {
                    normalize_authority_key(item)
                    for item in NESTED_NOT_PUBLIC_SAFE_FIELDS
                }
            ):
                allowed = (
                    nested == "NOT_PUBLIC_SAFE"
                    or nested == ["NOT_PUBLIC_SAFE"]
                )
                if not allowed:
                    fail(f"{nested_label} must remain NOT_PUBLIC_SAFE")
            if key == normalize_authority_key("human_review_required") and nested is not True:
                fail(f"{nested_label} must remain true")
            if key in {
                normalize_authority_key("approval_status"),
                normalize_authority_key("authorization_status"),
            }:
                allowed = {"NOT_APPROVED", "BLOCKED", "PENDING", "HUMAN_REVIEW_REQUIRED"}
                if not isinstance(nested, str) or nested.upper() not in allowed:
                    fail(f"{nested_label} contains unsupported approval state")
            scan_nested_authority(
                nested,
                nested_label,
                child_normalized_path,
                child_promotion_context,
            )
        return
    if isinstance(value, list):
        for index, nested in enumerate(value):
            scan_nested_authority(
                nested,
                f"{label}[{index}]",
                normalized_path,
                promotion_context,
            )
        return
    if promotion_context and not is_explicitly_bounded_authority_value(value):
        fail(f"{label} attempts compositional authority promotion")
    if isinstance(value, str):
        normalized_label = normalize_authority_key(label)
        exact_blocked_claim_leaf = (
            any(
                marker in normalized_label
                for marker in (
                    "blockedclaims",
                    "blockedwording",
                    "claimsnotsupported",
                    "doesnotsupport",
                    "notclaimedhere",
                )
            )
            and normalize_authority_key(label.rsplit("[", 1)[0]).endswith(
                (
                    "blockedclaims",
                    "blockedwording",
                    "claimsnotsupported",
                    "doesnotsupport",
                    "notclaimedhere",
                )
            )
            and not re.search(
                r"\b(?:is|was|has|enabled|granted|received)\b",
                value,
                re.IGNORECASE,
            )
        )
        if (
            contains_unsupported_affirmative_authority_claim(value)
            and not exact_blocked_claim_leaf
        ) or (
            contains_unbounded_forbidden_claim_term(value)
            and not exact_blocked_claim_leaf
        ):
            fail(f"{label} contains an unsupported affirmative authority claim")
        return
    if value is None or type(value) in {int, float, bool}:
        return
    fail(f"{label} contains unsupported value type {type(value).__name__}")


def canonical_detection_id(value: Any, label: str) -> str:
    detection_id = ensure_string(value, label)
    if not CANONICAL_ID_RE.fullmatch(detection_id):
        fail(f"{label} must be a canonical uppercase detection ID")
    return detection_id


def read_detection_id_from_yaml(path: Path, root: Path) -> str | None:
    data = load_yaml(path)
    if isinstance(data, dict):
        allowed = DOCUMENT_ALLOWED_FIELDS.get(path.name)
        if allowed is not None:
            unknown = sorted(set(data) - allowed)
            if unknown:
                fail(
                    f"{rel(path, root)} contains unsupported top-level fields: "
                    f"{', '.join(unknown)}"
                )
            scan_nested_authority(data, rel(path, root))
        detection_id = data.get("detection_id")
        if isinstance(detection_id, str) and detection_id.strip():
            return canonical_detection_id(detection_id, f"{rel(path, root)}.detection_id")
        artifact_id = data.get("artifact_id")
        if isinstance(artifact_id, str) and artifact_id.strip():
            return canonical_detection_id(artifact_id, f"{rel(path, root)}.artifact_id")
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
    normalized_ids: dict[str, str] = {}
    normalized_paths: dict[str, str] = {}
    for family, package_dir in iter_package_dirs(root):
        detection_id = package_detection_id(family, package_dir, root)
        id_key = detection_id.casefold()
        path_key = rel(package_dir.resolve(), root.resolve()).replace("\\", "/").casefold()
        if id_key in normalized_ids:
            previous_id = normalized_ids[id_key]
            fail(
                f"duplicate package detection_id alias {detection_id}: "
                f"{rel(out[previous_id], root)} and {rel(package_dir, root)}"
            )
        if path_key in normalized_paths:
            fail(
                f"duplicate normalized package path {rel(package_dir, root)} "
                f"for {normalized_paths[path_key]} and {detection_id}"
            )
        out[detection_id] = package_dir
        normalized_ids[id_key] = detection_id
        normalized_paths[path_key] = detection_id
    return out


def verify_reverse_source_inventory(
    root: Path,
    packages: dict[str, Path],
    matrix_paths: dict[str, str],
) -> None:
    package_roots = {
        path.resolve(): detection_id for detection_id, path in packages.items()
    }
    detections_root = root / "detections"
    for family in PACKAGE_FAMILIES:
        family_root = detections_root / family
        if not family_root.exists():
            continue
        for source in family_root.rglob("*"):
            if not source.is_file() or source.name not in SOURCE_CONTRACT_FILENAMES:
                continue
            owner = package_roots.get(source.parent.resolve())
            if owner is None:
                fail(
                    f"orphaned detection source file outside an indexed package: "
                    f"{rel(source, root)}"
                )
            declared_path = matrix_paths.get(owner)
            if declared_path is None:
                fail(f"source package {owner} exists but matrix entry is missing")
            expected_parent = repo_relative_path(
                root, declared_path, f"{owner} package_path"
            )
            if source.parent.resolve() != expected_parent.resolve():
                fail(
                    f"source file ownership mismatch for {rel(source, root)}: "
                    f"package={owner}"
                )


def factory_index_ids(root: Path) -> set[str]:
    if not (root / INDEX_PATH.relative_to(ROOT)).exists():
        fail("missing detections/DETECTION_FACTORY_INDEX.md")
    ids: set[str] = set()
    normalized: dict[str, str] = {}
    for raw in (root / INDEX_PATH.relative_to(ROOT)).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line.startswith("|"):
            continue
        parts = [p.strip().strip("`") for p in line.strip("|").split("|")]
        if not parts:
            continue
        candidate = parts[0]
        if re.fullmatch(INDEX_ID_RE.pattern, candidate, re.IGNORECASE):
            if not INDEX_ID_RE.fullmatch(candidate):
                fail(f"factory index contains noncanonical detection ID: {candidate}")
            key = candidate.casefold()
            if key in normalized and normalized[key] != candidate:
                fail(f"factory index contains case-folded detection ID alias: {candidate}")
            normalized[key] = candidate
            ids.add(candidate)
    return ids


def verify_factory_ledger_table(
    root: Path, expected_buckets: dict[str, list[str]]
) -> None:
    index_path = root / INDEX_PATH.relative_to(ROOT)
    text = index_path.read_text(encoding="utf-8")
    section_match = re.search(
        r"(?ms)^## Detection-Side Ledger Eligibility\s*(.+?)(?=^## )",
        text,
    )
    if not section_match:
        fail("factory index is missing Detection-Side Ledger Eligibility section")
    rendered: dict[str, set[str]] = {}
    for raw in section_match.group(1).splitlines():
        line = raw.strip()
        if not line.startswith("|") or "---" in line or "Ledger eligibility" in line:
            continue
        parts = [part.strip() for part in line.strip("|").split("|")]
        if len(parts) < 2:
            continue
        status = parts[0].strip("`")
        if status not in ALLOWED_LEDGER_ELIGIBILITY_STATUS:
            continue
        cell = parts[1]
        ids = set(re.findall(r"`((?:HOD|HO-DET|ID-DET|AWS-DET|HO-NDR|HO-PIPE)-\d{3})`", cell))
        if status in rendered:
            fail(f"factory index duplicates ledger eligibility row {status}")
        rendered[status] = ids
    for bucket, status in LEDGER_ELIGIBILITY_BUCKETS.items():
        expected = set(expected_buckets[bucket])
        actual = rendered.get(status)
        if actual is None:
            fail(f"factory index missing ledger eligibility row {status}")
        if actual != expected:
            fail(
                f"factory index {status} disagrees with matrix: "
                f"expected={sorted(expected)}, actual={sorted(actual)}"
            )


def verify_factory_current_states(
    root: Path, entries: list[dict[str, Any]]
) -> None:
    index_path = root / INDEX_PATH.relative_to(ROOT)
    text = index_path.read_text(encoding="utf-8")
    section_match = re.search(
        r"(?ms)^## Detection Factory Matrix\s*(.+?)(?=^## )",
        text,
    )
    if not section_match:
        fail("factory index is missing Detection Factory Matrix section")
    rendered: dict[str, str] = {}
    for raw in section_match.group(1).splitlines():
        line = raw.strip()
        if not line.startswith("|") or "---" in line or "| ID |" in line:
            continue
        parts = [part.strip() for part in line.strip("|").split("|")]
        if len(parts) < 6:
            continue
        if re.fullmatch(CANONICAL_ID_RE.pattern, parts[0], re.IGNORECASE) and not CANONICAL_ID_RE.fullmatch(parts[0]):
            fail(f"factory matrix contains noncanonical detection ID: {parts[0]}")
        if not CANONICAL_ID_RE.fullmatch(parts[0]):
            continue
        detection_id = parts[0]
        state = parts[5].strip("`")
        if detection_id in rendered:
            fail(f"factory matrix duplicates detection row {detection_id}")
        rendered[detection_id] = state

    for entry in entries:
        detection_id = entry["detection_id"]
        if detection_id == "HOD-001":
            continue
        if entry["source_status"] == "VALIDATION_PLANNED":
            expected = "VALIDATION_PLANNED"
        elif detection_id == "HO-NDR-001":
            expected = "BOUNDARY_CONTRACT_ONLY"
        elif detection_id == "HO-PIPE-001":
            expected = "SOURCE_EXISTS"
        elif (
            entry["validation_status_if_known"]
            == "CONTROLLED_TEST_VALIDATED_IN_VALIDATION_REPO"
        ):
            expected = "CONTROLLED_TEST_VALIDATED"
        else:
            expected = entry["source_status"]
        actual = rendered.get(detection_id)
        if actual != expected:
            fail(
                f"factory matrix current state disagrees for {detection_id}: "
                f"expected={expected}, actual={actual}"
            )


def load_external_yaml(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        fail(f"{label} is missing: {path}")
    try:
        data = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        fail(f"{label} cannot be parsed: {exc}")
    return ensure_mapping(data, label)


def load_strict_json(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        fail(f"{label} is missing: {path}")
    try:
        data = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_pairs,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        fail(f"{label} cannot be parsed: {exc}")
    return ensure_mapping(data, label)


def canonical_repository_origin(value: str) -> str:
    normalized = value.strip().rstrip("/").casefold()
    if normalized.startswith("git@github.com:"):
        normalized = "https://github.com/" + normalized.removeprefix(
            "git@github.com:"
        )
    elif normalized.startswith("ssh://git@github.com/"):
        normalized = "https://github.com/" + normalized.removeprefix(
            "ssh://git@github.com/"
        )
    if not normalized.endswith(".git"):
        normalized += ".git"
    return normalized


def stored_repository_origin(repo_root: Path, label: str) -> str:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(repo_root),
            "config",
            "--local",
            "--get-all",
            "remote.origin.url",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=sanitized_git_environment(),
    )
    values = [value.strip() for value in result.stdout.splitlines()]
    if result.returncode != 0 or len(values) != 1 or not values[0]:
        fail(f"{label} stored origin must contain exactly one nonempty local URL")
    return values[0]


def external_repo_root(path: Path, expected_repo: str, label: str) -> Path:
    resolved = path.resolve()
    for parent in (resolved.parent, *resolved.parents):
        if parent.name.casefold() == expected_repo.casefold():
            if parent.name != expected_repo:
                fail(f"{label} repository directory must preserve canonical owner case")
            try:
                inside = subprocess.run(
                    ["git", "-C", str(parent), "rev-parse", "--is-inside-work-tree"],
                    check=True,
                    capture_output=True,
                    text=True,
                    env=sanitized_git_environment(),
                ).stdout.strip()
                origin = stored_repository_origin(parent, label)
                dirty = subprocess.run(
                    ["git", "-C", str(parent), "status", "--porcelain", "--untracked-files=no"],
                    check=True,
                    capture_output=True,
                    text=True,
                    env=sanitized_git_environment(),
                ).stdout.strip()
            except subprocess.CalledProcessError as exc:
                fail(f"{label} owner root is not a verifiable Git repository: {exc}")
            if inside != "true":
                fail(f"{label} owner root is not a Git worktree")
            expected_origin = (
                f"https://github.com/HawkinsOperations/{expected_repo}.git"
            )
            if canonical_repository_origin(origin) != canonical_repository_origin(
                expected_origin
            ):
                fail(f"{label} repository origin is not canonical: {origin}")
            if dirty:
                fail(f"{label} authority repository has tracked dirty state")
            return parent
    fail(f"{label} is not owned by {expected_repo}")


def verify_validation_handoffs(
    entries: list[dict[str, Any]], registry_path: Path, detection_root: Path
) -> None:
    registry = load_external_yaml(registry_path, "validation registry")
    if registry.get("owner_repo") != EXPECTED_VALIDATION_OWNER:
        fail("validation registry owner_repo is not canonical")
    if registry.get("truth_surface") != "controlled_validation":
        fail("validation registry truth_surface is not controlled_validation")
    if registry.get("human_review_required") is not True:
        fail("validation registry must require human review")
    if registry.get("ai_disposition_authority") is not False:
        fail("validation registry must deny AI disposition authority")
    validation_root = external_repo_root(
        registry_path, EXPECTED_VALIDATION_OWNER, "validation registry"
    )
    manifest_ref = registry.get("source_authority_manifest")
    if manifest_ref is None:
        fail("validation registry must declare source_authority_manifest")
    if manifest_ref is not None:
        manifest_relative = canonical_relative_path(
            ensure_string(manifest_ref, "source_authority_manifest"),
            "source_authority_manifest",
        )
        manifest_path = repo_relative_path(
            validation_root, manifest_relative, "source_authority_manifest"
        )
        manifest = load_strict_json(
            manifest_path, "validation source authority manifest"
        )
        expected_root = {
            "schema_version": 1,
            "owner_repo": EXPECTED_VALIDATION_OWNER,
            "source_owner": EXPECTED_OWNER_REPO,
            "truth_surface": "detection_to_validation_content_handoff",
            "matrix_path": "detections/DETECTION_PROMOTION_MATRIX.yml",
        }
        for field, expected_value in expected_root.items():
            if manifest.get(field) != expected_value:
                fail(
                    f"validation source authority manifest {field} mismatch: "
                    f"expected={expected_value}, actual={manifest.get(field)}"
                )
        matrix_path = detection_root / "detections" / "DETECTION_PROMOTION_MATRIX.yml"
        expected_matrix_blob = git_blob_sha(
            detection_root, matrix_path, at_head=True
        )
        expected_matrix_semantic = semantic_file_fingerprint(matrix_path)
        if manifest.get("matrix_git_blob_sha") != expected_matrix_blob:
            fail(
                "validation source authority manifest matrix blob is stale: "
                f"expected={expected_matrix_blob}, "
                f"actual={manifest.get('matrix_git_blob_sha')}"
            )
        if (
            manifest.get("matrix_semantic_fingerprint")
            != expected_matrix_semantic
        ):
            fail(
                "validation source authority manifest matrix semantic "
                "fingerprint is stale"
            )
        if (
            manifest.get("matrix_semantic_fingerprint_method")
            != semantic_fingerprint_method(matrix_path)
        ):
            fail(
                "validation source authority manifest matrix semantic "
                "fingerprint method is unsupported"
            )
        manifest_packages = ensure_list(
            manifest.get("packages"), "validation source authority packages"
        )
        by_manifest_id: dict[str, dict[str, Any]] = {}
        for raw in manifest_packages:
            item = ensure_mapping(raw, "validation source authority package")
            detection_id = canonical_detection_id(
                item.get("detection_id"),
                "validation source authority package detection_id",
            )
            if detection_id in by_manifest_id:
                fail(
                    f"validation source authority manifest duplicates "
                    f"{detection_id}"
                )
            by_manifest_id[detection_id] = item
        for entry in entries:
            if not is_local_path(str(entry["package_path"])):
                continue
            detection_id = entry["detection_id"]
            # Hero baseline does not declare a cross-repository source dependency.
            if detection_id == "HOD-001":
                continue
            manifest_item = by_manifest_id.get(detection_id)
            if manifest_item is None:
                fail(
                    f"validation source authority manifest omits {detection_id}"
                )
            if manifest_item.get("package_path") != entry["package_path"]:
                fail(
                    f"validation source authority package path mismatch for "
                    f"{detection_id}"
                )
            expected_files = []
            package_path = str(entry["package_path"])
            for relative_name in entry["required_files"]:
                source_relative = f"{package_path}/{relative_name}"
                source_path = repo_relative_path(
                    detection_root, source_relative, f"{detection_id} source"
                )
                expected_files.append(
                    {
                        "path": source_relative,
                        "git_blob_sha": git_blob_sha(
                            detection_root, source_path, at_head=True
                        ),
                        "semantic_fingerprint": semantic_file_fingerprint(
                            source_path
                        ),
                        "semantic_fingerprint_method": semantic_fingerprint_method(
                            source_path
                        ),
                    }
                )
            actual_files = manifest_item.get("required_files")
            if actual_files != sorted(
                expected_files, key=lambda item: item["path"].casefold()
            ):
                fail(
                    f"validation source authority file identities are stale "
                    f"for {detection_id}"
                )
        extra_manifest_ids = sorted(
            set(by_manifest_id)
            - {
                entry["detection_id"]
                for entry in entries
                if is_local_path(str(entry["package_path"]))
                and entry["detection_id"] != "HOD-001"
            }
        )
        if extra_manifest_ids:
            fail(
                "validation source authority manifest contains unknown source "
                f"packages: {', '.join(extra_manifest_ids)}"
            )
    packages = ensure_list(registry.get("packages"), "validation registry packages")
    by_id: dict[str, dict[str, Any]] = {}
    normalized_ids: set[str] = set()
    for raw in packages:
        package = ensure_mapping(raw, "validation registry package")
        detection_id = canonical_detection_id(
            package.get("detection_id"), "validation registry detection_id"
        )
        key = detection_id.casefold()
        if key in normalized_ids:
            fail(f"validation registry duplicates detection_id {detection_id}")
        normalized_ids.add(key)
        by_id[detection_id] = package
        validation_kind = package.get("validation_kind")
        for field in (
            "validation_package_path",
            "fixture_file",
            "report_json",
            "report_markdown",
            "validator_script",
        ):
            if (
                field in {"report_json", "report_markdown"}
                and validation_kind == "visibility_contract"
                and package.get(field) is None
            ):
                continue
            relative = canonical_relative_path(
                ensure_string(package.get(field), f"{detection_id}.{field}"),
                f"{detection_id}.{field}",
            )
            if not repo_relative_path(validation_root, relative, field).is_file() and field != "validation_package_path":
                fail(f"validation registry {detection_id}.{field} is missing")
            if field == "validation_package_path" and not repo_relative_path(
                validation_root, relative, field
            ).is_dir():
                fail(f"validation registry {detection_id}.{field} is missing")
        if validation_kind == "visibility_contract" and (
            (package.get("report_json") is None)
            != (package.get("report_markdown") is None)
        ):
            fail(
                f"{detection_id} visibility_contract reports must both exist or both remain null"
            )

    for entry in entries:
        detection_id = entry["detection_id"]
        status = entry["validation_status_if_known"]
        if status == "VALIDATION_PLANNED":
            continue
        if detection_id not in by_id:
            fail(f"{detection_id} claims validation status but has no registry package")
        package = by_id[detection_id]
        expected_kind = (
            {"visibility_contract", "controlled_validation"}
            if status == "VALIDATION_CONTRACT_ENFORCED_IN_VALIDATION_REPO"
            else {"controlled_validation", "baseline_contract"}
        )
        if package.get("validation_kind") not in expected_kind:
            fail(
                f"{detection_id} validation_kind disagrees with detection matrix: "
                f"{package.get('validation_kind')}"
            )
        if package.get("public_safe_status") != "NOT_PUBLIC_SAFE":
            fail(f"{detection_id} validation handoff must remain NOT_PUBLIC_SAFE")
        if package.get("runtime_status") is not False or package.get("signal_status") is not False:
            fail(f"{detection_id} validation handoff promotes runtime or signal")
        package_path = str(entry["package_path"])
        if bool(package.get("source_dependency_required")):
            expected_ref = f"{EXPECTED_OWNER_REPO}/{package_path}"
            if package.get("source_reference") != expected_ref:
                fail(
                    f"{detection_id} validation source_reference mismatch: "
                    f"expected {expected_ref}, got {package.get('source_reference')}"
                )


def verify_proof_handoffs(
    entries: list[dict[str, Any]],
    id_to_ledger_status: dict[str, str],
    proof_index_path: Path,
) -> None:
    proof_index = load_external_yaml(proof_index_path, "proof status index")
    if proof_index.get("owner_repo") != EXPECTED_PROOF_OWNER:
        fail("proof status index owner_repo is not canonical")
    if proof_index.get("truth_surface") != "proof_boundary_index":
        fail("proof status index truth_surface is not proof_boundary_index")
    proof_root = external_repo_root(
        proof_index_path, EXPECTED_PROOF_OWNER, "proof status index"
    )
    proof_entries = ensure_list(proof_index.get("entries"), "proof status index entries")
    by_id: dict[str, dict[str, Any]] = {}
    normalized_paths: dict[str, str] = {}
    for raw in proof_entries:
        item = ensure_mapping(raw, "proof status index entry")
        detection_id = canonical_detection_id(
            item.get("detection_id"), "proof status index detection_id"
        )
        if detection_id.casefold() in {value.casefold() for value in by_id}:
            fail(f"proof status index duplicates detection_id {detection_id}")
        by_id[detection_id] = item
        if item.get("source_truth_owner") != EXPECTED_OWNER_REPO:
            fail(f"{detection_id} proof handoff has a spoofed source owner")
        for field in ("proof_record_path", "proof_card_path"):
            path_value = item.get(field)
            if path_value is None:
                continue
            relative = canonical_relative_path(
                ensure_string(path_value, f"{detection_id}.{field}"),
                f"{detection_id}.{field}",
            )
            key = relative.casefold()
            if key in normalized_paths:
                fail(
                    f"proof artifact {relative} is shared by "
                    f"{normalized_paths[key]} and {detection_id}"
                )
            normalized_paths[key] = detection_id
            if not repo_relative_path(proof_root, relative, field).is_file():
                fail(f"{detection_id} proof handoff points to missing {field}")
        if item.get("public_safe_status") != "NOT_PUBLIC_SAFE":
            fail(f"{detection_id} proof handoff exceeds NOT_PUBLIC_SAFE")

    entry_ids = {entry["detection_id"] for entry in entries}
    for detection_id, ledger_status in id_to_ledger_status.items():
        if ledger_status != "PROOF_RECORDED":
            continue
        if detection_id == "HOD-001":
            legacy_path = (
                proof_root
                / "proof"
                / "records"
                / "PROOF-HOD-001-2026-04-21-001.json"
            )
            legacy = load_strict_json(
                legacy_path, "HOD-001 historical baseline proof record"
            )
            detection = ensure_mapping(
                legacy.get("detection"),
                "HOD-001 historical baseline proof record detection",
            )
            if detection.get("id") != "HOD-001":
                fail("HOD-001 historical baseline proof record identity mismatch")
            if not isinstance(legacy.get("created_at"), str):
                fail("HOD-001 historical baseline proof record must be point-in-time")
            continue
        if detection_id not in entry_ids or detection_id not in by_id:
            fail(f"{detection_id} proof-recorded handoff is missing from proof index")
        if not by_id[detection_id].get("proof_record_path"):
            fail(f"{detection_id} is PROOF_RECORDED but proof_record_path is null")


def is_local_path(package_path: str) -> bool:
    return "://" not in package_path


def scan_claim_lines(path: Path, root: Path) -> None:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for index, line in enumerate(lines):
        normalized_line = unicodedata.normalize("NFKC", line)
        lower = normalized_line.casefold()
        for term in FORBIDDEN_CLAIM_TERMS:
            term_index = lower.find(term.casefold())
            if term_index == -1:
                continue
            clause_start = max(
                normalized_line.rfind(";", 0, term_index),
                normalized_line.rfind(".", 0, term_index),
                normalized_line.rfind("!", 0, term_index),
                normalized_line.rfind("?", 0, term_index),
            )
            clause_end_candidates = [
                position
                for separator in ";.!?"
                if (position := normalized_line.find(separator, term_index)) != -1
            ]
            clause_end = min(clause_end_candidates, default=len(normalized_line))
            clause = normalized_line[clause_start + 1 : clause_end]
            bounded_structured_parent = False
            bounded_markdown_section = False
            bounded_markdown_list = False
            bounded_markdown_table = False
            bounded_markdown_paragraph = False
            bounded_xml_comment = False
            if path.suffix.casefold() in {".yml", ".yaml"}:
                child_indent = len(line) - len(line.lstrip())
                for parent_line in reversed(lines[:index]):
                    if not parent_line.strip() or parent_line.lstrip().startswith("#"):
                        continue
                    parent_indent = len(parent_line) - len(parent_line.lstrip())
                    if parent_indent >= child_indent:
                        continue
                    parent_match = re.fullmatch(
                        r"([A-Za-z0-9_-]+):\s*", parent_line.strip()
                    )
                    if parent_match:
                        bounded_structured_parent = (
                            normalize_authority_key(parent_match.group(1))
                            in {
                                normalize_authority_key("blocked_claims"),
                                normalize_authority_key("claims_not_supported"),
                                normalize_authority_key("does_not_support"),
                                normalize_authority_key("not_claimed_here"),
                            }
                        )
                    break
            elif path.suffix.casefold() == ".md":
                section_heading = ""
                for heading_line in reversed(lines[: index + 1]):
                    heading_match = re.fullmatch(r"\s*#{1,6}\s+(.+?)\s*", heading_line)
                    if heading_match:
                        section_heading = normalize_authority_key(
                            heading_match.group(1)
                        )
                        break
                stripped = normalized_line.strip()
                bounded_markdown_section = (
                    section_heading
                    in {
                        normalize_authority_key("Blocked Claims"),
                        normalize_authority_key("Out of Scope"),
                        normalize_authority_key("Not Claimed"),
                        normalize_authority_key("Claims Not Supported"),
                    }
                    and stripped.startswith("- ")
                    and is_safe_blocked_claim_leaf(stripped[2:])
                )
                list_label = ""
                for candidate in reversed(lines[:index]):
                    candidate_stripped = candidate.strip()
                    if not candidate_stripped or candidate_stripped.startswith("- "):
                        continue
                    list_label = normalize_authority_key(candidate_stripped)
                    break
                bounded_markdown_list = (
                    list_label
                    in {
                        normalize_authority_key("Blocked Claims"),
                        normalize_authority_key("Out of Scope"),
                        normalize_authority_key("Not Claimed"),
                        normalize_authority_key("Claims Not Supported"),
                    }
                    and stripped.startswith("- ")
                    and is_safe_blocked_claim_leaf(stripped[2:])
                )
                if stripped.startswith("|") and stripped.endswith("|"):
                    cells = [cell.strip() for cell in stripped.strip("|").split("|")]
                    term_cell_index = next(
                        (
                            cell_index
                            for cell_index, cell in enumerate(cells)
                            if term.casefold() in cell.casefold()
                        ),
                        None,
                    )
                    header_cells = None
                    for candidate in reversed(lines[:index]):
                        candidate_stripped = candidate.strip()
                        if not candidate_stripped.startswith("|"):
                            if header_cells is not None:
                                break
                            continue
                        candidate_cells = [
                            cell.strip()
                            for cell in candidate_stripped.strip("|").split("|")
                        ]
                        if all(
                            re.fullmatch(r":?-{3,}:?", cell) for cell in candidate_cells
                        ):
                            continue
                        header_cells = candidate_cells
                    if (
                        term_cell_index is not None
                        and header_cells is not None
                        and term_cell_index < len(header_cells)
                    ):
                        bounded_markdown_table = (
                            normalize_authority_key(header_cells[term_cell_index])
                            in {
                                normalize_authority_key("Blocked Claims"),
                                normalize_authority_key("Claims Not Supported"),
                                normalize_authority_key("Not Claimed"),
                            }
                            and is_safe_blocked_claim_leaf(cells[term_cell_index])
                        )
                paragraph_start = index
                while (
                    paragraph_start > 0
                    and lines[paragraph_start - 1].strip()
                    and not lines[paragraph_start - 1].lstrip().startswith("#")
                ):
                    paragraph_start -= 1
                paragraph_end = index
                while (
                    paragraph_end + 1 < len(lines)
                    and lines[paragraph_end + 1].strip()
                    and not lines[paragraph_end + 1].lstrip().startswith("#")
                ):
                    paragraph_end += 1
                paragraph = unicodedata.normalize(
                    "NFKC",
                    " ".join(lines[paragraph_start : paragraph_end + 1]),
                )
                paragraph_term_index = paragraph.casefold().find(term.casefold())
                if paragraph_term_index != -1:
                    paragraph_clause_start = max(
                        paragraph.rfind(";", 0, paragraph_term_index),
                        paragraph.rfind(".", 0, paragraph_term_index),
                        paragraph.rfind("!", 0, paragraph_term_index),
                        paragraph.rfind("?", 0, paragraph_term_index),
                    )
                    paragraph_clause_ends = [
                        position
                        for separator in ";.!?"
                        if (
                            position := paragraph.find(
                                separator, paragraph_term_index
                            )
                        )
                        != -1
                    ]
                    paragraph_clause_end = min(
                        paragraph_clause_ends, default=len(paragraph)
                    )
                    paragraph_clause = paragraph[
                        paragraph_clause_start + 1 : paragraph_clause_end
                    ]
                    bounded_markdown_paragraph = bool(
                        ALLOWED_CLAIM_CONTEXT_RE.search(paragraph_clause)
                    )
            elif path.suffix.casefold() == ".xml":
                before = "\n".join(lines[: index + 1])
                after = "\n".join(lines[index:])
                comment_start = before.rfind("<!--")
                comment_end = after.find("-->")
                if comment_start != -1 and comment_end != -1:
                    comment = (
                        before[comment_start + 4 :]
                        + "\n"
                        + after[:comment_end]
                    )
                    bounded_xml_comment = bool(
                        ALLOWED_CLAIM_CONTEXT_RE.search(
                            unicodedata.normalize("NFKC", comment)
                        )
                    )
            promotion_prefix = clause[max(0, clause.casefold().find(term.casefold()) - 80) :]
            if (
                POSITIVE_PROMOTION_RE.search(promotion_prefix)
                and not ALLOWED_CLAIM_CONTEXT_RE.search(clause)
                and not bounded_structured_parent
                and not bounded_markdown_section
                and not bounded_markdown_list
                and not bounded_markdown_table
                and not bounded_markdown_paragraph
                and not bounded_xml_comment
            ):
                fail(f"unbounded blocked claim term in {rel(path, root)}:{index + 1}: {term}")
            if (
                not ALLOWED_CLAIM_CONTEXT_RE.search(clause)
                and not bounded_structured_parent
                and not bounded_markdown_section
                and not bounded_markdown_list
                and not bounded_markdown_table
                and not bounded_markdown_paragraph
                and not bounded_xml_comment
            ):
                fail(f"unbounded blocked claim term in {rel(path, root)}:{index + 1}: {term}")


def scan_source_only_claims(package_dir: Path, root: Path) -> None:
    text_files = [
        p
        for p in package_dir.rglob("*")
        if p.is_file() and p.suffix.lower() in {".md", ".yml", ".yaml", ".spl", ".xml", ".jsonpath"}
    ]
    for path in text_files:
        if path.suffix.casefold() in {".yml", ".yaml"}:
            structured = ensure_mapping(
                load_yaml(path), f"{rel(path, root)} structured metadata"
            )
            scan_nested_authority(structured, rel(path, root))
        else:
            scan_claim_lines(path, root)


def scan_global_metadata_claims(root: Path) -> None:
    for relative_path in (MATRIX_PATH.relative_to(ROOT), INDEX_PATH.relative_to(ROOT)):
        path = root / relative_path
        if not path.exists():
            fail(f"missing global metadata file: {relative_path.as_posix()}")
        if path.suffix.casefold() in {".yml", ".yaml"}:
            scan_nested_authority(
                load_yaml(path), f"{rel(path, root)} structured metadata"
            )
        else:
            scan_claim_lines(path, root)


def verify_entry(entry: dict[str, Any], root: Path) -> tuple[str, str]:
    ensure_exact_keys(entry, REQUIRED_FIELDS, "matrix entry")
    detection_id = canonical_detection_id(
        entry.get("detection_id"), "matrix entry detection_id"
    )

    package_path = entry["package_path"]
    package_path = ensure_string(package_path, f"{detection_id}.package_path")
    family = ensure_string(entry["detection_family"], f"{detection_id}.detection_family")
    if family not in {"hero", "successor", "identity", "cloud", "ndr", "pipeline"}:
        fail(f"{detection_id} detection_family is unsupported: {family}")

    required_files = ensure_list(entry["required_files"], f"{detection_id}.required_files")
    if any(not isinstance(item, str) or not item.strip() for item in required_files):
        fail(f"{detection_id}.required_files must contain only non-empty strings")
    normalized_required = [
        canonical_relative_path(item, f"{detection_id} required file").casefold()
        for item in required_files
    ]
    if len(normalized_required) != len(set(normalized_required)):
        fail(f"{detection_id}.required_files must not contain duplicates")

    source_status = entry["source_status"]
    if not isinstance(source_status, str):
        fail(f"{detection_id} source_status must be a string")
    if source_status not in ALLOWED_SOURCE_STATUS:
        fail(f"{detection_id} source_status not allowed: {source_status}")
    if not isinstance(entry["proof_ceiling"], str) or entry["proof_ceiling"] not in ALLOWED_PROOF_CEILING:
        fail(f"{detection_id} proof_ceiling not allowed: {entry['proof_ceiling']}")
    if entry["public_safe_status"] != "NOT_PUBLIC_SAFE":
        fail(f"{detection_id} public_safe_status must be NOT_PUBLIC_SAFE")
    if ensure_bool(entry["runtime_active"], f"{detection_id}.runtime_active"):
        fail(f"{detection_id} runtime_active must remain false")
    if ensure_bool(entry["signal_observed"], f"{detection_id}.signal_observed"):
        fail(f"{detection_id} signal_observed must remain false")
    if entry["validation_expected_owner"] != EXPECTED_VALIDATION_OWNER:
        fail(
            f"{detection_id} validation_expected_owner must be "
            f"{EXPECTED_VALIDATION_OWNER}"
        )
    if entry["validation_status_if_known"] not in VALIDATION_STATUS_VALUES:
        fail(
            f"{detection_id} validation_status_if_known is unsupported: "
            f"{entry['validation_status_if_known']}"
        )
    if not isinstance(entry["next_gate"], str) or not entry["next_gate"].strip():
        fail(f"{detection_id} next_gate must be a non-empty string")
    if not isinstance(entry["notes"], str) or not entry["notes"].strip():
        fail(f"{detection_id} notes must be a non-empty string")

    blocked_claims = ensure_list(entry["blocked_claims"], f"{detection_id}.blocked_claims")
    if not blocked_claims or any(not isinstance(item, str) or not item.strip() for item in blocked_claims):
        fail(f"{detection_id}.blocked_claims must contain non-empty blocked claim strings")
    normalized_claims = [item.strip().casefold() for item in blocked_claims]
    if len(normalized_claims) != len(set(normalized_claims)):
        fail(f"{detection_id}.blocked_claims must not contain aliases or duplicates")
    expected_ceiling = {
        "SOURCE_EXISTS": "SOURCE_EXISTS",
        "BOUNDARY_CONTRACT_ONLY": "BOUNDARY_CONTRACT_ONLY",
        "EXTERNAL_BOUNDARY_CONTRACT": "BOUNDARY_CONTRACT_ONLY",
        "VALIDATION_PLANNED": "VALIDATION_PLANNED",
    }[source_status]
    if entry["proof_ceiling"] != expected_ceiling:
        fail(
            f"{detection_id} proof_ceiling exceeds or contradicts source_status: "
            f"expected {expected_ceiling}"
        )

    if is_local_path(package_path):
        package_path = canonical_relative_path(
            package_path, f"{detection_id} package_path"
        )
        package_dir = repo_relative_path(root, package_path, f"{detection_id} package_path")
        if not package_dir.exists():
            if source_status in LOCAL_SOURCE_STATUSES:
                fail(f"{detection_id} package path missing: {package_path}")
        elif not package_dir.is_dir():
            fail(f"{detection_id} package path is not a directory: {package_path}")

        if package_dir.exists():
            if source_status in LOCAL_SOURCE_STATUSES:
                required_by_family = {
                    "hero": {"rule.yml", "attack-mapping.json"},
                    "successor": {"rule.yml", "event-mapping.yml", "status.yml"},
                    "identity": {"rule.yml", "event-mapping.yml", "status.yml"},
                    "cloud": {"rule.yml", "status.yml"},
                }.get(str(entry["detection_family"]), {"rule.yml", "status.yml"})
                missing_contract_files = sorted(required_by_family - set(required_files))
                if missing_contract_files:
                    fail(
                        f"{detection_id} required_files omits source-contract files: "
                        f"{', '.join(missing_contract_files)}"
                    )
                if entry["detection_family"] == "cloud" and not {
                    "cloudtrail.jsonpath",
                    "event-mapping.yml",
                }.intersection(required_files):
                    fail(f"{detection_id} cloud package requires an event mapping or CloudTrail mapping")
            for required in required_files:
                required_path = repo_relative_path(package_dir, required, f"{detection_id} required file")
                if not required_path.exists():
                    fail(f"{detection_id} required file missing: {package_path}/{required}")
                if not required_path.is_file():
                    fail(f"{detection_id} required path is not a file: {package_path}/{required}")
            existing_contract_files = {
                path.name
                for path in package_dir.iterdir()
                if path.is_file() and path.name in SOURCE_CONTRACT_FILENAMES
            }
            orphaned = sorted(existing_contract_files - set(required_files))
            if orphaned:
                fail(
                    f"{detection_id} source contract files omitted from required_files: "
                    f"{', '.join(orphaned)}"
                )
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
            rule_path = package_dir / "rule.yml"
            if rule_path.exists():
                rule = ensure_mapping(load_yaml(rule_path), f"{detection_id} rule")
                scan_nested_authority(rule, f"{detection_id}.rule")
                backend_target = rule.get("backend_target")
                if backend_target is not None:
                    backend_target = ensure_string(
                        backend_target, f"{detection_id}.rule.backend_target"
                    )
                    if backend_target not in BACKEND_REQUIRED_FILES:
                        fail(
                            f"{detection_id} declares unsupported backend_target "
                            f"{backend_target}"
                        )
                    missing_backend = sorted(
                        BACKEND_REQUIRED_FILES[backend_target] - set(required_files)
                    )
                    if missing_backend:
                        fail(
                            f"{detection_id} backend_target {backend_target} requires "
                            f"{', '.join(missing_backend)}"
                        )
            status_path = package_dir / "status.yml"
            if status_path.exists():
                status = ensure_mapping(load_yaml(status_path), f"{detection_id} status")
                scan_nested_authority(status, f"{detection_id}.status")
                if status.get("source_status") != source_status:
                    fail(
                        f"{detection_id} source status disagreement: matrix={source_status}, "
                        f"status.yml={status.get('source_status')}"
                    )
                if status.get("public_safe_status") != "NOT_PUBLIC_SAFE":
                    fail(f"{detection_id} status.yml public_safe_status must be NOT_PUBLIC_SAFE")
                if truthy(status.get("runtime_active")):
                    fail(f"{detection_id} status.yml promotes runtime status")
                if truthy(status.get("signal_observed")):
                    fail(f"{detection_id} status.yml promotes signal status")
                expected_validation = EXPECTED_STATUS_VALIDATION.get(str(entry["validation_status_if_known"]))
                if expected_validation and status.get("validation_status") != expected_validation:
                    fail(
                        f"{detection_id} validation status disagreement: "
                        f"matrix={entry['validation_status_if_known']}, "
                        f"status.yml={status.get('validation_status')}"
                    )
                if not isinstance(status.get("blocked_claims"), list) or not status["blocked_claims"]:
                    fail(f"{detection_id} status.yml must preserve blocked_claims")
                for field, expected_name in STATUS_SOURCE_FIELDS.items():
                    if field not in status:
                        continue
                    source_ref = canonical_relative_path(
                        ensure_string(status[field], f"{detection_id}.{field}"),
                        f"{detection_id}.{field}",
                    )
                    expected_ref = f"{package_path}/{expected_name}"
                    if source_ref.casefold() != expected_ref.casefold():
                        fail(
                            f"{detection_id} {field} must reference {expected_ref}, "
                            f"got {source_ref}"
                        )
                    if source_ref != expected_ref:
                        fail(
                            f"{detection_id} {field} must preserve canonical path case"
                        )
                    if expected_name not in required_files:
                        fail(
                            f"{detection_id} {field} references undeclared backend "
                            f"{expected_name}"
                        )
                    if not repo_relative_path(root, source_ref, field).is_file():
                        fail(f"{detection_id} {field} points to a missing file")
            for metadata_name in ("event-mapping.yml", "cribl-pipeline.yml"):
                metadata_path = package_dir / metadata_name
                if metadata_path.exists():
                    metadata = ensure_mapping(
                        load_yaml(metadata_path), f"{detection_id} {metadata_name}"
                    )
                    scan_nested_authority(
                        metadata, f"{detection_id}.{metadata_name}"
                    )
            scan_source_only_claims(package_dir, root)
    else:
        scheme, owner, relative = parse_authority_uri(
            package_path, f"{detection_id} package_path"
        )
        package_path = f"{scheme}://{owner}/{relative}"
        if source_status not in PLANNED_OR_EXTERNAL_STATUSES:
            fail(f"{detection_id} non-local package paths must be planned or external")
        if scheme == "planned" and source_status != "VALIDATION_PLANNED":
            fail(f"{detection_id} planned URI requires VALIDATION_PLANNED")
        if scheme == "external":
            if source_status != "EXTERNAL_BOUNDARY_CONTRACT":
                fail(
                    f"{detection_id} external URI requires EXTERNAL_BOUNDARY_CONTRACT"
                )
            if owner != EXPECTED_VALIDATION_OWNER:
                fail(
                    f"{detection_id} external source owner must be "
                    f"{EXPECTED_VALIDATION_OWNER}"
                )
        if required_files:
            fail(f"{detection_id} non-local entries must not declare local required_files")

    scan_nested_authority(entry, f"matrix.entries[{detection_id}]")

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
            detection_id = canonical_detection_id(
                detection_id,
                f"matrix.detection_side_ledger_eligibility.{bucket}",
            )
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
        ensure_exact_keys(
            entry,
            REVIEWER_EXPANSION_REQUIRED_FIELDS,
            "reviewer expansion map entry",
        )
        detection_id = canonical_detection_id(
            entry.get("detection_id"), "reviewer expansion map detection_id"
        )
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


def verify_matrix_contract_header(matrix: dict[str, Any]) -> None:
    if matrix["schema_version"] != "phase2c-detection-promotion-matrix-v1":
        fail("matrix schema_version is unsupported")
    if matrix["enforcement_status"] != "SOURCE_CONTRACT_ENFORCED":
        fail("matrix enforcement_status is unsupported")
    claim_boundary = ensure_mapping(matrix["claim_boundary"], "claim_boundary")
    expected_claim_boundary = {
        "repo_truth_is_not_runtime_truth": True,
        "source_exists_is_not_validation": True,
        "validation_is_not_signal_observation": True,
        "website_rendering_is_not_proof": True,
        "proof_records_authorize_claim_ceilings": True,
        "public_safe_status": "NOT_PUBLIC_SAFE",
    }
    ensure_exact_keys(
        claim_boundary, set(expected_claim_boundary), "claim_boundary"
    )
    if claim_boundary != expected_claim_boundary:
        fail("matrix claim_boundary values are not canonical")

    allowed = ensure_mapping(
        matrix["allowed_status_values"], "allowed_status_values"
    )
    ensure_exact_keys(
        allowed,
        {"source_status", "public_safe_status", "runtime_active", "signal_observed"},
        "allowed_status_values",
    )
    if set(ensure_list(allowed["source_status"], "allowed source statuses")) != ALLOWED_SOURCE_STATUS:
        fail("allowed source_status values disagree with verifier")
    if allowed["public_safe_status"] != ["NOT_PUBLIC_SAFE"]:
        fail("allowed public_safe_status must contain only NOT_PUBLIC_SAFE")
    if allowed["runtime_active"] != [False] or allowed["signal_observed"] != [False]:
        fail("runtime and signal allowed values must contain only boolean false")

    ledger_boundary = ensure_mapping(matrix["ledger_boundary"], "ledger_boundary")
    ensure_exact_keys(
        ledger_boundary,
        {
            "detections_repo_scope",
            "canonical_lifetime_case_ledger_owner",
            "does_not_claim_canonical_ledger_state",
            "does_not_append_ledger_entries",
        },
        "ledger_boundary",
    )
    if (
        ledger_boundary["canonical_lifetime_case_ledger_owner"]
        != "hawkinsoperations-platform"
        or ledger_boundary["does_not_claim_canonical_ledger_state"] is not True
        or ledger_boundary["does_not_append_ledger_entries"] is not True
    ):
        fail("ledger_boundary attempts to exceed detection-source authority")
    statuses = ensure_list(
        matrix["ledger_eligibility_status_values"],
        "ledger_eligibility_status_values",
    )
    if len(statuses) != len(set(statuses)) or set(statuses) != ALLOWED_LEDGER_ELIGIBILITY_STATUS:
        fail("ledger eligibility status values disagree with verifier")


def verify_repo(
    root: Path = ROOT,
    print_summary: bool = True,
    *,
    validation_registry_path: Path | None = None,
    proof_index_path: Path | None = None,
    require_sibling_handoffs: bool = False,
) -> list[dict[str, Any]]:
    matrix_path = root / MATRIX_PATH.relative_to(ROOT)
    if not matrix_path.exists():
        fail("missing detections/DETECTION_PROMOTION_MATRIX.yml")
    matrix = ensure_mapping(load_yaml(matrix_path), "matrix root")
    ensure_exact_keys(matrix, ROOT_FIELDS, "matrix root")
    if matrix["owner_repo"] != EXPECTED_OWNER_REPO:
        fail(f"matrix owner_repo must be {EXPECTED_OWNER_REPO}")
    if matrix["truth_surface"] != EXPECTED_TRUTH_SURFACE:
        fail(f"matrix truth_surface must be {EXPECTED_TRUTH_SURFACE}")
    if matrix["human_review_required"] is not True:
        fail("matrix human_review_required must be true")
    verify_matrix_contract_header(matrix)
    scan_nested_authority(matrix, "matrix")
    entries = ensure_list(matrix.get("entries"), "matrix.entries")
    if not entries:
        fail("matrix.entries must not be empty")

    seen: dict[str, str] = {}
    seen_ids_casefold: dict[str, str] = {}
    seen_paths: dict[str, str] = {}
    normalized_entries: list[dict[str, Any]] = []
    for raw_entry in entries:
        entry = ensure_mapping(raw_entry, "matrix entry")
        detection_id, package_path = verify_entry(entry, root)
        id_key = detection_id.casefold()
        if id_key in seen_ids_casefold:
            fail(
                f"duplicate detection_id alias in matrix: "
                f"{seen_ids_casefold[id_key]} and {detection_id}"
            )
        ownership_key = package_ownership_key(root, package_path)
        if ownership_key in seen_paths:
            fail(
                f"duplicate package_path in matrix: {package_path} is owned by "
                f"{seen_paths[ownership_key]} and {detection_id}"
            )
        seen[detection_id] = package_path
        seen_ids_casefold[id_key] = detection_id
        seen_paths[ownership_key] = detection_id
        normalized_entries.append(copy.deepcopy(entry))

    id_to_status = verify_ledger_eligibility_map(matrix, set(seen))
    verify_reviewer_expansion_map(matrix, id_to_status)
    verify_factory_ledger_table(
        root,
        ensure_mapping(
            matrix["detection_side_ledger_eligibility"],
            "detection_side_ledger_eligibility",
        ),
    )
    verify_factory_current_states(root, normalized_entries)
    scan_global_metadata_claims(root)

    packages = package_ids(root)
    verify_reverse_source_inventory(root, packages, seen)
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
    missing_factory_rows = sorted((set(seen) - {"HOD-001"}) - index_ids)
    if missing_factory_rows:
        fail(
            f"matrix detection IDs missing from factory index: "
            f"{', '.join(missing_factory_rows)}"
        )

    if require_sibling_handoffs and (
        validation_registry_path is None or proof_index_path is None
    ):
        fail(
            "explicit --validation-registry and --proof-index are required "
            "for sibling handoff verification"
        )
    if validation_registry_path is not None:
        verify_validation_handoffs(
            normalized_entries, validation_registry_path, root
        )
    if proof_index_path is not None:
        verify_proof_handoffs(normalized_entries, id_to_status, proof_index_path)

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


def build_inventory(entries: list[dict[str, Any]], root: Path = ROOT) -> dict[str, Any]:
    """Build deterministic, source-linked inventory for cross-repo consumers."""
    state = repository_state(root)
    matrix_path = root / "detections" / "DETECTION_PROMOTION_MATRIX.yml"
    observed_head_blob = git_blob_sha(root, matrix_path, at_head=True)
    authoritative_blob = git_blob_sha(root, matrix_path, at_head=False)
    items: list[dict[str, Any]] = []
    for entry in entries:
        package_path = str(entry["package_path"])
        fingerprints: dict[str, str] = {}
        git_blobs: dict[str, str] = {}
        observed_head_git_blobs: dict[str, str] = {}
        semantic_fingerprints: dict[str, str] = {}
        if is_local_path(package_path):
            package_dir = repo_relative_path(root, package_path, f"{entry['detection_id']} package_path")
            for required in entry["required_files"]:
                path = package_dir / required
                if path.is_file():
                    fingerprints[required] = sha256_file(path)
                    git_blobs[required] = git_blob_sha(root, path, at_head=False)
                    observed_head_git_blobs[required] = git_blob_sha(
                        root, path, at_head=True
                    )
                    semantic_fingerprints[required] = semantic_file_fingerprint(path)
        items.append(
            {
                "detection_id": entry["detection_id"],
                "package_path": package_path,
                "source_status": entry["source_status"],
                "validation_status": entry["validation_status_if_known"],
                "proof_ceiling": entry["proof_ceiling"],
                "public_safe_status": entry["public_safe_status"],
                "required_file_fingerprints": dict(sorted(fingerprints.items())),
                "required_file_git_blobs": dict(sorted(git_blobs.items())),
                "required_file_observed_head_git_blobs": dict(
                    sorted(observed_head_git_blobs.items())
                ),
                "required_file_semantic_fingerprints": dict(
                    sorted(semantic_fingerprints.items())
                ),
                "content_matches_observed_head": all(
                    blob != "UNRESOLVED"
                    and blob == observed_head_git_blobs.get(name)
                    for name, blob in git_blobs.items()
                ),
            }
        )
    return {
        **state,
        "current_observed_head_sha": state["source_commit_sha"],
        "authoritative_path": "detections/DETECTION_PROMOTION_MATRIX.yml",
        "authoritative_fingerprint": sha256_file(matrix_path),
        "authoritative_content_fingerprint": sha256_file(matrix_path),
        "authoritative_semantic_fingerprint": semantic_file_fingerprint(matrix_path),
        "authoritative_git_blob_sha": authoritative_blob,
        "observed_head_blob_sha": observed_head_blob,
        "current_authority": bool(
            state["worktree_clean"]
            and authoritative_blob != "UNRESOLVED"
            and authoritative_blob == observed_head_blob
        ),
        "entry_count": len(items),
        "entries": items,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify and inventory the detection promotion matrix.")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--validation-registry", type=Path)
    parser.add_argument("--proof-index", type=Path)
    parser.add_argument(
        "--require-sibling-handoffs",
        action="store_true",
        help="fail unless explicit validation and proof authority paths are supplied",
    )
    args = parser.parse_args()
    try:
        entries = verify_repo(
            ROOT,
            print_summary=args.format == "text",
            validation_registry_path=args.validation_registry,
            proof_index_path=args.proof_index,
            require_sibling_handoffs=args.require_sibling_handoffs,
        )
    except MatrixError as exc:
        print(f"Detection promotion matrix check failed: {exc}", file=sys.stderr)
        return 1
    if args.format == "json":
        print(json.dumps(build_inventory(entries, ROOT), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
