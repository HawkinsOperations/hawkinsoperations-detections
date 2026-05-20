# ID-DET-001 Suspicious Identity Session Context

## Purpose

ID-DET-001 defines source artifacts for suspicious identity session context where authentication succeeds but surrounding session context indicates possible abuse.

Public-facing hook:

> A successful login is not proof of a legitimate user.

This source does not prove runtime activity, signal observation, public-safe proof, live identity-provider coverage, routed telemetry, production deployment, or analyst disposition.

## Scope

The detection focuses on successful identity/session activity with suspicious context combinations.

In scope:

- Impossible travel with a successful login.
- Successful login from a new device and a new ASN category.
- Service account used interactively.
- AI or agent identity performing a privileged action outside approved tool scope.
- Session reuse after user-agent and ASN category shift.

Out of scope:

- Failed-login brute-force detection.
- Complete identity attack coverage.
- Live Okta, Entra, or other IdP integration.
- Live Splunk, Wazuh, Security Onion, or Cribl proof.
- Runtime deployment or production identity governance.

## Detection Behavior

ID-DET-001 should match only when a successful identity event includes suspicious context combinations. A successful login alone is not sufficient.

Positive condition combinations:

- `auth_result=success` with `impossible_travel=true`.
- `auth_result=success` with `known_device=false` and a new source ASN category.
- `identity_type=service_account` with interactive login context and no expected automation.
- `identity_type=ai_agent` with privileged action outside approved tool scope.
- `session_reuse=true` after user-agent and ASN category shift.

Negative exclusions:

- Known-device successful login without suspicious travel, ASN, or session shift.
- VPN country change with a known device and expected ASN category.
- Service account activity from expected automation.
- AI or agent identity using an approved tool within approved scope.
- Privileged action inside an approved maintenance window.

## Detection Surfaces

- `rule.yml` provides a source detection record.
- `splunk.spl` provides a source query candidate.
- `event-mapping.yml` maps controlled identity-event fields to detection logic fields.
- `status.yml` records the controlled-test truth boundary.

## Validation Boundary

Validation belongs to `hawkinsoperations-validation` and uses controlled identity-event fixtures only. This source package is not live IdP evidence, not routed telemetry, not proof promotion, and not website material.

## Supported Claims

- ID-DET-001 source artifacts exist.
- ID-DET-001 has controlled-test validation surfaces planned or present in the validation repo.
- ID-DET-001 documents identity/session context assumptions and false-positive review guidance.

## Blocked Claims

This source must not be cited as evidence for:

- runtime-active
- signal-observed
- public-safe
- evidence-linked public proof
- live Okta proof
- live Entra proof
- live IdP proof
- live Splunk proof
- Wazuh-routed proof
- Cribl-routed proof
- Security Onion observed proof
- production identity coverage
- machine identity production governance
- AI agent production governance
- full identity attack coverage
- impossible-travel completeness
- session hijacking completeness
- autonomous SOC
- AI-approved disposition
- analyst-approved disposition
- proof promotion
- website/public-surface promotion

## Next Gate

The next gate is controlled-test validation in `hawkinsoperations-validation` with 10 controlled identity-event fixtures and deterministic report parity.
