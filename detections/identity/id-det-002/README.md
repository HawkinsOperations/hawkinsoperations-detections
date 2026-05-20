# ID-DET-002 Suspicious MFA Fatigue or Repeated MFA Failure Pattern

## Purpose

ID-DET-002 defines source artifacts for suspicious MFA fatigue, repeated MFA failure, or success after an MFA failure burst in controlled identity-event records.

This source does not prove runtime activity, signal observation, public-safe proof, live identity-provider coverage, routed telemetry, production deployment, or analyst disposition.

## Scope

The detection focuses on identity activity where MFA outcomes and short-window repetition indicate possible push fatigue or repeated authentication pressure.

In scope:

- Repeated MFA push attempts in a short window.
- Repeated MFA denial or failure outcomes.
- Successful authentication after repeated MFA failures.
- MFA challenge volume against a privileged or sensitive identity.

Out of scope:

- Complete brute-force coverage.
- Live Okta, Entra, or other IdP proof.
- Live Splunk, Wazuh, Security Onion, or Cribl proof.
- Production MFA or identity-provider coverage.
- Analyst disposition or automated response.

## Detection Behavior

ID-DET-002 should match only when MFA repetition or failure context exceeds the planned controlled-event threshold. A single MFA failure is not sufficient.

Positive condition combinations:

- `mfa_push_count>=5` inside the controlled window.
- `mfa_denied_count>=3` inside the controlled window.
- `auth_result=success` after `mfa_failure_count>=3`.
- `privileged_identity=true` with repeated MFA pressure.

Negative exclusions:

- Approved MFA reset or help-desk test.
- Known user enrollment or device replacement workflow.
- Approved break-glass identity exercise.
- Expected automated identity health check.

## Detection Surfaces

- `rule.yml` provides a source detection record.
- `splunk.spl` provides a source query candidate.
- `event-mapping.yml` maps controlled MFA-event fields to detection logic fields.
- `status.yml` records the source truth boundary.

## Validation Boundary

Validation belongs to `hawkinsoperations-validation` and is planned for controlled identity-event fixtures only. This source package is not live IdP evidence, not routed telemetry, not proof promotion, and not website material.

## Supported Claims

- ID-DET-002 source artifacts exist.
- ID-DET-002 documents controlled MFA fatigue and repeated failure assumptions.
- ID-DET-002 validation is planned, not completed.

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
- production identity coverage
- complete identity attack coverage
- autonomous SOC
- AI-approved disposition
- analyst-approved disposition

## Next Gate

The next gate is controlled-test validation in `hawkinsoperations-validation` with positive and negative controlled MFA-event fixtures and deterministic report parity.
