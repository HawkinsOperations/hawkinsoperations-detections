# ID-DET-003 Privileged Role Assignment or Admin Group Change

## Purpose

ID-DET-003 defines source artifacts for privileged role assignment, admin group membership change, or sensitive identity privilege modification in controlled identity-event records.

This source does not prove runtime activity, signal observation, public-safe proof, live identity-provider coverage, routed telemetry, production deployment, or analyst disposition.

## Scope

The detection focuses on privilege changes involving administrative roles, privileged groups, or sensitive identities.

In scope:

- Privileged role assignment.
- Admin group membership addition.
- Privileged entitlement grant.
- Sensitive role change without approved change context.

Out of scope:

- Complete IAM governance coverage.
- Live Okta, Entra, or other IdP proof.
- Live Splunk, Wazuh, Security Onion, or Cribl proof.
- Production identity coverage.
- Analyst disposition or automated response.

## Detection Behavior

ID-DET-003 should match controlled identity administration events where a privileged role, group, or entitlement changes without an approved change context.

Negative exclusions:

- Approved just-in-time privilege workflow.
- Documented change ticket.
- Approved break-glass exercise.
- Maintenance window with expected administrative actor.

## Detection Surfaces

- `rule.yml` provides a source detection record.
- `splunk.spl` provides a source query candidate.
- `event-mapping.yml` maps controlled identity administration fields to detection logic fields.
- `status.yml` records the source truth boundary.

## Validation Boundary

Validation belongs to `hawkinsoperations-validation` and is planned for controlled identity administration fixtures only. This source package is not live IdP evidence, not routed telemetry, not proof promotion, and not website material.

## Supported Claims

- ID-DET-003 source artifacts exist.
- ID-DET-003 documents controlled privileged role and admin group change assumptions.
- ID-DET-003 validation is planned, not completed.

## Blocked Claims

This source must not be cited as evidence for runtime-active, signal-observed, public-safe, live IdP proof, production identity coverage, complete identity attack coverage, autonomous SOC, AI-approved disposition, or analyst-approved disposition.

## Next Gate

The next gate is controlled-test validation in `hawkinsoperations-validation` with positive and negative privileged role or admin group change fixtures and deterministic report parity.
