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

ID-DET-003 has source artifacts in this repo and controlled validation in `hawkinsoperations-validation`. The validation report supports `CONTROLLED_TEST_VALIDATED` for 10 controlled identity administration fixtures: 5 positive, 5 negative, 0 missed positives, and 0 false-positive negatives.

This does not prove live IdP activity, runtime activation, signal observation, production identity coverage, public-safe proof, autonomous SOC operation, AI-approved disposition, or analyst-approved disposition.

## Supported Claims

- ID-DET-003 source artifacts exist.
- ID-DET-003 documents controlled privileged role and admin group change assumptions.
- ID-DET-003 passed controlled validation against 10 controlled identity administration fixtures for privileged role assignment or admin group change behavior.
- Runtime, signal, public-safe, live IdP, production identity coverage, autonomous SOC, AI-approved disposition, and analyst-approved disposition claims remain blocked.

## Blocked Claims

This source must not be cited as evidence for runtime-active, signal-observed, public-safe, live IdP proof, production identity coverage, complete identity attack coverage, autonomous SOC, AI-approved disposition, or analyst-approved disposition.

## Next Gate

The next gates are proof record creation, runtime evidence, signal evidence, and public-proof review under separate approval. Controlled validation is satisfied for the current fixture scope.
