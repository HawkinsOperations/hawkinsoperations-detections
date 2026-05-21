# ID-DET-004 Impossible Travel or Anomalous Session Context

## Purpose

ID-DET-004 defines source artifacts for impossible travel or anomalous identity session context in controlled identity-event records.

This source does not prove runtime activity, signal observation, public-safe proof, live identity-provider coverage, routed telemetry, production deployment, or analyst disposition.

## Scope

The detection focuses on successful identity/session activity with impossible travel or session context shifts that require review.

In scope:

- Impossible travel marker on a successful login.
- High location velocity in a controlled window.
- New country or region with new device context.
- Session context shift across ASN category and user-agent family.

Out of scope:

- Complete impossible-travel coverage.
- Complete session hijacking coverage.
- Live Okta, Entra, or other IdP proof.
- Live Splunk, Wazuh, Security Onion, or Cribl proof.
- Production identity coverage.

## Detection Behavior

ID-DET-004 should match only when successful identity activity includes impossible travel or anomalous session context. A country change alone is not sufficient.

Negative exclusions:

- Known-device VPN usage with expected ASN category.
- Approved travel window.
- Known corporate proxy or egress change.
- Maintenance or test session.

## Detection Surfaces

- `rule.yml` provides a source detection record.
- `splunk.spl` provides a source query candidate.
- `event-mapping.yml` maps controlled travel and session-context fields to detection logic fields.
- `status.yml` records the source truth boundary.

## Validation Boundary

ID-DET-004 has source artifacts in this repo and controlled validation in `hawkinsoperations-validation`. The validation report supports `CONTROLLED_TEST_VALIDATED` for 10 controlled identity-event fixtures: 5 positive, 5 negative, 0 missed positives, and 0 false-positive negatives.

This does not prove live IdP activity, runtime activation, signal observation, production identity coverage, public-safe proof, impossible-travel completeness, session-hijacking completeness, autonomous SOC operation, AI-approved disposition, or analyst-approved disposition.

## Supported Claims

- ID-DET-004 source artifacts exist.
- ID-DET-004 documents controlled impossible-travel and anomalous session assumptions.
- ID-DET-004 passed controlled validation against 10 controlled identity-event fixtures for impossible travel or anomalous session context.
- Runtime, signal, public-safe, live IdP, production identity coverage, autonomous SOC, AI-approved disposition, and analyst-approved disposition claims remain blocked.
- Impossible-travel completeness, session-hijacking completeness, and complete identity coverage remain blocked unless separately proven.

## Blocked Claims

This source must not be cited as evidence for runtime-active, signal-observed, public-safe, live IdP proof, live Splunk proof, production identity coverage, complete identity attack coverage, impossible-travel completeness, session hijacking completeness, autonomous SOC, AI-approved disposition, or analyst-approved disposition.

## Next Gate

The next gates are proof record creation, runtime evidence, signal evidence, and public-proof review under separate approval. Controlled validation is satisfied for the current fixture scope.
