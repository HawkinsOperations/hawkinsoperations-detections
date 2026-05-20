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

Validation belongs to `hawkinsoperations-validation` and is planned for controlled identity-event fixtures only. This source package is not live IdP evidence, not routed telemetry, not proof promotion, and not website material.

## Supported Claims

- ID-DET-004 source artifacts exist.
- ID-DET-004 documents controlled impossible-travel and anomalous session assumptions.
- ID-DET-004 validation is planned, not completed.

## Blocked Claims

This source must not be cited as evidence for runtime-active, signal-observed, public-safe, live IdP proof, live Splunk proof, production identity coverage, complete identity attack coverage, impossible-travel completeness, session hijacking completeness, autonomous SOC, AI-approved disposition, or analyst-approved disposition.

## Next Gate

The next gate is controlled-test validation in `hawkinsoperations-validation` with positive and negative impossible-travel and anomalous-session fixtures and deterministic report parity.
