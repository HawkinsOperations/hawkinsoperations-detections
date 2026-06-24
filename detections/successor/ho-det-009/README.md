# HO-DET-009 Windows Local User Creation Source

## Purpose

HO-DET-009 defines source artifacts for Windows local user account creation telemetry. This package covers controlled source, Wazuh XML, Splunk SPL, event mapping, and status metadata for local account lifecycle review.

This source does not prove runtime activity, signal observation, public proof, public-safe proof, routed telemetry, or production readiness.

## Scope

In scope:

- Windows Security Event ID 4720 for local user account creation where audit policy and collection support it.
- Windows Security Event ID 4738 as related account change context where available.
- Sysmon Event ID 1 process context for local account creation tooling such as `net.exe`, `net1.exe`, `powershell.exe`, `pwsh.exe`, and `cmd.exe`.

Out of scope:

- Runtime deployment.
- Live routing.
- Credential collection, password inspection, or account use.
- Public proof.
- Completeness claims for account lifecycle visibility.

## Detection Behavior

HO-DET-009 raises review interest when local user creation telemetry appears, especially where the account name, creation process, or command context suggests a controlled, temporary, hidden, service-like, support-like, backup-like, or administrator-adjacent local account.

The primary telemetry source is Windows Security Event ID 4720. Process context is optional and supports review when account creation tooling is observed.

## Detection Surfaces

- `rule.yml` provides a Sigma-style source record.
- `splunk.spl` provides a Splunk source query candidate.
- `wazuh.xml` provides a Wazuh XML source candidate.
- `event-mapping.yml` maps expected fields across Windows Security and Sysmon sources.
- `status.yml` records source, validation, and proof-boundary truth.

## False-Positive Boundary

Expected benign sources include approved helpdesk onboarding, lab reset, classroom or training account creation, break-glass account rotation under change control, and local service-account provisioning through documented endpoint management.

Tuning should not suppress local account creation without an approved source identity, host role, change window, or account naming policy.

## Validation Boundary

Controlled validation belongs in `hawkinsoperations-validation`. This source package supports a controlled-test validation lane but does not itself prove validation, runtime, signal, Wazuh routing, public-safe status, production coverage, SOCaaS deployment, customer deployment, autonomous SOC operation, AI/analyst-approved disposition, or case closure.

## Supported Claims

- HO-DET-009 source artifacts exist in this repository.
- HO-DET-009 documents Windows local user creation telemetry assumptions and false-positive guidance.
- Detection source includes Sigma/SPL/Wazuh/event-mapping/status surfaces.

## Blocked Claims

- runtime-active
- signal-observed
- public-safe
- evidence-linked public proof
- public-safe runtime proof
- live Splunk proof
- live Wazuh proof
- Cribl-routed proof
- Security Onion observed
- production-ready
- production triage
- fleet-wide
- autonomous SOC
- AI-approved disposition
- analyst-approved disposition
- account-lifecycle coverage completeness

## Next Gate

The next gate is controlled-test validation in `hawkinsoperations-validation` using synthetic local-account creation fixtures. Runtime evidence and public proof remain blocked until separately approved.
