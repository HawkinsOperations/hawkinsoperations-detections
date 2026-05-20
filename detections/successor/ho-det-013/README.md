# HO-DET-013 Defense Tool and Telemetry Tamper Attempt

## Purpose

HO-DET-013 defines source artifacts for suspicious attempts to stop, disable, impair, clear, reconfigure, or blind endpoint telemetry and security controls in the HawkinsOperations Windows lab.

This package is source truth only. It does not prove runtime observation, signal observation, live SIEM ingestion, production coverage, evidence-linked public proof, public-safe proof, or deployment readiness.

## Scope

The detection focuses on endpoint telemetry and security-control tamper behavior where process, service, registry, policy, Defender, or event-log activity indicates possible impairment of visibility or defensive tooling.

In scope:

- Process creation context for `sc.exe`, `net.exe`, `powershell.exe`, `pwsh.exe`, `taskkill.exe`, `wevtutil.exe`, `reg.exe`, and related shells.
- Service stop or disable attempts targeting Sysmon, Splunk Universal Forwarder, Wazuh agent, Defender, Windows Event Log, SecurityHealthService, or Microsoft Defender for Endpoint sensor services.
- Event-log clearing or audit-policy disable patterns.
- Defender preference, exclusion, or policy-tamper command strings used as detection indicators only.
- Registry or policy path indicators that may disable or impair security controls.

Out of scope:

- Validation fixtures or validation reports.
- Runtime deployment.
- Live Splunk, Wazuh, Defender, Security Onion, or SIEM proof.
- Signal observation.
- Evidence-linked public proof.
- Public-safe proof.
- Completeness claims for security-control or telemetry coverage.
- Production readiness, customer readiness, or SOCaaS availability.

## Detection Behavior

HO-DET-013 should raise review interest when commands, processes, service-control events, registry edits, policy edits, or event-log actions indicate attempts to impair security controls or telemetry visibility.

Primary review pivots:

- Process image and command line.
- Parent process.
- User and host.
- Target service or target process.
- Service state or startup type where available.
- Event ID and source channel.
- Approved maintenance, endpoint-management, security-agent upgrade, or lab reset context.

High-interest source patterns include:

- `sc stop`, `sc config`, `net stop`, `Stop-Service`, `Set-Service -StartupType Disabled`, and `taskkill` targeting security or telemetry controls.
- `wevtutil cl`, `Clear-EventLog`, `Remove-EventLog`, `Clear-WinEvent`, or audit policy disable patterns.
- Defender preference or exclusion changes such as `Set-MpPreference`, `DisableRealtimeMonitoring`, `DisableBehaviorMonitoring`, `DisableIOAVProtection`, `DisableScriptScanning`, `DisableBlockAtFirstSeen`, `ExclusionPath`, or `ExclusionProcess`.
- Registry or policy paths for Defender, Sysmon, SplunkForwarder, WazuhSvc, WinDefend, EventLog, or related control services.

These are detection strings and review indicators, not instructions to execute tamper commands.

## ATT&CK Mapping

- T1562.001 Disable or Modify Tools
- T1070.001 Clear Windows Event Logs
- T1112 Modify Registry
- T1059.001 PowerShell
- T1489 Service Stop

## Detection Surfaces

- `rule.yml` provides a source detection record.
- `splunk.spl` provides a bounded Splunk source query candidate.
- `event-mapping.yml` maps expected backend and normalized fields.
- `status.yml` records the source-only truth boundary.

No validation fixtures, validation reports, platform files, proof records, website files, GitHub workflow files, or runtime files are part of this package.

## Telemetry Requirements

Expected telemetry sources include Windows process creation, Sysmon Event ID 1 where available, Windows Security Event ID 4688 where command-line auditing supports it, Windows System service-control context where collected, Windows Security Event ID 1102 for Security log clearing where available, Defender operational context where available, and Wazuh/Splunk/Sysmon pipeline context as intended telemetry.

Those telemetry assumptions do not prove live ingestion. Wazuh, Splunk, Defender, Sysmon, and Security Onion references in this package are source-planning context only until separate validation, runtime, and proof gates are completed.

## False-Positive Boundary

Expected benign contexts include:

- Approved security-agent upgrade, repair, or maintenance windows.
- Endpoint management activity that restarts or reconfigures agents.
- Approved Defender policy baselines.
- Documented log retention, rotation, or lab reset activity.
- Authorized administrator troubleshooting under a change record.

Tuning should not suppress event-log clearing, Defender disablement, telemetry-agent service disablement, or security-control registry edits without environment-specific approval and validation evidence.

## Validation Boundary

Validation is planned, not complete. Future validation should use controlled positive and negative fixtures that distinguish suspicious tamper attempts from approved maintenance, endpoint management, Defender policy baselines, and lab reset behavior.

No HO-DET-013 fixtures were created in this detections repository. Fixture work belongs in a separately scoped `hawkinsoperations-validation` lane.

Suggested future fixture coverage:

- Positive process creation for service stop or disable against a telemetry service.
- Positive process creation for Defender preference tamper strings.
- Positive event-log clear command pattern.
- Positive registry or policy path edit affecting Defender or telemetry services.
- Negative approved agent upgrade or service restart.
- Negative endpoint-management maintenance action.
- Negative approved Defender policy baseline.
- Negative lab reset or log retention action with explicit approved context.

## Supported Claims

This package supports only these source-quality claims:

- HO-DET-013 source artifacts exist in this repository.
- HO-DET-013 validation is planned for controlled telemetry/security-control tamper fixtures.
- HO-DET-013 documents source-only tamper detection assumptions and false-positive review guidance.

## Blocked Claims

This source must not be cited as evidence for:

- controlled-test validated
- runtime-active
- signal-observed
- public-safe
- evidence-linked public proof
- public-safe runtime proof
- live SIEM ingestion
- live Splunk proof
- live Wazuh proof
- live Defender proof
- live Security Onion proof
- Splunk-fired
- Wazuh-routed
- Cribl-routed
- Security Onion observed
- production-ready
- production triage
- fleet-wide
- complete telemetry coverage
- autonomous SOC
- AI-approved disposition
- AI-decided disposition
- analyst-approved disposition
- SOCaaS availability
- customer-ready product
- website/public-surface promotion

Website rendering is not proof. Validation fixtures and reports are pending until a later validation PR. Human review is required before promotion.

## Next Gate

The next gate is controlled-test validation in `hawkinsoperations-validation` with positive and negative telemetry/security-control tamper fixtures and deterministic report parity. Public proof, website use, runtime claims, signal-observed claims, and evidence-linked claims remain blocked until separately approved and proven.
