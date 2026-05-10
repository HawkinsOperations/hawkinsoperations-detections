# HO-DET-011 Windows Service Creation Source

## Purpose

HO-DET-011 defines source artifacts for suspicious Windows service creation or service binary change behavior. This folder prepares the detection source for future synthetic validation across Sigma-style YAML, Splunk SPL, Wazuh XML, event mapping, and status metadata.

This source does not prove runtime activity, signal observation, validation passage, or public-safe proof.

## Scope

The source focuses on service-install telemetry and related process context where service creation tooling or suspicious service image paths are present.

In scope:

- Windows System Event ID 7045 from Service Control Manager service-install telemetry.
- Windows Security Event ID 4697 where service-install auditing is enabled.
- Sysmon Event ID 1 process context for service creation tooling such as `sc.exe`, `powershell.exe`, `pwsh.exe`, `cmd.exe`, and service-control command patterns.

Out of scope:

- Runtime deployment.
- Live routing.
- Validation results.
- Public proof.
- Completeness claims for service-creation visibility.

## Detection Behavior

HO-DET-011 is intended to raise review interest when service-install telemetry includes a suspicious service binary path, or when process telemetry shows service creation tooling with suspicious service-creation command-line patterns.

The main review pivots are:

- Service image path fields such as `ImagePath`, `ServiceFileName`, `param2`, or normalized backend equivalents.
- Service names where available.
- Process image and command-line context where Sysmon Event ID 1 or equivalent process telemetry is available.
- Parent process context where available.

Suspicious service path indicators include user-writable or commonly abused locations such as AppData, Temp, ProgramData, Public, Downloads, Windows Temp, and PerfLogs. Suspicious wrapper indicators include PowerShell, pwsh, cmd, rundll32, regsvr32, mshta, wscript, cscript, and script-like service targets such as `.ps1`, `.vbs`, `.js`, `.hta`, `.bat`, or `.cmd`.

The detection is not intended to flag every service creation event. Service creation is common during normal administration, installation, management, update, security, backup, driver, monitoring, and remote-support workflows. Reviewer-grade use requires comparing the service path, service name, signer/vendor context, parent process, account, and change window before escalation.

## Detection Surfaces

- `rule.yml` provides a Sigma-style source record.
- `splunk.spl` provides a Splunk source query candidate.
- `wazuh.xml` provides a Wazuh XML source candidate.
- `event-mapping.yml` maps expected fields across Windows System 7045, Windows Security 4697, Sysmon Event ID 1, Splunk, and Wazuh.
- `status.yml` records the source-only truth boundary.

## Telemetry Requirements

Windows System Event ID 7045 is the primary service-install event from Service Control Manager. It is not a Windows Security log event.

Windows Security Event ID 4697 may be available where audit policy records service installation.

Sysmon Event ID 1 can provide process context for service creation tooling and parent/command-line review, but this source does not require Sysmon to claim that service-install telemetry exists.

Command-line review depends on process telemetry collection. Windows System 7045 and Windows Security 4697 may provide service image path data without full creator command-line context.

## False-Positive Boundary

Expected benign sources include software installation, endpoint management, driver installation, patching, backup agents, monitoring agents, and authorized administrator activity. Future validation must separate expected service-install activity from suspicious service image paths or suspicious creation tooling.

Tuning should account for:

- Approved endpoint management and software deployment tools.
- Signed vendor installers and update services.
- Driver, print, backup, monitoring, security, and remote-support agents.
- Known service paths under managed application directories.
- Administrator activity during approved maintenance windows.

Tuning should not suppress user-writable service paths or interpreter-backed service paths without environment-specific approval and validation evidence.

## Validation Boundary

Validation is planned, not complete. Future validation should use controlled positive and negative fixtures that distinguish benign service installation from suspicious service image path or tooling patterns.

No HO-DET-011 fixtures were found in this detections repository during this tuning pass. Fixture expansion belongs in a separately scoped `hawkinsoperations-validation` lane unless fixture paths are later added to this repository.

Suggested future fixture coverage:

- Positive service-install fixture using a suspicious user-writable service image path.
- Positive service-install fixture using `ServiceFileName` instead of `ImagePath`.
- Positive process-context fixture using service creation tooling and `binPath=`.
- Negative benign installer/update fixture under a managed application path.
- Negative benign driver/security/backup/remote-support fixture.

## Supported Claims

This package supports only these source-quality claims:

- HO-DET-011 detection source artifacts exist in this repository.
- HO-DET-011 includes Sigma-style YAML, Splunk SPL, Wazuh XML, event mapping, status metadata, and tuning notes.
- HO-DET-011 is prepared for separately scoped synthetic validation.

## Blocked Claims

This source must not be cited as evidence for:

- runtime-active
- signal-observed
- public-safe
- evidence-linked public proof
- Cribl-routed
- live Splunk fired
- Wazuh-routed
- Security Onion observed
- Suricata observed
- Zeek observed
- production-ready
- fleet-wide
- autonomous SOC
- AI-approved disposition
- analyst-approved disposition
- attack coverage
- service-creation coverage completeness
- validation passed

## Next Gate

The next gate is a validation-repo fixture set and deterministic synthetic validation harness for HO-DET-011. That work must be scoped separately and must not be inferred from these source files.
