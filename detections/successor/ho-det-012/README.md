# HO-DET-012 Suspicious Scheduled Task Creation Source

## Purpose

HO-DET-012 defines source artifacts for suspicious Windows scheduled task creation, registration, or update behavior. This folder preserves the detection source and controlled-test validation boundary across Sigma-style YAML, Splunk SPL, Wazuh XML, event mapping, and status metadata.

This source does not prove runtime activity, signal observation, public proof, public-safe proof, routed telemetry, or production readiness.

## Scope

The source focuses on scheduled-task telemetry and related process context where task creation tooling, suspicious task actions, suspicious task paths, or suspicious command-line patterns are present.

In scope:

- Windows Security Event ID 4698 for scheduled task creation where audit policy and collection support it.
- Windows Security Event ID 4702 for scheduled task update where audit policy and collection support it.
- Microsoft-Windows-TaskScheduler/Operational Event ID 106 for task registration where the operational log is enabled and collected.
- Microsoft-Windows-TaskScheduler/Operational Event ID 140 for task update where the operational log is enabled and collected.
- Sysmon Event ID 1 process context for scheduled-task creation tooling such as `schtasks.exe`, `powershell.exe`, `pwsh.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, and `regsvr32.exe`.

Out of scope:

- Runtime deployment.
- Live routing.
- Validation results.
- Public proof.
- Completeness claims for scheduled-task visibility.

## Detection Behavior

HO-DET-012 is intended to raise review interest when scheduled-task creation or update telemetry includes a suspicious task action, suspicious task path, script-like target, interpreter-backed action, encoded or obfuscated command-line pattern, or process telemetry showing scheduled-task creation tooling.

The main review pivots are:

- Task name, task path, task content, and task action fields where available.
- Process image and command-line context where Sysmon Event ID 1 or equivalent process telemetry exists.
- Parent process, user, host, and approved change-window context where available.

Suspicious task action indicators include user-writable or commonly abused locations such as AppData, Temp, ProgramData, Public, Users Public, Downloads, Windows Temp, and PerfLogs. Suspicious wrapper indicators include PowerShell, pwsh, cmd, wscript, cscript, mshta, rundll32, regsvr32, and script-like task targets such as `.ps1`, `.vbs`, `.js`, `.hta`, `.bat`, or `.cmd`.

Suspicious task names are weak review context only. Updater-like names, one-character names, random-looking names, or names pretending to be Windows or vendor tasks should not trigger by themselves unless paired with suspicious action, path, or tooling evidence.

## Detection Surfaces

- `rule.yml` provides a Sigma-style source record.
- `splunk.spl` provides a Splunk source query candidate.
- `wazuh.xml` provides a Wazuh XML source candidate.
- `event-mapping.yml` maps expected fields across Windows Security 4698/4702, TaskScheduler Operational 106/140, Sysmon Event ID 1, Splunk, and Wazuh.
- `status.yml` records the source, validation, and proof-boundary truth split.

## Telemetry Requirements

Windows Security Event IDs 4698 and 4702 depend on audit policy and event collection. They may expose task name, task content, author, user, or action data differently across collectors.

TaskScheduler Operational Event IDs 106 and 140 depend on the Microsoft-Windows-TaskScheduler/Operational log being enabled and collected. They can provide task registration and update context but may not include full command action detail in every backend.

Sysmon Event ID 1 can provide process context for task creation tooling and parent/command-line review, but this source does not require Sysmon to claim that scheduled-task telemetry exists.

Command-line review depends on process telemetry collection. Scheduled-task event logs can exist without full creator process command-line context.

## Suspicious Indicator Guidance

Review scheduled tasks more closely when task action, command, or process context includes:

- User-writable or commonly abused paths: `\AppData\`, `\Temp\`, `\ProgramData\`, `\Public\`, `\Users\Public\`, `\Downloads\`, `\Windows\Temp\`, or `\PerfLogs\`.
- Interpreters or proxy execution tools: `powershell`, `pwsh`, `cmd.exe`, `wscript`, `cscript`, `mshta`, `rundll32`, or `regsvr32`.
- Script-like targets: `.ps1`, `.vbs`, `.js`, `.hta`, `.bat`, or `.cmd`.
- Task creation tooling and command-line patterns: `schtasks /create`, `Register-ScheduledTask`, `New-ScheduledTaskAction`, `-EncodedCommand`, `FromBase64String`, hidden execution, minimized execution, or remote/LOLBIN-style task actions.

## False-Positive Boundary

Expected benign sources include software deployment tools, vendor updaters, endpoint management platforms, backup agents, monitoring and security tools, remote support tools, browser or app update tasks, approved admin automation, and approved maintenance windows.

Tuning should account for:

- Signed vendor binaries under Program Files or Program Files (x86).
- Managed application directories and known enterprise software deployment paths.
- Endpoint management and remote-support platforms.
- Backup, monitoring, and security agents.
- Approved administrator automation and approved maintenance windows.

Tuning should not suppress user-writable task actions, interpreter-backed task actions, or encoded command execution without environment-specific approval and validation evidence.

## Validation Boundary

HO-DET-012 has source artifacts in this repo and controlled validation in `hawkinsoperations-validation`. The validation report supports `CONTROLLED_TEST_VALIDATED` for 8 controlled scheduled-task fixtures: 4 positive, 4 negative, 0 missed positives, and 0 false-positive negatives.

Static/logtest Wazuh contract validation is represented by HO-LAB-WAZUH-001 in `hawkinsoperations-validation`. This detections repo remains source truth only. The validation-owned lab verifies source/static/logtest contract consistency for the Wazuh registry and controlled sample wiring; it does not prove live Wazuh deployment, Wazuh-routed runtime proof, signal-observed proof, public-safe runtime proof, production SOC, SOCaaS deployment, customer deployment, autonomous SOC, AI/analyst-approved disposition, or case closure.

No HO-DET-012 fixtures were created in this detections repository. Fixture expansion belongs in a separately scoped `hawkinsoperations-validation` lane unless fixture paths are later added to this repository.

Current controlled fixture coverage:

- Positive Windows Security 4698 task creation using a suspicious action under AppData.
- Positive TaskScheduler Operational 106 registration using an interpreter-backed action.
- Positive Sysmon Event ID 1 process context using `schtasks.exe /create` with a suspicious `/tr` target.
- Positive PowerShell process context using `Register-ScheduledTask` and `New-ScheduledTaskAction`.
- Negative benign vendor updater task under Program Files.
- Negative endpoint management task under a managed application directory.
- Negative approved maintenance-window task creation.
- Negative suspicious-looking task name without suspicious action, path, or tooling evidence.

## Supported Claims

This package supports only these controlled source and validation claims:

- HO-DET-012 source artifacts exist in this repository.
- HO-DET-012 passed controlled-test validation against scheduled-task creation and update fixtures.
- Detection source includes Sigma/SPL/Wazuh/event-mapping/status surfaces.
- HO-LAB-WAZUH-001 in `hawkinsoperations-validation` verifies Wazuh source/static/logtest contract consistency for this source entry.
- HO-DET-012 documents scheduled-task telemetry assumptions and false-positive review guidance.
- HO-DET-012 has a `CONTROLLED_TEST_VALIDATED` proof record in `hawkinsoperations-proof`.

## Blocked Claims

This source must not be cited as evidence for:

- runtime-active
- signal-observed
- public-safe
- evidence-linked public proof
- public-safe runtime proof
- Splunk-fired
- live Splunk fired
- Wazuh-routed
- Cribl-routed
- Security Onion observed
- Suricata observed
- Zeek observed
- production-ready
- production triage
- fleet-wide
- autonomous SOC
- AI-approved disposition
- analyst-approved disposition
- attack coverage completeness
- scheduled-task coverage completeness

## Next Gate

The next gates are runtime evidence, signal evidence, and public-proof review under separate approval. Controlled validation and proof-record creation are satisfied for the current controlled-test scope.
