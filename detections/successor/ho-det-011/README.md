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

## False-Positive Boundary

Expected benign sources include software installation, endpoint management, driver installation, patching, backup agents, monitoring agents, and authorized administrator activity. Future validation must separate expected service-install activity from suspicious service image paths or suspicious creation tooling.

## Validation Boundary

Validation is planned, not complete. Future validation should use controlled positive and negative fixtures that distinguish benign service installation from suspicious service image path or tooling patterns.

## Blocked Claims

This source must not be cited as evidence for:

- runtime-active
- signal-observed
- public-safe
- evidence-linked public proof
- live Splunk fired
- Wazuh-routed
- production-ready
- fleet-wide
- attack coverage
- service-creation coverage completeness
- validation passed

## Next Gate

The next gate is a validation-repo fixture set and deterministic synthetic validation harness for HO-DET-011. That work must be scoped separately and must not be inferred from these source files.
