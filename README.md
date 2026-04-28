# HawkinsOperations Detections

Detection content and rule engineering for HawkinsOps V2.

Owner identity: Raylee Hawkins, Detection Engineer | SOC Automation | Detection-as-Code | Security Automation.

Official links: [Raylee Hawkins on LinkedIn](https://www.linkedin.com/in/raylee-hawkins) · [Raylee Hawkins on GitHub](https://github.com/raylee-hawkins) · [HawkinsOps detection engineering portfolio](https://hawkinsops.com) · [HawkinsOperations GitHub organization](https://github.com/HawkinsOperations) · [RayleeOps public operating journal](https://rayleeops.com)

## Purpose

This repository contains detection logic as source content. It is the authoring layer for production-bound security detections.

## Scope

- Detection rules (Sigma/Wazuh/Splunk-compatible sources)
- Detection metadata and taxonomy
- Build/conversion scripts for detection artifacts

## Out of Scope

- Runtime platform deployment state
- Host-specific operational logs
- Internal-only credentials, endpoints, or infrastructure secrets

## Repository Contract

- Source-of-truth detection content lives here.
- Generated artifacts are reproducible from source.
- Changes must be explainable with validation evidence from `hawkinsoperations-validation`.

## Public-Safe Proof

- Sanitized detection examples
- Rule quality checks
- Change history with rationale

## Hero Detections

- `001-powershell-encoded-command`  
  Path: `detections/hero/001-powershell-encoded-command/`

## Related Repositories

- Validation: `hawkinsoperations-validation`
- Platform: `hawkinsoperations-platform`
- Proof: `hawkinsoperations-proof`
- Website: `hawkinsoperations-website`
