# HO-DET-010 Windows Local Administrators Group Membership Change

HO-DET-010 detects Windows local administrators group membership changes using
controlled source artifacts only. It is intended for local lab validation and
private runtime gating after separate approval.

## Telemetry Model

- Windows Security Event ID 4732: member added to local security-enabled group.
- Windows Security Event ID 4733: member removed from local security-enabled group.
- Optional Sysmon Event ID 1: process context for `net localgroup`, PowerShell
  `Add-LocalGroupMember`, and `Remove-LocalGroupMember`.

## Detection Intent

The rule focuses on local Administrators membership changes, especially where
the target group is `Administrators`, `Builtin\Administrators`, or the built-in
administrators SID `S-1-5-32-544`.

## Validation Boundary

This package is source and controlled-test validation ready. It does not claim
runtime activity, Wazuh routing, Splunk firing, public-safe status, production
coverage, autonomous SOC authority, AI-approved disposition, analyst-approved
disposition, or case closure.

## Expected Follow-up

Before any runtime attempt, require a separate governed VM108 gate with snapshot,
one execution ID, immediate cleanup, sanitized evidence only, and no public proof
promotion.
