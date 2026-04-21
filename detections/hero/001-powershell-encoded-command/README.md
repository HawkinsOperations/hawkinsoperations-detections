# Hero Detection 001: PowerShell Encoded Command

## Intent

Detect suspicious use of Base64-encoded PowerShell command execution, a common technique used to hide malicious command content.

## Detection ID

- Internal ID: `HOD-001`
- Sigma file: `rule.yml`

## ATT&CK Mapping

- `T1059.001` (PowerShell)
- `TA0002` (Execution)

## Test Artifacts

- Positive event: `tests/positive-event-sysmon-1.json`
- Negative event: `tests/negative-event-sysmon-1.json`

## Notes

This rule is intentionally strict for the first hero pass and should be tuned per environment allowlists and automation runners.

