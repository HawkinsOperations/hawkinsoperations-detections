# Tuning Notes

## Initial Tuning Strategy

- Keep high severity by default.
- Add allowlists for known admin tooling that legitimately uses encoded command payloads.
- Track recurrence by user, host, and parent process for contextual triage.

## Candidate Allowlist Dimensions

- `ParentImage`
- `User`
- `CommandLine` known-good prefixes

