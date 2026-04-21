# Governance

Repository: `hawkinsoperations-detections`

## Rules

1. Source truth must be versioned and reviewable.
2. Every claim in README/docs must map to evidence entries.
3. No host-local paths, credentials, or secret material in tracked files.
4. Detection changes require corresponding validation/proof references before promotion.

## Evidence Contract

- Evidence ledger files:
  - `evidence/EVIDENCE_LEDGER_SCHEMA.json`
  - `evidence/evidence-ledger.json`
- Evidence entries are append-focused and include reproducible identifiers.

## Promotion Gate

- Required governance files must exist.
- CI gate must pass before merge.
- Public-safe output only; internal control-plane data stays out.

