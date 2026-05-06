# Status

## Current Milestone

Governance baseline initialized and Hero Rule 001 implemented.

## Next Gate

Link Hero Rule 001 to validation harness output and proof ledger entry.

## Baseline Contract Check Scope

- Current check coverage: `detections/hero/*` baseline artifact + schema-shape validation only.
- Not yet covered: non-hero families, semantic rule quality, cross-repo detection-to-validation-to-proof linkage.

## Blocking Risks

- Non-hero detection families are not covered by the current baseline contract check.
- Semantic detection quality is not enforced by the current baseline contract check.
- Cross-repo detection-to-validation-to-proof linkage is not enforced here.
- Claim-boundary scanning is not enforced here.
