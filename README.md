# HawkinsOperations Detections

This repo is the HawkinsOperations detection source-truth layer: it shows how detection ideas become source-controlled rules, reviewer-readable metadata, and promotion candidates without pretending source code is runtime proof.

## What A Reviewer Should See In 10 Seconds

- **Purpose:** detection engineering source, not runtime operations.
- **Value:** clear detection logic, field mapping, blocked claims, and promotion gates a reviewer can inspect.
- **Path:** source here -> deterministic validation in `hawkinsoperations-validation` -> bounded proof records in `hawkinsoperations-proof`.
- **Boundary:** this repo does not prove deployed coverage, live signals, production triage, public-safe proof, SOCaaS availability, or AI final disposition.

## Source To Validation To Proof

| Step | Where it lives | What it can show | What it cannot show |
|---|---|---|---|
| Source | `hawkinsoperations-detections` | Detection rules, SPL/Sigma/Wazuh sources, event mappings, metadata, blocked claims, and next gates | Runtime execution, signal observation, production deployment, public-safe proof, or final disposition |
| Validation | `hawkinsoperations-validation` | Deterministic fixture or contract results within the stated test scope | Live telemetry, production quality, public-safe proof, or analyst approval |
| Proof | `hawkinsoperations-proof` | Bounded proof records and reviewer routes after the required review gates | Broader claims than the approved record, current runtime state, or reusable public-safe status by default |

## Detection Reviewer Route

Start with the factory view, then follow the candidate-specific source and proof routes:

- Factory matrix: [`detections/DETECTION_FACTORY_INDEX.md`](detections/DETECTION_FACTORY_INDEX.md)
- Promotion metadata: [`detections/DETECTION_PROMOTION_MATRIX.yml`](detections/DETECTION_PROMOTION_MATRIX.yml)
- Scope boundary: [`SCOPE.md`](SCOPE.md)
- Organization reviewer start: [`HawkinsOperations/.github profile`](https://github.com/HawkinsOperations/.github/blob/main/profile/START_HERE.md)
- Proof record route: [`hawkinsoperations-proof/proof/records`](https://github.com/HawkinsOperations/hawkinsoperations-proof/tree/main/proof/records)

## HO-DET-001 Source Route

HO-DET-001 is included here only because it already exists in this repository as a source package and reviewer route. The proof ceiling is controlled by the proof record, not by this README.

| Source item | Route |
|---|---|
| Sigma source | [`detections/successor/ho-det-001/rule.yml`](detections/successor/ho-det-001/rule.yml) |
| Splunk source | [`detections/successor/ho-det-001/splunk.spl`](detections/successor/ho-det-001/splunk.spl) |
| Event mapping | [`detections/successor/ho-det-001/event-mapping.yml`](detections/successor/ho-det-001/event-mapping.yml) |
| Source status metadata | [`detections/successor/ho-det-001/status.yml`](detections/successor/ho-det-001/status.yml) |
| Reviewer proof route | [`HO-DET-001 proof record`](https://github.com/HawkinsOperations/hawkinsoperations-proof/blob/main/proof/records/HO-DET-001.md) |

Safe reading: this repo can show source existence and authoring structure for HO-DET-001. Validation and proof claims must be read from their owning repositories and bounded by their current records.

## Repository Authority

This repository owns:

- Detection source files.
- Detection metadata and taxonomy.
- Source-side event mappings.
- Source-side promotion readiness metadata.
- Build or conversion logic for detection artifacts.

This repository does not own:

- Validation execution results.
- Runtime platform state.
- Signal observation.
- Public proof approval.
- Website/public narrative authority.
- Human or AI final disposition.

## Blocked Claims

Do not cite this repo as evidence for:

- runtime-active status
- signal-observed status
- evidence-linked public proof
- public-safe status
- live Splunk firing
- Wazuh-routed proof
- Cribl-routed proof
- AWS-live proof
- production triage
- production-ready SOC
- fleet-wide deployment
- SOCaaS availability
- autonomous SOC operation
- analyst-approved disposition
- AI-approved disposition
- AI-decided disposition

## Hiring Signal

For a reviewer, the value here is not a claim that HawkinsOperations is operating as a live service. The value is a disciplined detection-engineering system: source-controlled rules, explicit truth boundaries, deterministic validation routes, proof-record handoff, and blocked-claim hygiene.

AI is labor. Governance is authority.
