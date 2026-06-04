# HawkinsOperations Detections

`hawkinsoperations-detections` is the HawkinsOperations source-truth layer for governed detection engineering. It turns detection ideas into reviewable source packages: rules, SPL/Sigma/Wazuh sources where applicable, ATT&CK mapping, event-field contracts, source metadata, promotion readiness, and blocked-claim boundaries.

This repo does not prove runtime execution, live signal, public-safe proof, production coverage, SOCaaS availability, customer deployment, or final AI/analyst disposition. Source truth is the first governed layer, not the final claim authority.

## 10-Second Source Signal

| Start here | Route | Reviewer signal |
|---|---|---|
| Detection factory | [`detections/DETECTION_FACTORY_INDEX.md`](detections/DETECTION_FACTORY_INDEX.md) | Multi-surface detection catalog with truth states, blocked claims, next gates, and source/validation/proof separation. |
| Promotion matrix | [`detections/DETECTION_PROMOTION_MATRIX.yml`](detections/DETECTION_PROMOTION_MATRIX.yml) | Machine-readable source-side eligibility and reviewer expansion map. |
| HO-DET-001 source package | [`detections/successor/ho-det-001/`](detections/successor/ho-det-001/) | Flagship PowerShell EncodedCommand package: Sigma source, SPL source, event mapping, status metadata, and proof route. |
| Event-field contract | [`detections/successor/ho-det-001/event-mapping.yml`](detections/successor/ho-det-001/event-mapping.yml) | Required process-creation fields and backend adapter planning without live-runtime claims. |
| Validation handoff | [`hawkinsoperations-validation`](https://github.com/HawkinsOperations/hawkinsoperations-validation) | Controlled behavior checks live outside this source repo. |
| Proof handoff | [`hawkinsoperations-proof`](https://github.com/HawkinsOperations/hawkinsoperations-proof) | Proof records own claim ceilings and blocked public wording. |

## Current Source Highlights

| Source highlight | What exists here | Reviewer boundary |
|---|---|---|
| `HO-DET-001` Suspicious PowerShell EncodedCommand | Source package with [`rule.yml`](detections/successor/ho-det-001/rule.yml), [`splunk.spl`](detections/successor/ho-det-001/splunk.spl), [`event-mapping.yml`](detections/successor/ho-det-001/event-mapping.yml), and [`status.yml`](detections/successor/ho-det-001/status.yml). Maps PowerShell process behavior to ATT&CK `T1059.001` and routes proof to [`hawkinsoperations-proof/proof/records/HO-DET-001.md`](https://github.com/HawkinsOperations/hawkinsoperations-proof/blob/main/proof/records/HO-DET-001.md). | Source and controlled-test status are reviewable; runtime, signal, public-safe, production, live SIEM, and final disposition claims remain blocked. |
| `HO-DET-011` service creation/tamper lane | Source-side metadata records Sigma/SPL/Wazuh/event-mapping/status surfaces, controlled validation alignment, platform case-packet guardrail linkage, and a proof-record route. | Private runtime evidence is bounded as private/non-public; no live Splunk, Wazuh, Cribl, Security Onion, production, fleet-wide, or public-safe claim is made here. |
| `HO-DET-012` scheduled task persistence | Source metadata aligns Sigma/SPL/Wazuh/event mapping, controlled scheduled-task validation handoff, and `CONTROLLED_TEST_VALIDATED` proof-record routing. | Runtime evidence, signal evidence, and public proof remain blocked; the source package does not imply scheduled-task coverage completeness. |
| `HO-NDR-001` Security Onion visibility boundary | Factory and promotion metadata preserve it as an NDR boundary/route hygiene contract rather than a published detection package. | Boundary contract only; no unpublished proof record, packet capture, Security Onion observation, Splunk forwarding, or runtime proof is implied. |
| Detection Factory / Promotion Matrix | Source-level catalog, truth-state vocabulary, ledger eligibility, reviewer expansion posture, next gates, and blocked-claim inventory. | Reviewer navigation and source eligibility only; the matrix does not append ledger entries, validate behavior, observe signals, or promote proof. |

## Source To Validation To Proof

| Truth surface | Owner | What it can show | What it cannot show |
|---|---|---|---|
| Source package | `hawkinsoperations-detections` | Detection logic, metadata, ATT&CK framing, event-field mapping, required source files, readiness metadata, and source-side blocked claims. | Runtime execution, signal observation, public-safe proof, production coverage, SOCaaS/customer deployment, or final disposition. |
| Behavior validation | [`hawkinsoperations-validation`](https://github.com/HawkinsOperations/hawkinsoperations-validation) | Controlled fixtures, validation reports, parity checks, case packets, and deterministic behavior checks inside their stated scope. | Live telemetry, production quality, public-safe proof, or analyst approval. |
| Contracts and guardrails | [`hawkinsoperations-platform`](https://github.com/HawkinsOperations/hawkinsoperations-platform) | Schemas, verifier guardrails, platform contracts, case-packet shapes, ledger mechanics, and runtime-candidate controls where applicable. | Proof promotion, runtime truth by itself, public-safe status, case closure, or production readiness. |
| Proof ceilings | [`hawkinsoperations-proof`](https://github.com/HawkinsOperations/hawkinsoperations-proof) | Proof records, proof cards, release routes, reviewer maps, claim ceilings, and blocked public wording. | Broader claims than the proof record authorizes or raw private evidence publication. |
| Website rendering | [`hawkinsoperations-website`](https://github.com/HawkinsOperations/hawkinsoperations-website) | Reviewer navigation and bounded presentation. | Proof authority. Rendering is navigation only. |

Source truth is necessary for proof, but it is not sufficient for proof. A detection source package becomes stronger only when validation, platform, proof, evidence, and human-review gates support the exact stronger claim.

## What This Repo Owns

- Detection source files.
- Detection metadata and taxonomy.
- Source-side event mappings.
- Promotion readiness metadata.
- Build and conversion logic for detection artifacts.
- Reviewer routing to validation and proof.

## What This Repo Does Not Own

- Validation execution results.
- Runtime platform state.
- Signal observation.
- Public proof approval.
- Website/public narrative authority.
- Human or AI final disposition.

## Reviewer Commands

Run from this repository root:

```powershell
python -B scripts/verify_detection_contract.py
python -B scripts/verify_detection_promotion_matrix.py
git diff --check
```

These commands verify source-contract shape, promotion-matrix boundaries, and whitespace cleanliness only. Passing checks do not prove runtime activity, signal observation, public-safe proof, production coverage, live SIEM/cloud routing, merge authority, or disposition approval.

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
- customer deployment
- autonomous SOC operation
- analyst-approved disposition
- AI-approved disposition
- AI-decided disposition

## Hiring Signal

This repo shows detection engineering discipline: explicit source packages, ATT&CK-aware behavior framing, event-field mapping, dependency-ordered validation handoff, source-side promotion metadata, reviewer routing, and blocked-claim hygiene.

The signal is not that source files magically prove an operating SOC. The signal is that detection work is structured so reviewers can inspect what exists, run the contract checks, follow the validation/proof handoff, and see exactly which claims remain blocked.

AI is labor. Governance is authority.

Build loud. Verify hard. Claim tight. Ship receipts.
