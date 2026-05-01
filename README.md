# HawkinsOperations Detections

Detection content and rule engineering for HawkinsOperations.

Owner identity: Raylee Hawkins, Detection Engineer | SOC Automation | Detection-as-Code | Security Automation.

Official links: [Raylee Hawkins on LinkedIn](https://www.linkedin.com/in/raylee-hawkins) · [Raylee Hawkins on GitHub](https://github.com/raylee-hawkins) · [HawkinsOps detection engineering portfolio](https://hawkinsops.com) · [HawkinsOperations GitHub organization](https://github.com/HawkinsOperations) · [RayleeOps public operating journal](https://rayleeops.com)

## Purpose

This repository contains detection logic as source content. It is the authoring layer for production-bound security detections.

## HawkinsOperations Closed SOC Loop 001

- GitHub Projects: pending access / attachment. Current org project route: https://github.com/orgs/HawkinsOperations/projects
- Reviewer entry point: https://github.com/HawkinsOperations/.github/blob/main/profile/START_HERE.md
- HO-DET-001 public proof route: https://github.com/HawkinsOperations/hawkinsoperations-proof/blob/main/proof/records/HO-DET-001.md
- Current HO-DET-001 ceiling: TEST_VALIDATED_SYNTHETIC_SCOPE
- HawkinsOperations is the governed successor system; HawkinsOps and older surfaces are legacy/reference unless revalidated.
- Truth surface: detection source truth. This repository proves source existence and detection-authoring structure only.
- Sprint thesis: speed with enforcement through deterministic validation, CI/CD gates, evidence records, proof contracts, and bounded public claims.
- AI is labor. Governance is authority.
- Build loud. Verify hard. Claim tight. Ship receipts.
- Website/public pages route to proof records; they do not replace proof.
- Next gates: case packet spine, deterministic verifier, claim-boundary scanner, CI proof-loop, proof card, website route.

## Blocked Claims

This repository does not claim: runtime-active, signal-observed, evidence-linked public proof, public-safe, live Splunk firing, production triage, analyst-approved disposition, HO-GPU-01 runtime-active, Cribl-routed, Wazuh-routed, AWS-live, autonomous SOC, production-ready SOC, fleet-wide deployment, or AI-approved disposition.

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

## Reviewed External Proof Candidates

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
