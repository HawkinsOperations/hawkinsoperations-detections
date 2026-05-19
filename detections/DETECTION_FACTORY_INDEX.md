# HawkinsOperations Detection Factory Index

## Purpose

This file exposes the HawkinsOperations detection factory and its promotion state. It enumerates detection candidates, the surfaces they ride on, and the truth state of each candidate so reviewers can read detection breadth without inferring proof.

This index does not create proof. It does not promote proof. It is source-truth metadata only. Source existence, validation passage, and runtime evidence are separate planes and remain governed by their own repositories and approvals.

## Current Boundary

- Repo truth is not runtime truth.
- Source existence is not validation.
- Validation is not signal observation.
- Private runtime evidence is not public-safe proof.
- GitHub or website rendering is not proof.
- Proof promotion belongs in `hawkinsoperations-proof`.
- Validation behavior belongs in `hawkinsoperations-validation`.

## Detection Surfaces

The HawkinsOperations detection factory is intentionally multi-surface. Each candidate is associated with one or more of:

- Sigma YAML
- Splunk SPL
- Wazuh XML
- Security Onion / NDR
- Suricata candidate
- Zeek log candidate
- CloudTrail JSON fixture
- Sysmon field mapping
- Windows Event ID mapping
- Linux auth/audit
- Cowrie honeypot
- Cribl pipeline contract
- Python validators and scanners (support tooling only - not the detection product)

Python in this factory is QA machinery: validator logic, replay harnesses, proof-integrity checks, claim-boundary scanners, and fixture runners. The detection product is the detection content itself across the surfaces above.

## Truth States

Only the following truth states are used in this index:

- `SOURCE_EXISTS` - A detection source artifact is committed in this repository.
- `VALIDATION_PLANNED` - The candidate is identified and validation work is on the roadmap; no source or validation artifact has been promoted yet.
- `TEST_DEFINED` - A controlled test fixture or harness contract exists for the candidate.
- `CONTROLLED_TEST_VALIDATED` - The detection passed deterministic validation against controlled positive and negative fixtures only.
- `RUNTIME_EVIDENCE_CANDIDATE` - Runtime evidence is targeted but not captured; no runtime claim is supported.
- `PRIVATE_RUNTIME_EVIDENCE_CAPTURED` - Internal/controlled runtime evidence has been captured and is not public-safe.
- `LAB_RUNTIME_VALIDATED` - Validated in a controlled lab path; not equivalent to production behavior.
- `PUBLIC_SAFE_PROOF_READY` - Sanitized, reviewed, and approved for promotion through the proof repository.
- `BOUNDARY_CONTRACT_ONLY` - The artifact describes a visibility, field-preservation, or scope contract; it does not assert detection of a specific behavior.
- `BLOCKED` - The candidate cannot proceed under current authorization or evidence boundaries.
- `UNKNOWN` - State has not been classified.

A higher state is never inferred from a lower one. State changes require evidence and approval routed through the appropriate repository.

## Detection Factory Matrix

| ID | Detection | Detection surface | Artifact format | Primary telemetry source | Current truth state | Existing artifact | Next source artifact | Next validation gate | Next runtime/evidence gate | Blocked claims |
|---|---|---|---|---|---|---|---|---|---|---|
| HO-DET-001 | Suspicious PowerShell EncodedCommand | Splunk SPL + Sigma/Sysmon mapping | `.spl` + `.yml` + Sysmon mapping | Sysmon Event ID 1 process creation | `CONTROLLED_TEST_VALIDATED` | `detections/successor/ho-det-001/rule.yml`, `detections/successor/ho-det-001/splunk.spl`, `detections/hero/001-powershell-encoded-command/` | Field-mapping reference for non-Sysmon process-creation sources | Expanded fixture matrix in validation repo for false-positive boundary | Runtime evidence remains internal/private; not promoted | runtime-active, signal-observed, evidence-linked public proof, public-safe |
| HO-DET-002 | PowerShell suspicious flags and hidden execution behavior | Sigma + Splunk SPL | `.yml` + `.spl` | Sysmon Event ID 1 process creation | `VALIDATION_PLANNED` | none | Sigma source for `-NoP`, `-W Hidden`, `-Exec Bypass`, `-NonI` flag combinations | Controlled-test positive/negative fixture set in validation repo | Runtime evidence not in scope at this stage | runtime-active, signal-observed, evidence-linked public proof, public-safe |
| HO-DET-003 | certutil download/decode behavior | Sigma + Splunk SPL | `.yml` + `.spl` | Sysmon Event ID 1 process creation | `VALIDATION_PLANNED` | none | Sigma source for `certutil` with `-urlcache`, `-decode`, `-decodehex` patterns | Controlled-test fixture set covering download and decode variants | Runtime evidence not in scope at this stage | runtime-active, signal-observed, evidence-linked public proof, public-safe |
| HO-DET-004 | bitsadmin transfer behavior | Sigma + Splunk SPL | `.yml` + `.spl` | Sysmon Event ID 1 process creation | `VALIDATION_PLANNED` | none | Sigma source for `bitsadmin /transfer` and related arguments | Controlled-test fixture set with positive transfers and benign service usage | Runtime evidence not in scope at this stage | runtime-active, signal-observed, evidence-linked public proof, public-safe |
| HO-DET-005 | mshta launching script or remote content | Sigma + Splunk SPL | `.yml` + `.spl` | Sysmon Event ID 1 process creation | `VALIDATION_PLANNED` | none | Sigma source for `mshta.exe` invoking `vbscript:`, `javascript:`, or remote `.hta` | Controlled-test fixture set covering script and remote-content variants | Runtime evidence not in scope at this stage | runtime-active, signal-observed, evidence-linked public proof, public-safe |
| HO-DET-006 | rundll32 suspicious script/proxy execution | Sigma + Splunk SPL | `.yml` + `.spl` | Sysmon Event ID 1 process creation | `VALIDATION_PLANNED` | none | Sigma source for `rundll32` with `javascript:` or unusual export targets | Controlled-test fixture set distinguishing benign DLL loading from script-proxy abuse | Runtime evidence not in scope at this stage | runtime-active, signal-observed, evidence-linked public proof, public-safe |
| HO-DET-007 | regsvr32 scriptlet/scrobj behavior | Sigma + Splunk SPL | `.yml` + `.spl` | Sysmon Event ID 1 process creation | `VALIDATION_PLANNED` | none | Sigma source for `regsvr32` with `/i:`, `scrobj.dll`, or remote `.sct` | Controlled-test fixture set covering scriptlet and remote-COM variants | Runtime evidence not in scope at this stage | runtime-active, signal-observed, evidence-linked public proof, public-safe |
| HO-DET-008 | Suspicious child process from Office, browser, or user shell | Sigma + Sysmon field mapping | `.yml` + Sysmon mapping table | Sysmon Event ID 1 with parent-image context | `VALIDATION_PLANNED` | none | Sigma source plus parent/child mapping table for productivity and browser parents | Controlled-test fixture set covering common office macros and browser child-spawn | Runtime evidence not in scope at this stage | runtime-active, signal-observed, evidence-linked public proof, public-safe |
| HO-DET-009 | Local user creation | Wazuh XML + Windows Event ID + Splunk SPL | `.xml` + Event ID mapping + `.spl` | Windows Security Event ID 4720 | `VALIDATION_PLANNED` | none | Wazuh XML rule plus Event ID 4720 mapping plus equivalent SPL | Controlled-test event fixture set with positive creations and tuning notes | Runtime evidence not in scope at this stage | runtime-active, signal-observed, evidence-linked public proof, public-safe |
| HO-DET-010 | Local administrators group membership change | Wazuh XML + Windows Event ID + Splunk SPL | `.xml` + Event ID mapping + `.spl` | Windows Security Event IDs 4732 and 4728 | `VALIDATION_PLANNED` | none | Wazuh XML rule plus Event ID 4732/4728 mapping plus equivalent SPL | Controlled-test event fixture set with positive privileged-group changes | Runtime evidence not in scope at this stage | runtime-active, signal-observed, evidence-linked public proof, public-safe |
| HO-DET-011 | Windows service creation or service binary change | Sigma + Wazuh XML + Splunk SPL | `.yml` + `.xml` + `.spl` | Windows System Event ID 7045 / Windows Security Event ID 4697 where available, plus Sysmon Event ID 1 context | `PRIVATE_RUNTIME_EVIDENCE_CAPTURED` | `detections/successor/ho-det-011/rule.yml`, `detections/successor/ho-det-011/wazuh.xml`, `detections/successor/ho-det-011/splunk.spl`, `hawkinsoperations-validation/reports/ho-det-011/validation-result.json`, `hawkinsoperations-proof/proof/records/HO-DET-011.md` | No new source artifact required for the current validated scope; continue source tuning only under separate approval | Validation PR #26 passed 17 controlled-test fixtures: 7 positives, 10 negatives, 7 matched positives, 0 missed positives, and 0 false-positive negatives | Private local Windows runtime evidence is recorded in the proof repo; next gate is event-specific Wazuh/Splunk/Cribl correlation review and public evidence-link/redaction review before any routed or public-safe wording | runtime-active, signal-observed, evidence-linked public proof, public-safe, Splunk observed, Wazuh observed, Cribl-routed, Security Onion observed, production-ready, fleet-wide, service-creation coverage completeness |
| HO-DET-012 | Suspicious scheduled task creation | Sigma + Wazuh XML + Splunk SPL | `.yml` + `.xml` + `.spl` | Windows Security Event IDs 4698/4702, TaskScheduler Operational Event IDs 106/140 where collected, and Sysmon Event ID 1 for task creation tooling | `CONTROLLED_TEST_VALIDATED` | `detections/successor/ho-det-012/rule.yml`, `detections/successor/ho-det-012/wazuh.xml`, `detections/successor/ho-det-012/splunk.spl`, `detections/successor/ho-det-012/event-mapping.yml`, `detections/successor/ho-det-012/status.yml`, `hawkinsoperations-validation/reports/ho-det-012/validation-result.json` | No new source artifact required for the current controlled-test scope; future tuning only under separate approval | Controlled-test validation passed 8 fixtures: 4 positives, 4 negatives, 4 matched positives, 0 missed positives, and 0 false-positive negatives | Runtime evidence not in scope at this stage | runtime-active, signal-observed, evidence-linked public proof, public-safe, Splunk-fired, Wazuh-routed, Cribl-routed, Security Onion observed, scheduled-task coverage completeness |
| HO-DET-013 | SSH failed-login burst followed by success candidate | Linux auth/audit + Wazuh XML + Splunk SPL | auth log mapping + `.xml` + `.spl` | Linux `auth.log` / `secure` and `sshd` events | `VALIDATION_PLANNED` | none | Field-mapping doc for `sshd` failed/accepted events plus Wazuh XML correlation rule plus SPL | Controlled-test auth log fixture set replaying failed-burst-then-success and benign control | Runtime evidence not in scope at this stage | runtime-active, signal-observed, evidence-linked public proof, public-safe |
| HO-DET-014 | sudo or root command pattern outside expected admin lane | Linux auth/audit + Wazuh XML | auth log mapping + `.xml` | Linux `auth.log` / `secure` `sudo` events | `VALIDATION_PLANNED` | none | Field-mapping doc for `sudo` user/command/cwd plus Wazuh XML rule with allowlisted admin lane | Controlled-test fixture set covering allowlisted and unexpected sudo invocations | Runtime evidence not in scope at this stage | runtime-active, signal-observed, evidence-linked public proof, public-safe |
| HO-DET-015 | Wazuh agent lifecycle anomaly | Wazuh manager event + Wazuh XML | `.xml` + manager event mapping | Wazuh manager `ossec-monitord` agent disconnect/restart events | `VALIDATION_PLANNED` | none | Wazuh XML rule plus manager event mapping for disconnect, restart, and version-change patterns | Controlled-test manager event fixture set covering normal restart and unexpected disconnect | Runtime evidence not in scope at this stage | runtime-active, signal-observed, evidence-linked public proof, public-safe |
| HO-DET-016 | Cowrie honeypot login or session command capture | Cowrie event detection + Wazuh or Splunk route | Cowrie event mapping + `.xml` or `.spl` candidate | Cowrie JSON event log | `VALIDATION_PLANNED` | none | Cowrie event field mapping plus Wazuh XML or SPL candidate covering login and command-input events | Controlled-test Cowrie event fixture set covering credential-spray and post-login command capture | Runtime evidence not in scope at this stage | runtime-active, signal-observed, evidence-linked public proof, public-safe |
| HO-NDR-001 | Security Onion packet/module visibility boundary and cross-source corroboration scaffold | Security Onion / NDR visibility contract | sanitized JSON contracts + verifiers | Security Onion sensor module enablement metadata plus planned controlled event correlation fields | `BOUNDARY_CONTRACT_ONLY` | `hawkinsoperations-validation/validation/security-onion/ho-ndr-001/visibility-rollup.sample.json`, `hawkinsoperations-validation/validation/security-onion/ho-ndr-001/cross-source-corroboration.sample.json`, `hawkinsoperations-proof/docs/boundaries/HO-NDR-001-SECURITY-ONION-VISIBILITY-CONTRACT.md`, `hawkinsoperations-proof/proof/cards/HO-NDR-001.md` | No new detection source artifact required for the scaffold; future runtime packet only after separate approval. No published HO-NDR-001 proof record exists. The local draft remains unpublished, parked, and NOT_PUBLIC_SAFE. | Validation harnesses assert contract shape and blocked-claim guardrails, not packet content or runtime behavior | Runtime evidence remains blocked pending separate approved event generation, Security Onion event summary, endpoint/Wazuh summary, Splunk correlation summary, and optional Cribl event-specific receipt | runtime-active, signal-observed, evidence-linked public proof, public-safe, PCAP availability, permanent SPAN, durable monitoring, cross-source corroboration captured, Security Onion telemetry forwarded to Splunk, Splunk search executed, Cribl route proven, JA4+ support, Strelka/YARA workflow |
| HO-NDR-002 | Suspicious scan visibility candidate | Suricata candidate + Zeek log candidate | Suricata candidate + Zeek field mapping | Suricata alert event and Zeek `conn.log` field set | `VALIDATION_PLANNED` | none | Suricata candidate rule plus Zeek `conn.log` field mapping for scan-shaped flow patterns | Controlled-test flow fixture set or sanitized Zeek log fixture set | Runtime evidence not in scope at this stage | runtime-active, signal-observed, evidence-linked public proof, public-safe, Zeek coverage completeness, Suricata detection quality |
| AWS-DET-001 | Denied IAM API activity from CloudTrail-style events | CloudTrail JSON fixture | JSON fixture + `rule.yml` with `eventSource`/`errorCode` matchers | CloudTrail-style JSON event with `iam.amazonaws.com` source | `CONTROLLED_TEST_VALIDATED` | `detections/cloud/aws/aws-det-001/rule.yml`, `detections/cloud/aws/aws-det-001/cloudtrail.jsonpath` | Expanded fixture set covering additional denial error codes | Boundary fixture set distinguishing denial from misconfiguration noise | Runtime evidence not in scope; AWS-live remains explicitly blocked | AWS-live, AWS CloudTrail live, cloud runtime-active, public-safe runtime, signal-observed public proof |
| HO-PIPE-001 | Cribl marker delivery and required-field preservation candidate | Cribl pipeline contract + Splunk rawdata marker | pipeline contract + field-preservation matrix | Cribl pipeline configuration metadata and downstream Splunk index marker fields | `SOURCE_EXISTS` | `detections/successor/ho-pipe-001/cribl-pipeline.yml` | Field-preservation matrix plus verifier for the source-controlled pipeline contract | Verifier that asserts contract shape and required-field set, not delivered traffic | Runtime observations, counts, markers, and Splunk result details are excluded from this source artifact and require separate private evidence review | runtime-active, signal-observed, evidence-linked public proof, public-safe, Cribl-routed live, fleet-wide deployment, perfect keep-event throughput |

## First Five Build Targets

After HO-DET-001, the next five candidates are selected for the best mix of safe validation, enterprise relevance, multi-surface value, and fastest proof-loop path:

- **HO-DET-002 - PowerShell suspicious flags and hidden execution behavior.** Reuses the HO-DET-001 telemetry source and fixture pattern, expands the same authoring lane to a second Sigma + SPL pair, and lets the validation harness exercise additional positive/negative shapes without new infrastructure.
- **HO-DET-003 - certutil download/decode behavior.** Living-off-the-land binary with high enterprise SOC relevance, narrow argument surface, and a clean false-positive boundary that maps cleanly to a controlled-test fixture set.
- **HO-DET-010 - Local administrators group membership change.** Adds Wazuh XML and Windows Event ID surfaces to the visible factory, exercises the auth-event lane, and is one of the most consistently expected SOC detections in enterprise reviews.
- **HO-DET-011 - Windows service creation or service binary change.** Combines Sigma, Wazuh XML, and SPL on a single candidate, now backed by validation PR #26 with 17 controlled-test fixtures. Its proof record preserves `PRIVATE_RUNTIME_EVIDENCE_CAPTURED`, `CONTROLLED_TEST_VALIDATED` for the validation layer, and `NOT_PUBLIC_SAFE` for public use.
- **HO-NDR-001 - Security Onion packet/module visibility boundary.** Establishes the NDR plane as a contract-only artifact, makes the visibility boundary explicit before any NDR detection claims, and adds a cross-source corroboration scaffold for a future separately approved controlled event.

These targets keep source and validation work bounded to deterministic fixture scope unless a separate proof record already preserves a stricter private boundary. HO-DET-011 is routed to the proof repo for its private runtime boundary and remains `NOT_PUBLIC_SAFE` for public use. The remaining targets do not require new runtime systems, do not promote runtime claims, and do not require evidence promotion through the proof repository.

## V1 Firewall

These candidates are curated for the current HawkinsOperations architecture. They are not copied from any prior HawkinsOps V1 detection inventory, do not migrate V1 detections, and do not import V1 wording or metrics. Older inventories are referenced, if at all, only as historical inspiration for broad detection categories. V1 metrics are not current HawkinsOperations truth and must not be cited as such.

## Blocked Claims

This index does not claim, and must not be cited as evidence for, any of the following: runtime-active, signal-observed, evidence-linked public proof, public-safe, live Splunk firing, production triage, analyst-approved disposition, HO-GPU-01 runtime-active, Cribl-routed, Wazuh-routed, AWS-live, autonomous SOC, production-ready SOC, fleet-wide deployment, enterprise deployed, AI-approved disposition, AI-decided disposition, production AutoSOC, production NDR, permanent SPAN, durable monitoring, PCAP availability, long-term retention, cross-source corroboration, Zeek coverage completeness, or Suricata detection quality.

The presence of a candidate in this matrix is not evidence that the candidate has been validated, signaled, deployed, or proven. The current truth state column is the only authoritative state for each candidate, and is itself bounded by the truth state definitions above.

## Next Gate

- Source artifacts for the next five build targets are authored in this repository under `detections/`.
- Validation fixtures and harnesses for those candidates are authored in `hawkinsoperations-validation`.
- Runtime evidence may only be pursued after explicit runtime approval, and remains internal/non-public until reviewed.
- Proof promotion may only occur through `hawkinsoperations-proof` after evidence review, privacy review, stale-state review, wording review, and Raylee approval.
