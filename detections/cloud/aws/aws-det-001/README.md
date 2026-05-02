# AWS-DET-001

Fixture-only source candidate for denied or unauthorized IAM API activity in CloudTrail-style events.

## Scope

- Detection ID: `AWS-DET-001`
- Source class: CloudTrail-style JSON fixtures
- Current ceiling: `TEST_VALIDATED_SYNTHETIC_SCOPE`
- Public-safe status: `NOT_PUBLIC_SAFE`

This source does not use AWS credentials, live AWS APIs, production telemetry, or CloudTrail live evidence.

## Allowed Claim

`AWS-DET-001 passed fixture-only validation against controlled CloudTrail-style IAM denial fixtures.`

## Blocked Claims

- AWS-live proof
- AWS CloudTrail live proof
- Cloud runtime-active proof
- Production proof
- Public-safe runtime proof
- Signal-observed public proof

