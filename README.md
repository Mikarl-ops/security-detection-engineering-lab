# Security Detection Engineering Lab

A small detection-as-code project for Linux SSH authentication failures. It includes a Sigma rule, a local evaluator for normalized event records, synthetic examples, and tests for both matching and non-matching behavior.

## Scenario

The lab asks whether one source generated at least five failed SSH authentications within a rolling five-minute window. The sample data contains one such burst, successful logins, and a low-volume source. All addresses and identities are synthetic.

## Run locally

Use Python 3.11 or newer. From the repository root, run:

    python src/ssh_bruteforce.py data/auth_events.jsonl
    python -m unittest discover -s tests -v

The evaluator reads JSON Lines with timestamp, event, outcome, source_ip, and optional user fields. It normalizes timestamps to UTC, validates IP addresses, and returns the largest matching burst for each source.

## Sigma rule

The Sigma rule is in detections/linux_ssh_bruteforce.yml. It expects a backend mapping that exposes the raw message as message and the source address as SourceIp. The local evaluator uses source_ip. Confirm field mapping and aggregation semantics for the target SIEM before deployment.

## Tuning and limitations

The threshold is a teaching baseline. Password managers, automation, jump hosts, NAT, and shared egress can change expected failure rates. The local evaluator is a transparent reference implementation; it is not a SIEM backend or a replacement for identity-aware correlation. The rule is experimental until tested against the target log source and production-like data.

## Validation

GitHub Actions runs the standard-library unit tests on pushes and pull requests to main.
