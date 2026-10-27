# Security Detection Engineering Lab

A small detection-as-code project for Linux SSH authentication failures. It includes a Sigma rule, a local evaluator for normalized event records, synthetic examples, and unit tests for detection boundaries and non-matching behavior.

## Detection objective

Detect at least **five failed SSH authentications from one source IP within a rolling 300-second window**. The Python evaluator returns the largest qualifying burst per source. A failure exactly 300 seconds after the first event remains within the configured window; an event beyond that boundary does not.

All addresses and identities in the sample data are synthetic documentation ranges.

## Run locally

Use Python 3.11 or newer. From the repository root, run:

```bash
python src/ssh_bruteforce.py data/auth_events.jsonl
python -m unittest discover -s tests -v
```

The evaluator reads JSON Lines with `timestamp`, `event`, `outcome`, `source_ip`, and optional `user` fields. It normalizes timestamps to UTC, validates IP addresses, and returns the largest matching burst for each source.

## Test coverage

The automated tests cover:

- Four failures versus the five-event alert threshold.
- Five failures within the window and the exact 300-second boundary.
- A failure beyond the rolling window.
- Separate source IPs (counts must not be combined).
- Successful logins (must not count as failures).
- Mixed timezone offsets normalized to UTC.
- Malformed timestamps, invalid IP addresses, unrelated event types, and invalid configuration.

## Sigma rule

The Sigma rule is in `detections/linux_ssh_bruteforce.yml`. It expects a backend mapping that exposes the raw message as `message` and the source address as `SourceIp`. The local evaluator uses `source_ip`. Confirm field mapping and aggregation semantics for the target SIEM before deployment.

## False-positive analysis and triage

This threshold is a starting point, not proof of malicious activity.

| Possible cause | Why it can trigger | Suggested analyst check |
| --- | --- | --- |
| Legitimate user mistyping a password | Several retries can occur in a short period | Correlate the account, source, and successful authentication; confirm with the user through an approved channel |
| Misconfigured automation or expired secret | A scheduled job may repeatedly retry stale credentials | Check change records, job identity, deployment logs, and secret-rotation history |
| Shared NAT, VPN, or jump host | Multiple people may appear under one egress IP | Correlate usernames, device identity, VPN/jump-host logs, and session context |
| Internet-facing host under password guessing | Many failures may precede a successful login or target multiple accounts | Review targeted usernames, later successes, source reputation, and adjacent host telemetry |

**Triage guidance:** preserve the relevant authentication records; establish the source, targeted accounts, and time range; look for a success after the failure burst; correlate with VPN, endpoint, and identity logs; and escalate according to the environment's incident-response process. Do not block an IP solely because this demonstration rule fired.

## Tuning and limitations

The threshold is a teaching baseline. Password managers, automation, jump hosts, NAT, and shared egress can change expected failure rates. The local evaluator is a transparent reference implementation; it is not a SIEM backend or a replacement for identity-aware correlation. It skips malformed events and treats naive timestamps as UTC. The Sigma rule remains experimental until tested against the target log source and production-like data.

## Validation

GitHub Actions runs the standard-library unit tests on pushes and pull requests to `main`.
