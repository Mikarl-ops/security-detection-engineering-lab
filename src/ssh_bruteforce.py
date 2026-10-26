"""Evaluate normalized SSH authentication events for rapid failure bursts."""

import argparse
import ipaddress
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


def parse_timestamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def load_events(path):
    events = []
    for line_number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON on line {line_number}") from exc
    return events


def detect_bursts(events, threshold=5, window_seconds=300):
    """Return one maximum failed-authentication burst per source IP."""
    if threshold < 1 or window_seconds < 1:
        raise ValueError("threshold and window_seconds must be positive")

    times_by_source = defaultdict(list)
    for event in events:
        if event.get("event") != "ssh_authentication" or event.get("outcome") != "failure":
            continue
        try:
            source_ip = str(ipaddress.ip_address(event["source_ip"]))
            timestamp = parse_timestamp(event["timestamp"])
        except (KeyError, TypeError, ValueError):
            continue
        times_by_source[source_ip].append(timestamp)

    detections = []
    window = timedelta(seconds=window_seconds)
    for source_ip, timestamps in times_by_source.items():
        timestamps.sort()
        left = 0
        largest = (0, None, None)
        for right, timestamp in enumerate(timestamps):
            while timestamp - timestamps[left] > window:
                left += 1
            count = right - left + 1
            if count > largest[0]:
                largest = (count, timestamps[left], timestamp)
        if largest[0] >= threshold:
            detections.append({
                "source_ip": source_ip,
                "failed_count": largest[0],
                "window_start": largest[1].isoformat().replace("+00:00", "Z"),
                "window_end": largest[2].isoformat().replace("+00:00", "Z"),
            })
    return sorted(detections, key=lambda finding: finding["source_ip"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", help="Path to normalized JSON Lines events")
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--window-seconds", type=int, default=300)
    args = parser.parse_args()
    for detection in detect_bursts(load_events(args.events), args.threshold, args.window_seconds):
        print(json.dumps(detection, sort_keys=True))


if __name__ == "__main__":
    main()
