import unittest

from src.ssh_bruteforce import detect_bursts, load_events


def event(seconds, source_ip="198.51.100.2", outcome="failure", timestamp_base="2026-10-24T02:00:00"):
    from datetime import datetime, timedelta, timezone

    start = datetime.fromisoformat(timestamp_base).replace(tzinfo=timezone.utc)
    timestamp = (start + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")
    return {
        "timestamp": timestamp,
        "event": "ssh_authentication",
        "outcome": outcome,
        "source_ip": source_ip,
    }


class SshBurstTests(unittest.TestCase):
    def test_fixture_contains_expected_detection(self):
        detections = detect_bursts(load_events("data/auth_events.jsonl"))
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["source_ip"], "203.0.113.50")
        self.assertEqual(detections[0]["failed_count"], 5)

    def test_exact_threshold_alerts_and_one_below_does_not(self):
        four_failures = [event(seconds) for seconds in (0, 20, 40, 60)]
        five_failures = four_failures + [event(80)]

        self.assertEqual(detect_bursts(four_failures), [])
        detections = detect_bursts(five_failures)
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["failed_count"], 5)

    def test_exactly_five_minutes_is_inclusive(self):
        events = [event(seconds) for seconds in (0, 60, 120, 180, 300)]
        detections = detect_bursts(events)
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["failed_count"], 5)

    def test_event_outside_five_minute_window_does_not_complete_threshold(self):
        events = [event(seconds) for seconds in (0, 60, 120, 180, 301)]
        self.assertEqual(detect_bursts(events), [])

    def test_failures_from_different_sources_are_not_combined(self):
        events = [
            event(0, "198.51.100.2"),
            event(10, "198.51.100.2"),
            event(20, "198.51.100.2"),
            event(0, "198.51.100.3"),
            event(10, "198.51.100.3"),
            event(20, "198.51.100.3"),
        ]
        self.assertEqual(detect_bursts(events), [])

    def test_successful_logins_do_not_count_towards_threshold(self):
        events = [
            event(0),
            event(10),
            event(20),
            event(30),
            event(40, outcome="success"),
        ]
        self.assertEqual(detect_bursts(events), [])

    def test_timezone_offsets_are_normalized_to_utc(self):
        events = [
            {"timestamp": "2026-10-24T10:00:00+08:00", "event": "ssh_authentication", "outcome": "failure", "source_ip": "198.51.100.2"},
            {"timestamp": "2026-10-24T02:00:30Z", "event": "ssh_authentication", "outcome": "failure", "source_ip": "198.51.100.2"},
            {"timestamp": "2026-10-24T02:01:00Z", "event": "ssh_authentication", "outcome": "failure", "source_ip": "198.51.100.2"},
            {"timestamp": "2026-10-24T02:01:30Z", "event": "ssh_authentication", "outcome": "failure", "source_ip": "198.51.100.2"},
            {"timestamp": "2026-10-24T02:02:00Z", "event": "ssh_authentication", "outcome": "failure", "source_ip": "198.51.100.2"},
        ]
        detections = detect_bursts(events)
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["window_start"], "2026-10-24T02:00:00Z")

    def test_malformed_events_and_invalid_addresses_are_ignored(self):
        events = [
            event(0),
            event(10),
            {"timestamp": "not-a-timestamp", "event": "ssh_authentication", "outcome": "failure", "source_ip": "198.51.100.2"},
            {"timestamp": "2026-10-24T02:00:20Z", "event": "ssh_authentication", "outcome": "failure", "source_ip": "not-an-ip"},
            {"timestamp": "2026-10-24T02:00:30Z", "event": "dns_query", "outcome": "failure", "source_ip": "198.51.100.2"},
        ]
        self.assertEqual(detect_bursts(events), [])

    def test_rejects_invalid_threshold_and_window(self):
        with self.assertRaises(ValueError):
            detect_bursts([], threshold=0)
        with self.assertRaises(ValueError):
            detect_bursts([], window_seconds=0)


if __name__ == "__main__":
    unittest.main()
