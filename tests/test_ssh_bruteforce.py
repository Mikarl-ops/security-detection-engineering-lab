import unittest

from src.ssh_bruteforce import detect_bursts, load_events


class SshBurstTests(unittest.TestCase):
    def test_fixture_contains_expected_detection(self):
        detections = detect_bursts(load_events("data/auth_events.jsonl"))
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["source_ip"], "203.0.113.50")
        self.assertEqual(detections[0]["failed_count"], 5)

    def test_successes_and_out_of_window_failures_do_not_alert(self):
        events = [
            {"timestamp": "2026-10-24T02:00:00Z", "event": "ssh_authentication", "outcome": "failure", "source_ip": "198.51.100.2"},
            {"timestamp": "2026-10-24T02:10:00Z", "event": "ssh_authentication", "outcome": "failure", "source_ip": "198.51.100.2"},
            {"timestamp": "2026-10-24T02:10:05Z", "event": "ssh_authentication", "outcome": "success", "source_ip": "198.51.100.2"},
        ]
        self.assertEqual(detect_bursts(events, threshold=2), [])

    def test_rejects_invalid_threshold(self):
        with self.assertRaises(ValueError):
            detect_bursts([], threshold=0)


if __name__ == "__main__":
    unittest.main()
