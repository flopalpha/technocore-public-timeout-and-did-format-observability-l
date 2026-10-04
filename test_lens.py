import json
import tempfile
import unittest
from pathlib import Path
import lens
import cli


def make_valid_did():
    raw = b"\xed\x01" + b"\x02" * 32
    return "did:key:z" + lens.b58encode(raw)


class TestClassify(unittest.TestCase):
    def test_timeout_408(self):
        line = "2026-03-01 10:00:01 GET /poll 408 Request Timeout elapsed=1200ms timer=longpoll"
        self.assertEqual(lens.classify_http_line(line), "timeout_408")

    def test_timeout_word_with_timer(self):
        line = "2026-03-01 10:01:00 poll timeout after 2000ms timer fired"
        self.assertEqual(lens.classify_http_line(line), "timeout_408")

    def test_refusal_no_timer(self):
        line = "2026-03-01 10:02:00 GET /poll connection refused no timer"
        self.assertEqual(lens.classify_http_line(line), "refusal_no_timer")

    def test_unknown_empty(self):
        self.assertEqual(lens.classify_http_line("   "), "unknown")

    def test_other(self):
        self.assertEqual(lens.classify_http_line("hello world"), "other")

    def test_per_hour_counts(self):
        lines = [
            "2026-03-01 10:00:01 GET /poll 408 timeout",
            "2026-03-01 10:05:00 GET /poll refused no timer",
            "2026-03-01 11:00:00 hello",
        ]
        by_hour = lens.count_http_by_hour(lines)
        self.assertIn("2026-03-01 10:00", by_hour)
        self.assertEqual(by_hour["2026-03-01 10:00"]["timeout_408"], 1)
        self.assertEqual(by_hour["2026-03-01 10:00"]["refusal_no_timer"], 1)


class TestDid(unittest.TestCase):
    def test_valid_ed25519(self):
        did = make_valid_did()
        res = lens.validate_did_key(did)
        self.assertTrue(res["valid"])
        self.assertEqual(res["codec"], "ed25519")

    def test_valid_x25519(self):
        raw = b"\xec\x01" + b"\x03" * 32
        did = "did:key:z" + lens.b58encode(raw)
        res = lens.validate_did_key(did)
        self.assertTrue(res["valid"])

    def test_bad_prefix(self):
        res = lens.validate_did_key("did:key:z00")
        self.assertFalse(res["valid"])

    def test_missing_prefix(self):
        res = lens.validate_did_key("did:web:example")
        self.assertFalse(res["valid"])

    def test_bad_char(self):
        did = make_valid_did() + "0"
        res = lens.validate_did_key(did)
        self.assertFalse(res["valid"])

    def test_find_keys(self):
        did = make_valid_did()
        found = lens.find_did_keys("here is " + did + " ok")
        self.assertEqual(found, [did])

    def test_roundtrip_base58(self):
        raw = b"\xed\x01" + bytes(range(32))
        enc = lens.b58encode(raw)
        back = lens.b58decode(enc)
        self.assertEqual(back, raw)


class TestReader(unittest.TestCase):
    def test_parse_seq(self):
        self.assertEqual(lens.parse_seq("poll seq 42 ok"), 42)
        self.assertEqual(lens.parse_seq("Sequence: 7"), 7)
        self.assertIsNone(lens.parse_seq("no counter here"))

    def test_gaps_and_restarts(self):
        info = lens.analyze_sequences([1, 2, 3, 6, 7, 2])
        self.assertEqual(info["gap_count"], 1)
        self.assertEqual(info["restart_count"], 1)
        self.assertEqual(info["max_gap"], 2)

    def test_continuous(self):
        info = lens.analyze_sequences([10, 11, 12])
        self.assertEqual(info["gap_count"], 0)
        self.assertEqual(info["restart_count"], 0)
        self.assertEqual(info["continuity"], 1.0)

    def test_empty(self):
        info = lens.analyze_sequences([])
        self.assertEqual(info["count"], 0)


class TestHeartbeat(unittest.TestCase):
    def test_heartbeat_detect(self):
        self.assertTrue(lens.is_heartbeat("heartbeat online uptime 5h"))
        self.assertTrue(lens.is_heartbeat("agent online still online"))
        self.assertFalse(lens.is_heartbeat("GET /poll 408 timeout"))

    def test_signal_detect(self):
        self.assertTrue(lens.is_signal("GET /poll 408 timeout"))
        self.assertTrue(lens.is_signal("did:key:zabc error"))
        self.assertFalse(lens.is_signal("heartbeat online uptime 1h"))

    def test_ratio(self):
        lines = [
            "heartbeat online uptime 1h load 0.2",
            "heartbeat online uptime 1h load 0.3",
            "GET /poll 408 timeout elapsed 1ms timer x",
            "plain note",
        ]
        hb = lens.heartbeat_stats(lines)
        self.assertEqual(hb["heartbeat"], 2)
        self.assertEqual(hb["signal"], 1)
        self.assertEqual(hb["other"], 1)

    def test_top_templates(self):
        lines = ["heartbeat uptime 10", "heartbeat uptime 20", "error 408 x"]
        tops = lens.top_templates(lines, limit=2)
        self.assertEqual(tops[0]["count"], 2)
        self.assertIn("#", tops[0]["template"])


class TestSummary(unittest.TestCase):
    def test_analyze_and_json(self):
        did = make_valid_did()
        lines = [
            "2026-03-01 10:00:01 GET /poll 408 Request Timeout elapsed=5ms timer=a seq 1",
            "2026-03-01 10:01:00 heartbeat online uptime 2h load 0.1 seq 2",
            "2026-03-01 10:02:00 connection refused no timer seq 5 " + did,
        ]
        summary = lens.analyze_lines(lines)
        self.assertEqual(summary["total_lines"], 3)
        self.assertEqual(summary["http_buckets"]["timeout_408"], 1)
        self.assertEqual(summary["http_buckets"]["refusal_no_timer"], 1)
        self.assertEqual(summary["did_checks"]["total_found"], 1)
        text = lens.summary_to_json(summary)
        back = json.loads(text)
        self.assertEqual(back["total_lines"], 3)
        md = lens.summary_to_markdown(summary)
        self.assertIn("Technocore", md)
        self.assertIn("408", md)

    def test_sha_deterministic(self):
        a = lens.sha256_text("abc")
        b = lens.sha256_text("abc")
        self.assertEqual(a, b)
        self.assertEqual(len(a), 64)

    def test_cli_with_tempfile(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.log"
            src.write_text("heartbeat online uptime 1h\nGET /poll 408 timeout\n", encoding="utf-8")
            jout = Path(td) / "out.json"
            mout = Path(td) / "out.md"
            rc = cli.main(["--input", str(src), "--json-out", str(jout), "--md-out", str(mout)])
            self.assertEqual(rc, 0)
            data = json.loads(jout.read_text(encoding="utf-8"))
            self.assertEqual(data["total_lines"], 2)
            self.assertIn("input_sha256", data)
            md = mout.read_text(encoding="utf-8")
            self.assertIn("Heartbeat", md)


if __name__ == "__main__":
    unittest.main()
