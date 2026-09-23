"""Safety-gate tests: prestart decision, cache, and --force behavior.

All offline; fixtures are tiny local PDFs. The gate must STOP huge
searches without --force (showing duration + exact rerun command) while
letting small/beginner searches start automatically. Clue stages (empty,
wordlist) always run before the gate.
"""
from __future__ import annotations

import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from typing import Optional
from unittest import mock


def _make_pdf(path: str, password: Optional[str]):
    from pypdf import PdfWriter

    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    if password is not None:
        writer.encrypt(password)
    with open(path, "wb") as fh:
        writer.write(fh)


BIG = "printable"
BIG_MIN, BIG_MAX = 1, 8


class TestPrestartDecision(unittest.TestCase):
    def test_small_space_proceeds(self):
        from pdf_recovery.benchmark import prestart_decision
        from pdf_recovery.candidates import auto_space_total

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "s.pdf")
            _make_pdf(pdf, "ab")
            total = auto_space_total("ab", 1, 2)
            dec = prestart_decision(pdf, "m", 2, total, workers_probe=1,
                                    samples=4, cache_path=None, force=False)
            self.assertTrue(dec["proceed"])
            self.assertGreater(dec["rate"], 0)

    def test_huge_space_gated(self):
        from pdf_recovery.benchmark import prestart_decision
        from pdf_recovery.candidates import CHARSET_PRESETS, auto_space_total

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "h.pdf")
            _make_pdf(pdf, "ab")
            total = auto_space_total(CHARSET_PRESETS[BIG], BIG_MIN, BIG_MAX)
            dec = prestart_decision(pdf, "m", 94, total, workers_probe=1,
                                    samples=4, cache_path=None, force=False)
            self.assertFalse(dec["proceed"])
            self.assertIn("duration", dec)
            self.assertGreater(dec["seconds"], 0)

    def test_force_short_circuits_without_measuring(self):
        from pdf_recovery.benchmark import prestart_decision

        with mock.patch("pdf_recovery.benchmark.measure_throughput",
                        side_effect=AssertionError("must not measure")):
            dec = prestart_decision("/tmp/x.pdf", "m", 94, 10**15,
                                    cache_path=None, force=True)
        self.assertTrue(dec["proceed"])
        self.assertTrue(dec["forced"])


class TestBenchmarkCache(unittest.TestCase):
    def test_store_load_and_mismatch(self):
        from pdf_recovery.benchmark import (
            default_benchmark_cache_path,
            load_benchmark_cache,
            store_benchmark_cache,
        )

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "c.pdf")
            _make_pdf(pdf, "ab")
            cache = default_benchmark_cache_path(os.path.join(d, "ck.json"))
            self.assertIsNone(load_benchmark_cache(cache, pdf, "m", 1))
            store_benchmark_cache(cache, pdf, "m", 1, 123.0, 12, 0.1)
            self.assertAlmostEqual(load_benchmark_cache(cache, pdf, "m", 1), 123.0)
            self.assertIsNone(load_benchmark_cache(cache, pdf, "m", 2))  # workers differ
            self.assertIsNone(load_benchmark_cache(cache, pdf, "other", 1))  # method differs

    def test_cached_probe_reused(self):
        from pdf_recovery.benchmark import prestart_decision
        from pdf_recovery.candidates import CHARSET_PRESETS, auto_space_total

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "h.pdf")
            _make_pdf(pdf, "ab")
            cache = os.path.join(d, "bench.json")
            total = auto_space_total(CHARSET_PRESETS[BIG], BIG_MIN, BIG_MAX)
            first = prestart_decision(pdf, "m", 94, total, workers_probe=1,
                                      samples=4, cache_path=cache, force=False)
            self.assertFalse(first["proceed"])
            self.assertFalse(first["cached"])
            self.assertTrue(os.path.exists(cache))
            with mock.patch("pdf_recovery.benchmark.measure_throughput",
                            side_effect=AssertionError("should use cache")):
                second = prestart_decision(pdf, "m", 94, total, workers_probe=1,
                                           samples=4, cache_path=cache, force=False)
            self.assertFalse(second["proceed"])
            self.assertTrue(second["cached"])


class TestEngineGate(unittest.TestCase):
    def test_huge_gated_no_checkpoint(self):
        from pdf_recovery.candidates import CHARSET_PRESETS, auto_space_total
        from pdf_recovery.engine import run_unified_recovery

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "g.pdf")
            _make_pdf(pdf, "ab")
            charset = CHARSET_PRESETS[BIG]
            total = auto_space_total(charset, BIG_MIN, BIG_MAX)
            res = run_unified_recovery(pdf, charset, BIG_MIN, BIG_MAX, total,
                                       workers=1, show_progress=False,
                                       checkpoint_path=os.path.join(d, "c.json"),
                                       checkpoint_meta={},
                                       bench_cache_path=os.path.join(d, "b.json"))
            self.assertEqual(res["status"], "gated")
            self.assertIsNone(res["password"])
            self.assertFalse(os.path.exists(os.path.join(d, "c.json")))
            self.assertIn("duration", res["gate"])

    def test_huge_forced_proceeds(self):
        from pdf_recovery.candidates import CHARSET_PRESETS, auto_space_total
        from pdf_recovery.engine import run_unified_recovery

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "g.pdf")
            _make_pdf(pdf, "ab")
            charset = CHARSET_PRESETS[BIG]
            total = auto_space_total(charset, BIG_MIN, BIG_MAX)
            res = run_unified_recovery(pdf, charset, BIG_MIN, BIG_MAX, total,
                                       workers=1, show_progress=False, limit=5,
                                       force=True,
                                       checkpoint_path=os.path.join(d, "c.json"),
                                       checkpoint_meta={},
                                       bench_cache_path=os.path.join(d, "b.json"))
            self.assertEqual(res["status"], "not_found")
            self.assertTrue(res["truncated"])

    def test_empty_check_runs_before_gate(self):
        from pdf_recovery.candidates import CHARSET_PRESETS, auto_space_total
        from pdf_recovery.engine import run_unified_recovery

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "e.pdf")
            _make_pdf(pdf, "")
            charset = CHARSET_PRESETS[BIG]
            total = auto_space_total(charset, BIG_MIN, BIG_MAX)
            res = run_unified_recovery(pdf, charset, BIG_MIN, BIG_MAX, total,
                                       workers=1, show_progress=False,
                                       checkpoint_path=os.path.join(d, "c.json"),
                                       checkpoint_meta={},
                                       bench_cache_path=os.path.join(d, "b.json"))
            self.assertEqual(res["status"], "found")
            self.assertEqual(res["password"], "")
            self.assertEqual(res["stage"], "empty")

    def test_wordlist_hit_runs_before_gate(self):
        from pdf_recovery.candidates import CHARSET_PRESETS, auto_space_total
        from pdf_recovery.engine import run_unified_recovery

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "w.pdf")
            _make_pdf(pdf, "secret1")
            wl = os.path.join(d, "w.txt")
            with open(wl, "w") as fh:
                fh.write("nope\nsecret1\n")
            charset = CHARSET_PRESETS[BIG]
            total = auto_space_total(charset, BIG_MIN, BIG_MAX)
            res = run_unified_recovery(pdf, charset, BIG_MIN, BIG_MAX, total,
                                       workers=1, show_progress=False,
                                       checkpoint_path=os.path.join(d, "c.json"),
                                       checkpoint_meta={}, wordlist_path=wl,
                                       bench_cache_path=os.path.join(d, "b.json"))
            self.assertEqual(res["status"], "found")
            self.assertEqual(res["password"], "secret1")
            self.assertEqual(res["stage"], "wordlist")


class TestCLIGate(unittest.TestCase):
    def test_recover_huge_stops_with_exact_command(self):
        from pdf_recovery.cli import main

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "doc.pdf")
            _make_pdf(pdf, "ab")
            ck = os.path.join(d, "ck.json")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["recover", "--pdf", pdf, "--charset", BIG,
                           "--min-length", str(BIG_MIN), "--max-length", str(BIG_MAX),
                           "--workers", "1", "--no-progress", "--checkpoint", ck])
            out = buf.getvalue()
            self.assertEqual(rc, 1)
            self.assertIn("AUTOMATIC SEARCH GATED", out)
            self.assertIn("estimated to take", out)
            self.assertIn("--force", out)
            self.assertIn(pdf, out)
            self.assertFalse(os.path.exists(ck))

    def test_recover_huge_forced_starts(self):
        from pdf_recovery.cli import main

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "doc.pdf")
            _make_pdf(pdf, "ab")
            ck = os.path.join(d, "ck.json")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["recover", "--pdf", pdf, "--auto", "--force",
                           "--charset", BIG,
                           "--min-length", str(BIG_MIN), "--max-length", str(BIG_MAX),
                           "--workers", "1", "--no-progress", "--limit", "4",
                           "--checkpoint", ck])
            out = buf.getvalue()
            self.assertEqual(rc, 1)  # truncated, but it STARTED
            self.assertNotIn("AUTOMATIC SEARCH GATED", out)
            self.assertTrue(os.path.exists(ck))

    def test_legacy_auto_huge_gated_and_forced(self):
        from pdf_recovery.cli import main

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "doc.pdf")
            _make_pdf(pdf, "ab")
            ck = os.path.join(d, "ck.json")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["--pdf", pdf, "--auto", "--charset", BIG,
                           "--min-length", str(BIG_MIN), "--max-length", str(BIG_MAX),
                           "--workers", "1", "--no-progress", "--checkpoint", ck])
            self.assertEqual(rc, 1)
            self.assertIn("AUTOMATIC SEARCH GATED", buf.getvalue())
            self.assertFalse(os.path.exists(ck))
            buf2 = io.StringIO()
            with redirect_stdout(buf2):
                rc2 = main(["--pdf", pdf, "--auto", "--force", "--charset", BIG,
                            "--min-length", str(BIG_MIN), "--max-length", str(BIG_MAX),
                            "--workers", "1", "--no-progress", "--limit", "4",
                            "--checkpoint", ck])
            self.assertEqual(rc2, 1)
            self.assertNotIn("AUTOMATIC SEARCH GATED", buf2.getvalue())

    def test_huge_with_small_limit_starts_without_force(self):
        # A user-imposed cap bounds the work, so the gate lets it start.
        from pdf_recovery.cli import main

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "doc.pdf")
            _make_pdf(pdf, "ab")
            ck = os.path.join(d, "ck.json")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["recover", "--pdf", pdf, "--charset", BIG,
                           "--min-length", str(BIG_MIN), "--max-length", str(BIG_MAX),
                           "--workers", "1", "--no-progress", "--limit", "4",
                           "--checkpoint", ck])
            out = buf.getvalue()
            self.assertEqual(rc, 1)  # truncated, but it STARTED
            self.assertNotIn("AUTOMATIC SEARCH GATED", out)
            self.assertTrue(os.path.exists(ck))

    def test_beginner_workflow_starts_automatically(self):
        from pdf_recovery.cli import main

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "doc.pdf")
            _make_pdf(pdf, "ab")
            ck = os.path.join(d, "ck.json")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["recover", "--pdf", pdf, "--charset-custom", "ab",
                           "--min-length", "1", "--max-length", "2",
                           "--workers", "1", "--no-progress", "--checkpoint", ck])
            out = buf.getvalue()
            self.assertEqual(rc, 0)
            self.assertIn("SUCCESS", out)
            self.assertNotIn("GATED", out)


if __name__ == "__main__":
    unittest.main()
