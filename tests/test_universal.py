"""Universal utility tests: detection, engine stages, benchmark, CLI.

All offline; fixtures are tiny PDFs generated locally with known passwords.
Existing suites (test_candidates / test_pdf_tester / test_auto) are intact.
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


class TestEncryptedDetection(unittest.TestCase):
    def test_encrypted_vs_plain(self):
        from pdf_recovery.pdf_tester import describe_encryption, get_encryption_info, is_encrypted

        with tempfile.TemporaryDirectory() as d:
            enc = os.path.join(d, "e.pdf")
            plain = os.path.join(d, "p.pdf")
            _make_pdf(enc, "pw")
            _make_pdf(plain, None)
            self.assertTrue(is_encrypted(enc))
            self.assertFalse(is_encrypted(plain))
            info = get_encryption_info(enc)
            self.assertTrue(info["encrypted"])
            # Version info exposed when the library provides it.
            self.assertIn("method", info)
            self.assertIn("v", info)
            self.assertIn("r", info)
            self.assertEqual(info["v"], 2)
            self.assertEqual(info["r"], 3)
            self.assertIn("RC4", describe_encryption(info))
            self.assertEqual(describe_encryption(get_encryption_info(plain)), "not encrypted")

    def test_malformed_pdf(self):
        from pdf_recovery.pdf_tester import PdfMalformedError, get_encryption_info

        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "bad.pdf")
            with open(bad, "wb") as fh:
                fh.write(b"%PDF-1.4 not really a pdf %%%%")
            with self.assertRaises(PdfMalformedError):
                get_encryption_info(bad)

    def test_unsupported_encryption_clean(self):
        from pdf_recovery.pdf_tester import PdfUnsupportedEncryptionError, get_encryption_info

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "u.pdf")
            _make_pdf(pdf, "pw")
            with mock.patch("pypdf.PdfReader", side_effect=NotImplementedError("No such crypt filter")):
                with self.assertRaises(PdfUnsupportedEncryptionError):
                    get_encryption_info(pdf)

    def test_unsupported_cli_reports_cleanly(self):
        from pdf_recovery.cli import main

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "u.pdf")
            _make_pdf(pdf, "pw")
            with mock.patch("pypdf.PdfReader", side_effect=NotImplementedError("bad crypt")):
                rc = main(["recover", "--pdf", pdf, "--charset-custom", "ab",
                           "--min-length", "1", "--max-length", "1",
                           "--workers", "1", "--no-progress"])
            self.assertEqual(rc, 1)


class TestEmptyPassword(unittest.TestCase):
    def test_empty_password_opens(self):
        from pdf_recovery.pdf_tester import try_password

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "e.pdf")
            _make_pdf(pdf, "")
            self.assertTrue(try_password(pdf, ""))
            self.assertFalse(try_password(pdf, "wrong"))

    def test_engine_empty_stage(self):
        from pdf_recovery.candidates import auto_space_total
        from pdf_recovery.engine import run_unified_recovery

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "e.pdf")
            _make_pdf(pdf, "")
            total = auto_space_total("ab", 1, 1)
            res = run_unified_recovery(pdf, "ab", 1, 1, total, workers=1,
                                       show_progress=False,
                                       checkpoint_path=os.path.join(d, "c.json"),
                                       checkpoint_meta={})
            self.assertEqual(res["status"], "found")
            self.assertEqual(res["password"], "")
            self.assertEqual(res["stage"], "empty")


class TestCharsets(unittest.TestCase):
    def test_every_preset(self):
        from pdf_recovery.candidates import CHARSET_PRESETS, resolve_charset

        expected = {"lower": 26, "upper": 26, "digits": 10, "letters": 52,
                    "alphanumeric": 62, "symbols": 32, "printable": 94}
        for name, size in expected.items():
            with self.subTest(name=name):
                cs = resolve_charset([name])
                self.assertEqual(len(cs), size)
                self.assertEqual(cs, CHARSET_PRESETS[name])

    def test_custom_charset(self):
        from pdf_recovery.candidates import resolve_charset

        self.assertEqual(resolve_charset(["lower"], custom="abca"), "abc")
        self.assertEqual(resolve_charset(None, custom="Xy9!"), "Xy9!")

    def test_combined(self):
        from pdf_recovery.candidates import CHARSET_PRESETS, resolve_charset

        self.assertEqual(resolve_charset(["lower,digits"]),
                         CHARSET_PRESETS["lower"] + CHARSET_PRESETS["digits"])
        self.assertEqual(resolve_charset(["lower", "digits"]),
                         CHARSET_PRESETS["lower"] + CHARSET_PRESETS["digits"])
        self.assertEqual(resolve_charset(["alphanumeric"]), CHARSET_PRESETS["alphanumeric"])


class TestOrderingAndSpace(unittest.TestCase):
    def test_increasing_length_ordering(self):
        from pdf_recovery.candidates import iter_indexed

        got = [(pw, ln) for _, pw, ln in iter_indexed("ab", 1, 3, 0)]
        self.assertEqual([ln for _, ln in got], [1] * 2 + [2] * 4 + [3] * 8)
        self.assertEqual([pw for pw, _ in got][:4], ["a", "b", "aa", "ab"])

    def test_search_space_calculation(self):
        from pdf_recovery.candidates import auto_space_total

        self.assertEqual(auto_space_total("ab", 1, 2), 2 + 4)
        self.assertEqual(auto_space_total("abc", 2, 3), 9 + 27)
        with self.assertRaises(ValueError):
            auto_space_total("", 1, 2)


class TestEngineRecovery(unittest.TestCase):
    def test_automatic_recovery(self):
        from pdf_recovery.candidates import auto_space_total
        from pdf_recovery.engine import run_unified_recovery

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "r.pdf")
            _make_pdf(pdf, "bb")
            total = auto_space_total("ab", 1, 2)
            res = run_unified_recovery(pdf, "ab", 1, 2, total, workers=1,
                                       show_progress=False,
                                       checkpoint_path=os.path.join(d, "c.json"),
                                       checkpoint_meta={})
            self.assertEqual(res["status"], "found")
            self.assertEqual(res["password"], "bb")
            self.assertEqual(res["stage"], "auto")

    def test_wordlist_stage_first(self):
        from pdf_recovery.candidates import auto_space_total
        from pdf_recovery.engine import run_unified_recovery

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "r.pdf")
            _make_pdf(pdf, "secret1")
            wl = os.path.join(d, "w.txt")
            with open(wl, "w") as fh:
                fh.write("nope\nsecret1\n")
            total = auto_space_total("ab", 1, 1)
            res = run_unified_recovery(pdf, "ab", 1, 1, total, workers=1,
                                       show_progress=False,
                                       checkpoint_path=os.path.join(d, "c.json"),
                                       checkpoint_meta={}, wordlist_path=wl)
            self.assertEqual(res["status"], "found")
            self.assertEqual(res["password"], "secret1")
            self.assertEqual(res["stage"], "wordlist")

    def test_exhausted_search(self):
        from pdf_recovery.candidates import auto_space_total
        from pdf_recovery.engine import run_unified_recovery

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "r.pdf")
            _make_pdf(pdf, "zz")
            total = auto_space_total("ab", 1, 1)
            res = run_unified_recovery(pdf, "ab", 1, 1, total, workers=1,
                                       show_progress=False,
                                       checkpoint_path=os.path.join(d, "c.json"),
                                       checkpoint_meta={})
            self.assertEqual(res["status"], "not_found")
            self.assertIsNone(res["password"])

    def test_interruption(self):
        from pdf_recovery.candidates import auto_space_total
        from pdf_recovery.engine import run_unified_recovery

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "r.pdf")
            _make_pdf(pdf, "zz-unfindable")
            total = auto_space_total("ab", 1, 2)
            real = __import__("pdf_recovery.runner", fromlist=["_check_one"])._check_one
            calls = {"n": 0}

            def flaky(args):
                calls["n"] += 1
                if calls["n"] == 3:
                    raise KeyboardInterrupt()
                return real(args)

            with mock.patch("pdf_recovery.runner._check_one", side_effect=flaky):
                res = run_unified_recovery(pdf, "ab", 1, 2, total, workers=1,
                                           show_progress=False,
                                           checkpoint_path=os.path.join(d, "c.json"),
                                           checkpoint_meta={})
            self.assertEqual(res["status"], "interrupted")

    def test_multiprocessing(self):
        from pdf_recovery.candidates import auto_space_total
        from pdf_recovery.engine import run_unified_recovery

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "r.pdf")
            _make_pdf(pdf, "ab")
            total = auto_space_total("ab", 1, 2)
            res = run_unified_recovery(pdf, "ab", 1, 2, total, workers=2,
                                       show_progress=False,
                                       checkpoint_path=os.path.join(d, "c.json"),
                                       checkpoint_meta={})
            self.assertEqual(res["status"], "found")
            self.assertEqual(res["password"], "ab")

    def test_original_never_modified(self):
        from pdf_recovery.candidates import auto_space_total
        from pdf_recovery.engine import run_unified_recovery

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "r.pdf")
            _make_pdf(pdf, "ab")
            before = (os.path.getmtime(pdf), os.path.getsize(pdf))
            total = auto_space_total("ab", 1, 2)
            run_unified_recovery(pdf, "ab", 1, 2, total, workers=1,
                                 show_progress=False,
                                 checkpoint_path=os.path.join(d, "c.json"),
                                 checkpoint_meta={})
            self.assertEqual((os.path.getmtime(pdf), os.path.getsize(pdf)), before)


class TestCheckpointResume(unittest.TestCase):
    def test_resume_after_limit(self):
        from pdf_recovery.cli import main

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "doc.pdf")
            _make_pdf(pdf, "bb")  # idx 5 in ab/1-2
            ck = os.path.join(d, "ck.json")
            rc1 = main(["recover", "--pdf", pdf, "--charset-custom", "ab",
                        "--min-length", "1", "--max-length", "2",
                        "--workers", "1", "--no-progress", "--limit", "3",
                        "--checkpoint", ck])
            self.assertEqual(rc1, 1)
            self.assertTrue(os.path.exists(ck))
            rc2 = main(["recover", "--pdf", pdf, "--charset-custom", "ab",
                        "--min-length", "1", "--max-length", "2",
                        "--workers", "1", "--no-progress", "--checkpoint", ck])
            self.assertEqual(rc2, 0)
            self.assertFalse(os.path.exists(ck))


class TestBenchmark(unittest.TestCase):
    def test_calculations(self):
        from pdf_recovery.benchmark import (
            estimate_seconds,
            feasibility_verdict,
            format_duration,
        )

        self.assertEqual(format_duration(45), "45s")
        self.assertEqual(format_duration(90), "1m 30s")
        self.assertEqual(estimate_seconds(1000, 100), 10)
        infeasible = feasibility_verdict(10**15, 500)
        self.assertIn("INFEASIBLE", infeasible)
        self.assertIn("cannot realistically be recovered", infeasible)
        quick = feasibility_verdict(100, 500)
        self.assertNotIn("INFEASIBLE", quick)

    def test_measure_throughput(self):
        from pdf_recovery.benchmark import benchmark_report

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "b.pdf")
            _make_pdf(pdf, "zz")
            rep = benchmark_report(pdf, total_candidates=6, charset_size=2,
                                   min_length=1, max_length=2, workers=1, samples=6)
            self.assertEqual(rep["throughput"]["samples"], 6)
            self.assertGreater(rep["throughput"]["rate"], 0)
            self.assertIn("verdict", rep)


class TestCLIBehavior(unittest.TestCase):
    def test_recover_success_banner(self):
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
            self.assertIn("Password recovered", out)
            for field in ("PDF", "Encrypted", "Encryption", "Charset",
                          "Length range", "Search space", "Workers",
                          "Rate", "Tested", "Elapsed", "Remaining"):
                self.assertIn(field, out)

    def test_recover_exhausted_banner(self):
        from pdf_recovery.cli import main

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "doc.pdf")
            _make_pdf(pdf, "zz")
            ck = os.path.join(d, "ck.json")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["recover", "--pdf", pdf, "--charset-custom", "ab",
                           "--min-length", "1", "--max-length", "1",
                           "--workers", "1", "--no-progress", "--checkpoint", ck])
            out = buf.getvalue()
            self.assertEqual(rc, 1)
            self.assertIn("SEARCH EXHAUSTED", out)
            self.assertIn("not found within the configured search space", out)

    def test_recover_unencrypted(self):
        from pdf_recovery.cli import main

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "plain.pdf")
            _make_pdf(pdf, None)
            self.assertEqual(main(["recover", "--pdf", pdf]), 0)

    def test_benchmark_cli(self):
        from pdf_recovery.cli import main

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "doc.pdf")
            _make_pdf(pdf, "zz")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["--pdf", pdf, "--benchmark", "--charset-custom", "ab",
                           "--min-length", "1", "--max-length", "2",
                           "--workers", "1", "--bench-samples", "4"])
            out = buf.getvalue()
            self.assertEqual(rc, 0)
            self.assertIn("Rate", out)
            self.assertIn("Feasibility", out)

    def test_status_reset(self):
        from pdf_recovery.cli import main

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "doc.pdf")
            _make_pdf(pdf, "bb")
            ck = os.path.join(d, "ck.json")
            rc1 = main(["recover", "--pdf", pdf, "--charset-custom", "ab",
                        "--min-length", "1", "--max-length", "2",
                        "--workers", "1", "--no-progress", "--limit", "2",
                        "--checkpoint", ck])
            self.assertEqual(rc1, 1)
            self.assertEqual(main(["--pdf", pdf, "--status", "--checkpoint", ck]), 0)
            self.assertEqual(main(["--pdf", pdf, "--reset", "--checkpoint", ck]), 0)
            self.assertFalse(os.path.exists(ck))


if __name__ == "__main__":
    unittest.main()
