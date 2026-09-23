"""Comprehensive tests for --auto mode (offline).

Covers: candidate ordering, search-space calculations, checkpoint
creation/restoration, interruption/resume, correct-password detection,
multiprocessing. Existing tests in test_candidates.py / test_pdf_tester.py
are left intact.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from typing import Optional

from pdf_recovery.candidates import (
    CHARSET_PRESETS,
    auto_space_total,
    brute_force_candidates,
    index_to_password,
    iter_indexed,
    length_for_index,
    password_to_index,
    resolve_charset,
)
from pdf_recovery.checkpoint import (
    checkpoint_exists,
    default_checkpoint_path,
    describe_checkpoint,
    load_checkpoint,
    make_checkpoint,
    params_match,
    reset_checkpoint,
    save_checkpoint,
)


def _make_pdf(path: str, password: Optional[str]):
    from pypdf import PdfWriter

    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    if password:
        writer.encrypt(password)
    with open(path, "wb") as fh:
        writer.write(fh)


class TestCharsetPresets(unittest.TestCase):
    def test_preset_sizes(self):
        self.assertEqual(len(CHARSET_PRESETS["lower"]), 26)
        self.assertEqual(len(CHARSET_PRESETS["upper"]), 26)
        self.assertEqual(len(CHARSET_PRESETS["digits"]), 10)
        self.assertEqual(len(CHARSET_PRESETS["letters"]), 52)
        self.assertEqual(len(CHARSET_PRESETS["alphanumeric"]), 62)
        self.assertEqual(len(CHARSET_PRESETS["printable"]), 94)

    def test_resolve_single_and_combined(self):
        self.assertEqual(resolve_charset(["lower"]), CHARSET_PRESETS["lower"])
        self.assertEqual(resolve_charset(["upper"]), CHARSET_PRESETS["upper"])
        self.assertEqual(resolve_charset(["digits"]), CHARSET_PRESETS["digits"])
        combined = CHARSET_PRESETS["lower"] + CHARSET_PRESETS["digits"]
        self.assertEqual(resolve_charset(["lower,digits"]), combined)
        self.assertEqual(resolve_charset(["lower", "digits"]), combined)
        self.assertEqual(resolve_charset(["alphanumeric"]), CHARSET_PRESETS["alphanumeric"])

    def test_resolve_custom_overrides(self):
        self.assertEqual(resolve_charset(["lower"], custom="abca"), "abc")
        self.assertEqual(resolve_charset(None, custom="xyz"), "xyz")

    def test_resolve_literal_fallback_backward_compat(self):
        # Old `--charset "abc123"` usage keeps working as literal chars.
        self.assertEqual(resolve_charset(["abc123"]), "abc123")

    def test_resolve_default(self):
        self.assertEqual(
            resolve_charset(None, None, default="lower"), CHARSET_PRESETS["lower"]
        )
        self.assertEqual(resolve_charset(None, None), "")


class TestSearchSpace(unittest.TestCase):
    def test_total_formula(self):
        # total = sum(k**n)
        self.assertEqual(auto_space_total("ab", 1, 2), 2 + 4)
        self.assertEqual(auto_space_total("abc", 2, 3), 9 + 27)
        k = len(CHARSET_PRESETS["lower"])
        self.assertEqual(auto_space_total(CHARSET_PRESETS["lower"], 1, 2), k + k**2)

    def test_total_invalid(self):
        with self.assertRaises(ValueError):
            auto_space_total("", 1, 2)
        with self.assertRaises(ValueError):
            auto_space_total("ab", 0, 2)
        with self.assertRaises(ValueError):
            auto_space_total("ab", 3, 2)

    def test_length_for_index(self):
        # charset size 2, lengths 1..2: idx 0,1 -> len1; 2..5 -> len2
        self.assertEqual(length_for_index(2, 1, 2, 0), 1)
        self.assertEqual(length_for_index(2, 1, 2, 1), 1)
        self.assertEqual(length_for_index(2, 1, 2, 2), 2)
        self.assertEqual(length_for_index(2, 1, 2, 5), 2)
        with self.assertRaises(IndexError):
            length_for_index(2, 1, 2, 6)

    def test_ordering_matches_brute_force(self):
        for charset, lo, hi in [("ab", 1, 2), ("abc", 1, 2), ("ab", 2, 3)]:
            expected = list(brute_force_candidates(charset, lo, hi))
            got = [pw for _, pw, _ in iter_indexed(charset, lo, hi, 0)]
            self.assertEqual(got, expected)

    def test_index_roundtrip(self):
        cs = "abc"
        total = auto_space_total(cs, 1, 2)
        for idx in range(total):
            pw, length = index_to_password(cs, 1, 2, idx)
            self.assertEqual(len(pw), length)
            self.assertEqual(password_to_index(cs, 1, 2, pw), idx)

    def test_iter_indexed_start_offset_lazy(self):
        cs = "ab"
        full = [pw for _, pw, _ in iter_indexed(cs, 1, 2, 0)]
        tail = [(i, pw) for i, pw, _ in iter_indexed(cs, 1, 2, 4)]
        self.assertEqual([p for _, p in tail], full[4:])
        self.assertEqual([i for i, _ in tail], [4, 5])
        # Laziness: generator, not list.
        it = iter_indexed(cs, 1, 2, 0)
        self.assertTrue(hasattr(it, "__next__"))

    def test_current_length_increases(self):
        cs = "ab"
        lengths = [ln for _, _, ln in iter_indexed(cs, 1, 3, 0)]
        # 2 x len1, 4 x len2, 8 x len3
        self.assertEqual(lengths, [1] * 2 + [2] * 4 + [3] * 8)


class TestCheckpoint(unittest.TestCase):
    def test_default_path(self):
        self.assertEqual(default_checkpoint_path("/tmp/x.pdf"), "/tmp/x.pdf.auto-checkpoint.json")

    def test_creation_and_restoration(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "c.json")
            data = make_checkpoint(
                pdf_path="/tmp/x.pdf", charset="ab", charset_spec=["ab"],
                charset_custom=None, min_length=1, max_length=2,
                total=6, next_index=3, tested_contiguous=3, workers=2,
            )
            save_checkpoint(path, data)
            self.assertTrue(checkpoint_exists(path))
            loaded = load_checkpoint(path)
            self.assertEqual(loaded["next_index"], 3)
            self.assertEqual(loaded["total"], 6)
            self.assertEqual(loaded["charset"], "ab")
            # Atomic write leaves no .tmp behind.
            self.assertFalse(os.path.exists(path + ".tmp"))

    def test_reset(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "c.json")
            self.assertFalse(reset_checkpoint(path))  # nothing there
            save_checkpoint(path, make_checkpoint("/tmp/x.pdf", "ab", [], None, 1, 1, 2, 1, 1, 1))
            self.assertTrue(reset_checkpoint(path))
            self.assertFalse(checkpoint_exists(path))

    def test_describe_and_match(self):
        data = make_checkpoint("/tmp/x.pdf", "ab", ["ab"], None, 1, 2, 6, 2, 2, 2)
        # params_match expects absolute pdf path
        import os as _os

        abs_pdf = _os.path.abspath("/tmp/x.pdf")
        self.assertEqual(data["pdf"], abs_pdf)
        ok, _ = params_match(data, "/tmp/x.pdf", "ab", 1, 2, 6)
        self.assertTrue(ok)
        ok2, reason = params_match(data, "/tmp/x.pdf", "abc", 1, 2, 9)
        self.assertFalse(ok2)
        self.assertIn("charset", reason)
        text = describe_checkpoint(data)
        self.assertIn("Remaining", text)
        self.assertIn("6", text)

    def test_load_invalid(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bad.json")
            with open(path, "w") as fh:
                json.dump({"foo": 1}, fh)
            with self.assertRaises(ValueError):
                load_checkpoint(path)


class TestAutoRunner(unittest.TestCase):
    def test_correct_password_detection_sequential(self):
        from pdf_recovery.auto import run_auto

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "r.pdf")
            _make_pdf(pdf, "ba")
            ck = os.path.join(d, "c.json")
            total = auto_space_total("ab", 1, 2)
            res = run_auto(pdf, "ab", 1, 2, total, start_index=0, workers=1,
                           show_progress=False, checkpoint_path=ck,
                           checkpoint_meta={"charset_spec": [], "charset_custom": None})
            self.assertEqual(res["status"], "found")
            self.assertEqual(res["password"], "ba")
            # order a,b,aa,ab,ba -> 5 tried; early stop (total 6)
            self.assertEqual(res["tried"], 5)
            self.assertLess(res["tried"], total)
            # checkpoint cleared on success
            self.assertFalse(checkpoint_exists(ck))

    def test_not_found_clears_checkpoint(self):
        from pdf_recovery.auto import run_auto

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "r.pdf")
            _make_pdf(pdf, "zz")
            ck = os.path.join(d, "c.json")
            total = auto_space_total("ab", 1, 1)
            res = run_auto(pdf, "ab", 1, 1, total, start_index=0, workers=1,
                           show_progress=False, checkpoint_path=ck,
                           checkpoint_meta={"charset_spec": [], "charset_custom": None})
            self.assertEqual(res["status"], "not_found")
            self.assertIsNone(res["password"])
            self.assertFalse(checkpoint_exists(ck))

    def test_limit_truncation_and_resume(self):
        from pdf_recovery.auto import run_auto

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "r.pdf")
            _make_pdf(pdf, "bb")  # idx: a0 b1 aa2 ab3 ba4 bb5
            ck = os.path.join(d, "c.json")
            total = auto_space_total("ab", 1, 2)
            r1 = run_auto(pdf, "ab", 1, 2, total, start_index=0, workers=1,
                          limit=3, show_progress=False, checkpoint_path=ck,
                          checkpoint_meta={"charset_spec": [], "charset_custom": None},
                          checkpoint_every=1)
            self.assertEqual(r1["status"], "not_found")
            self.assertTrue(r1["truncated"])
            self.assertTrue(checkpoint_exists(ck))
            data = load_checkpoint(ck)
            self.assertEqual(data["next_index"], 3)
            # Resume finds bb without re-searching from scratch.
            r2 = run_auto(pdf, "ab", 1, 2, total, start_index=data["next_index"],
                          workers=1, show_progress=False, checkpoint_path=ck,
                          checkpoint_meta={"charset_spec": [], "charset_custom": None},
                          checkpoint_every=1)
            self.assertEqual(r2["status"], "found")
            self.assertEqual(r2["password"], "bb")

    def test_interruption_saves_checkpoint(self):
        from pdf_recovery.auto import run_auto
        from unittest import mock

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "r.pdf")
            _make_pdf(pdf, "zz-unfindable")
            ck = os.path.join(d, "c.json")
            total = auto_space_total("ab", 1, 2)
            real = __import__("pdf_recovery.runner", fromlist=["_check_one"])._check_one

            calls = {"n": 0}

            def flaky(args):
                calls["n"] += 1
                if calls["n"] == 3:
                    raise KeyboardInterrupt()
                return real(args)

            with mock.patch("pdf_recovery.runner._check_one", side_effect=flaky):
                res = run_auto(pdf, "ab", 1, 2, total, start_index=0, workers=1,
                               show_progress=False, checkpoint_path=ck,
                               checkpoint_meta={"charset_spec": [], "charset_custom": None})
            self.assertEqual(res["status"], "interrupted")
            self.assertTrue(checkpoint_exists(ck))
            data = load_checkpoint(ck)
            # contiguous prefix of 2 (idx 0,1 done before interrupt at 3rd)
            self.assertEqual(data["next_index"], 2)

    def test_multiprocessing_finds_password(self):
        from pdf_recovery.auto import run_auto

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "r.pdf")
            _make_pdf(pdf, "ab")
            ck = os.path.join(d, "c.json")
            total = auto_space_total("ab", 1, 2)
            res = run_auto(pdf, "ab", 1, 2, total, start_index=0, workers=2,
                           show_progress=False, checkpoint_path=ck,
                           checkpoint_meta={"charset_spec": [], "charset_custom": None})
            self.assertEqual(res["status"], "found")
            self.assertEqual(res["password"], "ab")
            self.assertLessEqual(res["tried"], total)


class TestAutoCLI(unittest.TestCase):
    def test_cli_auto_finds_password(self):
        from pdf_recovery.cli import main

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "doc.pdf")
            _make_pdf(pdf, "ab")
            ck = os.path.join(d, "ck.json")
            rc = main(["--pdf", pdf, "--auto", "--charset-custom", "ab",
                       "--min-length", "1", "--max-length", "2",
                       "--workers", "1", "--no-progress", "--checkpoint", ck])
            self.assertEqual(rc, 0)
            self.assertFalse(os.path.exists(ck))  # cleared on success

    def test_cli_status_and_reset(self):
        from pdf_recovery.cli import main

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "doc.pdf")
            _make_pdf(pdf, "bb")
            ck = os.path.join(d, "ck.json")
            # truncated run leaves a checkpoint
            rc1 = main(["--pdf", pdf, "--auto", "--charset-custom", "ab",
                        "--min-length", "1", "--max-length", "2",
                        "--workers", "1", "--no-progress", "--limit", "2",
                        "--checkpoint", ck])
            self.assertEqual(rc1, 1)
            self.assertTrue(os.path.exists(ck))
            rc2 = main(["--pdf", pdf, "--status", "--checkpoint", ck])
            self.assertEqual(rc2, 0)
            rc3 = main(["--pdf", pdf, "--reset", "--checkpoint", ck])
            self.assertEqual(rc3, 0)
            self.assertFalse(os.path.exists(ck))

    def test_cli_auto_rejects_clues(self):
        from pdf_recovery.cli import main

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "doc.pdf")
            _make_pdf(pdf, "ab")
            rc = main(["--pdf", pdf, "--auto", "--wordlist", "x.txt"])
            self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
