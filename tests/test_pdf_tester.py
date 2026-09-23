"""Unit tests for PDF password verification.

Creates small encrypted PDFs on the fly with pypdf (local temp files),
so no fixture PDFs are checked into the repo.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from typing import Optional

from pdf_recovery.pdf_tester import (
    PdfMalformedError,
    PdfNotFoundError,
    get_encryption_info,
    is_encrypted,
    try_password,
)


def _make_pdf(path: str, password: Optional[str]):
    from pypdf import PdfWriter

    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    if password:
        writer.encrypt(password)
    with open(path, "wb") as fh:
        writer.write(fh)


class TestPdfTester(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.enc = os.path.join(self.tmp.name, "enc.pdf")
        self.plain = os.path.join(self.tmp.name, "plain.pdf")
        _make_pdf(self.enc, "Secret123")
        _make_pdf(self.plain, None)

    def tearDown(self):
        self.tmp.cleanup()

    def test_is_encrypted(self):
        self.assertTrue(is_encrypted(self.enc))
        self.assertFalse(is_encrypted(self.plain))

    def test_get_encryption_info(self):
        self.assertTrue(get_encryption_info(self.enc)["encrypted"])
        self.assertFalse(get_encryption_info(self.plain)["encrypted"])

    def test_try_password_correct_and_wrong(self):
        self.assertTrue(try_password(self.enc, "Secret123"))
        self.assertFalse(try_password(self.enc, "secret123"))
        self.assertFalse(try_password(self.enc, "wrong"))
        self.assertFalse(try_password(self.enc, ""))

    def test_try_password_plain_pdf_returns_true(self):
        self.assertTrue(try_password(self.plain, "anything"))

    def test_missing_file(self):
        with self.assertRaises(PdfNotFoundError):
            is_encrypted(os.path.join(self.tmp.name, "nope.pdf"))
        with self.assertRaises(PdfNotFoundError):
            try_password(os.path.join(self.tmp.name, "nope.pdf"), "x")

    def test_malformed_pdf(self):
        bad = os.path.join(self.tmp.name, "bad.pdf")
        with open(bad, "wb") as fh:
            fh.write(b"%PDF-1.4 not really a pdf %%%%")
        with self.assertRaises(PdfMalformedError):
            get_encryption_info(bad)

    def test_original_never_modified(self):
        before = os.path.getmtime(self.enc)
        size_before = os.path.getsize(self.enc)
        try_password(self.enc, "wrong")
        try_password(self.enc, "Secret123")
        self.assertEqual(os.path.getsize(self.enc), size_before)
        self.assertEqual(os.path.getmtime(self.enc), before)


class TestRunnerIntegration(unittest.TestCase):
    def test_runner_finds_password_sequential(self):
        from pdf_recovery.runner import run_recovery

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "r.pdf")
            _make_pdf(pdf, "ab")
            res = run_recovery(pdf, iter(["xx", "ab", "yy"]), workers=1,
                               total=3, show_progress=False)
            self.assertEqual(res["status"], "found")
            self.assertEqual(res["password"], "ab")
            self.assertEqual(res["tried"], 2)

    def test_runner_not_found(self):
        from pdf_recovery.runner import run_recovery

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "r.pdf")
            _make_pdf(pdf, "zz-top-secret")
            res = run_recovery(pdf, iter(["a", "b"]), workers=1,
                               total=2, show_progress=False)
            self.assertEqual(res["status"], "not_found")
            self.assertIsNone(res["password"])


if __name__ == "__main__":
    unittest.main()
