"""Production-quality tests: validation, paths, robustness, privacy.

All offline with tiny locally generated fixtures. Every existing test is
kept intact; these add release-grade coverage.
"""
from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
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


def _run_main(argv):
    """Run cli.main capturing both streams; returns (rc, out, err)."""
    from pdf_recovery.cli import main

    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


class TestVersionAndHelp(unittest.TestCase):
    def test_version_flag(self):
        from pdf_recovery import __version__

        rc, out, _ = _run_main(["--version"])
        self.assertEqual(rc, 0)
        self.assertIn(__version__, out)

    def test_help_exits_zero(self):
        from pdf_recovery.cli import main

        with self.assertRaises(SystemExit) as ctx:
            with redirect_stdout(io.StringIO()):
                main(["--help"])
        self.assertEqual(ctx.exception.code, 0)


class TestArgumentValidation(unittest.TestCase):
    def test_missing_pdf_arg_is_usage_error(self):
        from pdf_recovery.cli import main

        with self.assertRaises(SystemExit) as ctx:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                main(["recover"])
        self.assertEqual(ctx.exception.code, 2)

    def test_nonexistent_file_clear_error(self):
        rc, _, err = _run_main(["recover", "--pdf", "/nonexistent-dir-xyz/doc.pdf"])
        self.assertEqual(rc, 1)
        self.assertIn("not found", err.lower())

    def test_directory_as_pdf_clear_error(self):
        with tempfile.TemporaryDirectory() as d:
            rc, _, err = _run_main(["recover", "--pdf", d])
            self.assertEqual(rc, 1)
            self.assertIn("directory", err.lower())

    def test_windows_style_missing_path_no_traceback(self):
        rc, out, err = _run_main(["recover", "--pdf", "C:\\nonexistent\\doc.pdf"])
        self.assertEqual(rc, 1)
        self.assertNotIn("Traceback", out + err)

    def test_invalid_workers(self):
        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "a.pdf")
            _make_pdf(pdf, "ab")
            rc, _, err = _run_main(["recover", "--pdf", pdf, "--workers", "0"])
            self.assertEqual(rc, 1)
            self.assertIn("--workers", err)

    def test_invalid_length_range(self):
        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "a.pdf")
            _make_pdf(pdf, "ab")
            rc, _, err = _run_main(["recover", "--pdf", pdf,
                                    "--min-length", "5", "--max-length", "2"])
            self.assertEqual(rc, 1)
            self.assertIn("min-length", err)

    def test_invalid_charset(self):
        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "a.pdf")
            _make_pdf(pdf, "ab")
            cfg = os.path.join(d, "config.json")
            with open(cfg, "w") as fh:
                json.dump({"charset": 12345}, fh)
            rc, _, err = _run_main(["recover", "--pdf", pdf, "--config", cfg])
            self.assertEqual(rc, 1)
            self.assertIn("charset", err.lower())

    def test_no_traceback_on_unexpected_error(self):
        from pdf_recovery.cli import main

        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "a.pdf")
            _make_pdf(pdf, "ab")
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                with mock.patch("pdf_recovery.cli.get_encryption_info",
                                side_effect=RuntimeError("boom")):
                    rc = main(["recover", "--pdf", pdf])
            self.assertEqual(rc, 1)
            self.assertNotIn("Traceback", out.getvalue() + err.getvalue())
            self.assertIn("Error:", err.getvalue())


class TestSpecialPaths(unittest.TestCase):
    def test_path_with_spaces(self):
        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "my document.pdf")
            _make_pdf(pdf, "ab")
            ck = os.path.join(d, "ck.json")
            rc, out, _ = _run_main(["recover", "--pdf", pdf, "--charset-custom", "ab",
                                    "--min-length", "1", "--max-length", "2",
                                    "--workers", "1", "--no-progress",
                                    "--checkpoint", ck])
            self.assertEqual(rc, 0)
            self.assertIn("SUCCESS", out)

    def test_unicode_path(self):
        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "décument-✓.pdf")
            _make_pdf(pdf, "ab")
            ck = os.path.join(d, "ck.json")
            rc, out, _ = _run_main(["recover", "--pdf", pdf, "--charset-custom", "ab",
                                    "--min-length", "1", "--max-length", "2",
                                    "--workers", "1", "--no-progress",
                                    "--checkpoint", ck])
            self.assertEqual(rc, 0)
            self.assertIn("Password recovered", out)


class TestCheckpointRobustness(unittest.TestCase):
    def test_corrupted_checkpoint_clean_error(self):
        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "doc.pdf")
            _make_pdf(pdf, "ab")
            ck = os.path.join(d, "ck.json")
            with open(ck, "w") as fh:
                fh.write("{not valid json!!!")
            rc, _, err = _run_main(["recover", "--pdf", pdf, "--charset-custom", "ab",
                                    "--min-length", "1", "--max-length", "2",
                                    "--workers", "1", "--no-progress",
                                    "--checkpoint", ck])
            self.assertEqual(rc, 1)
            self.assertIn("--reset", err)

    def test_wrong_types_checkpoint_clean_error(self):
        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "doc.pdf")
            _make_pdf(pdf, "ab")
            ck = os.path.join(d, "ck.json")
            with open(ck, "w") as fh:
                json.dump({"pdf": os.path.abspath(pdf), "charset": "ab",
                           "min_length": 1, "max_length": 1, "total": 2,
                           "next_index": "oops"}, fh)
            rc, _, err = _run_main(["recover", "--pdf", pdf, "--charset-custom", "ab",
                                    "--min-length", "1", "--max-length", "1",
                                    "--workers", "1", "--no-progress",
                                    "--checkpoint", ck])
            self.assertEqual(rc, 1)
            self.assertIn("--reset", err)

    def test_changed_pdf_invalidates_checkpoint(self):
        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "doc.pdf")
            _make_pdf(pdf, "bb")
            ck = os.path.join(d, "ck.json")
            # Truncated run writes a fingerprinted checkpoint.
            rc1, _, _ = _run_main(["recover", "--pdf", pdf, "--charset-custom", "ab",
                                   "--min-length", "1", "--max-length", "2",
                                   "--workers", "1", "--no-progress", "--limit", "2",
                                   "--checkpoint", ck])
            self.assertEqual(rc1, 1)
            self.assertTrue(os.path.exists(ck))
            # Replace the PDF: same path, different content.
            _make_pdf(pdf, "cc")
            rc2, _, err = _run_main(["recover", "--pdf", pdf, "--charset-custom", "ab",
                                     "--min-length", "1", "--max-length", "2",
                                     "--workers", "1", "--no-progress",
                                     "--checkpoint", ck])
            self.assertEqual(rc2, 1)
            self.assertIn("changed", err)
            self.assertIn("--reset", err)


class TestResultObject(unittest.TestCase):
    def test_fields_and_safe_export(self):
        from pdf_recovery.results import result_from_dict

        res = result_from_dict(
            {"status": "found", "password": "ab", "tried": 4,
             "elapsed": 2.0, "total": 6, "stage": "auto",
             "truncated": False, "error": None, "stages": []},
            encryption_info={"encrypted": True, "method": "m",
                             "details": {"/O": "RAW", "/V": 2}},
            checkpoint_path="/tmp/c.json")
        self.assertEqual(res.status, "found")
        self.assertEqual(res.tested_count, 4)
        self.assertEqual(res.elapsed_seconds, 2.0)
        self.assertEqual(res.attempts_per_second, 2.0)
        self.assertEqual(res.search_space, 6)
        self.assertEqual(res.checkpoint_path, "/tmp/c.json")
        safe = res.to_safe_dict()
        self.assertNotIn("password", safe)
        self.assertEqual(safe["encryption_info"]["details"]["/O"], "<present>")
        full = res.to_safe_dict(include_password=True)
        self.assertEqual(full["password"], "ab")

    def test_result_without_password_key_by_default(self):
        from pdf_recovery.results import RecoveryResult

        res = RecoveryResult(status="not_found", tested_count=3)
        self.assertNotIn("password", res.to_safe_dict())

    def test_safe_export_strips_nested_stage_passwords(self):
        from pdf_recovery.results import RecoveryResult

        res = RecoveryResult(
            status="found", password="ab", tested_count=4,
            stages=[{"stage": "auto", "status": "found", "tried": 3,
                     "password": "ab"}])
        safe = res.to_safe_dict()
        self.assertNotIn("password", safe)
        for entry in safe["stages"]:
            self.assertNotIn("password", entry)
        full = res.to_safe_dict(include_password=True)
        self.assertEqual(full["password"], "ab")
        self.assertEqual(full["stages"][0]["password"], "ab")


class TestOutputJson(unittest.TestCase):
    def test_output_json_excludes_password_by_default(self):
        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "doc.pdf")
            _make_pdf(pdf, "ab")
            ck = os.path.join(d, "ck.json")
            outp = os.path.join(d, "result.json")
            rc, _, _ = _run_main(["recover", "--pdf", pdf, "--charset-custom", "ab",
                                  "--min-length", "1", "--max-length", "2",
                                  "--workers", "1", "--no-progress",
                                  "--checkpoint", ck, "--output-json", outp])
            self.assertEqual(rc, 0)
            with open(outp) as fh:
                payload = json.load(fh)
            self.assertNotIn("password", payload)
            self.assertEqual(payload["status"], "found")
            self.assertIn("tested_count", payload)
            # Nested per-stage dicts must not leak the password either:
            # no "password" key and no value equal to it, at any depth.

            def _walk(node):
                if isinstance(node, dict):
                    for key, value in node.items():
                        self.assertNotEqual(key, "password")
                        _walk(value)
                elif isinstance(node, list):
                    for value in node:
                        _walk(value)
                elif isinstance(node, str):
                    self.assertNotEqual(node, "ab")

            _walk(payload)

    def test_output_json_include_password_explicit(self):
        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "doc.pdf")
            _make_pdf(pdf, "ab")
            ck = os.path.join(d, "ck.json")
            outp = os.path.join(d, "result.json")
            rc, _, _ = _run_main(["recover", "--pdf", pdf, "--charset-custom", "ab",
                                  "--min-length", "1", "--max-length", "2",
                                  "--workers", "1", "--no-progress",
                                  "--checkpoint", ck, "--output-json", outp,
                                  "--include-password"])
            self.assertEqual(rc, 0)
            with open(outp) as fh:
                payload = json.load(fh)
            self.assertEqual(payload["password"], "ab")


class TestConfigFile(unittest.TestCase):
    def test_config_applies_defaults(self):
        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "doc.pdf")
            _make_pdf(pdf, "ab")
            cfg = os.path.join(d, "config.json")
            with open(cfg, "w") as fh:
                json.dump({"charset": "ab", "min_length": 1, "max_length": 2,
                           "workers": 1}, fh)
            ck = os.path.join(d, "ck.json")
            rc, out, _ = _run_main(["recover", "--pdf", pdf, "--config", cfg,
                                    "--no-progress", "--checkpoint", ck])
            self.assertEqual(rc, 0)
            self.assertIn("SUCCESS", out)

    def test_cli_overrides_config(self):
        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "doc.pdf")
            _make_pdf(pdf, "ab")
            cfg = os.path.join(d, "config.json")
            with open(cfg, "w") as fh:
                json.dump({"charset": "xy", "min_length": 1, "max_length": 2,
                           "workers": 1}, fh)
            ck = os.path.join(d, "ck.json")
            # CLI charset-custom wins over config charset; "ab" is found.
            rc, out, _ = _run_main(["recover", "--pdf", pdf, "--config", cfg,
                                    "--charset-custom", "ab",
                                    "--workers", "1", "--no-progress",
                                    "--checkpoint", ck])
            self.assertEqual(rc, 0)
            self.assertIn("SUCCESS", out)

    def test_sensitive_keys_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "doc.pdf")
            _make_pdf(pdf, "ab")
            cfg = os.path.join(d, "config.json")
            with open(cfg, "w") as fh:
                json.dump({"password": "ab", "workers": 1, "charset": "ab",
                           "min_length": 1, "max_length": 2}, fh)
            ck = os.path.join(d, "ck.json")
            rc, _, err = _run_main(["recover", "--pdf", pdf, "--config", cfg,
                                    "--workers", "1", "--no-progress",
                                    "--checkpoint", ck])
            self.assertEqual(rc, 0)
            self.assertIn("ignored", err.lower())

    def test_invalid_config_file(self):
        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "doc.pdf")
            _make_pdf(pdf, "ab")
            cfg = os.path.join(d, "config.json")
            with open(cfg, "w") as fh:
                fh.write("{broken")
            rc, _, err = _run_main(["recover", "--pdf", pdf, "--config", cfg])
            self.assertEqual(rc, 1)
            self.assertIn("config", err.lower())

    def test_missing_explicit_config(self):
        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "doc.pdf")
            _make_pdf(pdf, "ab")
            rc, _, err = _run_main(["recover", "--pdf", pdf,
                                    "--config", os.path.join(d, "nope.json")])
            self.assertEqual(rc, 1)
            self.assertIn("config", err.lower())


class TestBenchmarkSubcommand(unittest.TestCase):
    def test_benchmark_prefix_form(self):
        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "doc.pdf")
            _make_pdf(pdf, "zz")
            rc, out, _ = _run_main(["benchmark", "--pdf", pdf,
                                    "--charset-custom", "ab",
                                    "--min-length", "1", "--max-length", "2",
                                    "--workers", "1", "--bench-samples", "4"])
            self.assertEqual(rc, 0)
            self.assertIn("Rate", out)
            self.assertIn("Feasibility", out)


class TestEntryPoint(unittest.TestCase):
    def test_console_script_declared(self):
        import pathlib

        text = pathlib.Path(__file__).resolve().parent.parent.joinpath(
            "pyproject.toml").read_text()
        self.assertIn('pdf-recovery = "pdf_recovery.cli:main"', text)

    def test_main_callable(self):
        from pdf_recovery import cli

        self.assertTrue(callable(cli.main))


class TestProgressHelpers(unittest.TestCase):
    def test_fmt_int(self):
        from pdf_recovery.cli import _fmt_int

        self.assertEqual(_fmt_int(1240531), "1,240,531")
        self.assertEqual(_fmt_int(0), "0")

    def test_fmt_elapsed(self):
        from pdf_recovery.cli import _fmt_elapsed

        self.assertEqual(_fmt_elapsed(42), "00:42")
        self.assertEqual(_fmt_elapsed(3723), "01:02:03")


class TestPrivacy(unittest.TestCase):
    def test_log_checkpoint_cache_exclude_password(self):
        with tempfile.TemporaryDirectory() as d:
            pdf = os.path.join(d, "doc.pdf")
            _make_pdf(pdf, "qz9")
            ck = os.path.join(d, "ck.json")
            log = os.path.join(d, "run.log")
            wl = os.path.join(d, "w.txt")
            with open(wl, "w") as fh:
                fh.write("nope\n")
            rc, _, _ = _run_main(["recover", "--pdf", pdf, "--wordlist", wl,
                                  "--charset-custom", "qz9w", "--min-length", "1",
                                  "--max-length", "2", "--workers", "1",
                                  "--no-progress", "--limit", "3",
                                  "--checkpoint", ck, "--verbose",
                                  "--log-file", log])
            self.assertEqual(rc, 1)  # truncated, not found: password never hit
            with open(log, encoding="utf-8", errors="replace") as fh:
                self.assertNotIn("qz9", fh.read(), "secret leaked in log")
            cache = ck + ".benchmark.json"
            if os.path.exists(cache):
                with open(cache, encoding="utf-8", errors="replace") as fh:
                    self.assertNotIn("qz9", fh.read(), "secret leaked in cache")
            # Checkpoint holds the user-supplied alphabet ("qz9w") but must
            # never store the password itself as a value.
            with open(ck, encoding="utf-8") as fh:
                data = json.load(fh)
            string_values = [v for v in data.values() if isinstance(v, str)]
            self.assertNotIn("qz9", string_values)
            self.assertNotIn("password", json.dumps(data).lower())


if __name__ == "__main__":
    unittest.main()
