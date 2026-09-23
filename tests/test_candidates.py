"""Unit tests for candidate generation (offline, no PDF I/O)."""
import os
import tempfile
import unittest

from pdf_recovery.candidates import (
    brute_force_candidates,
    capitalization_variants,
    count_wordlist,
    estimate_bruteforce_total,
    estimate_variation_count,
    generate_variations,
    load_bases_file,
    load_wordlist,
)


class TestCapitalization(unittest.TestCase):
    def test_variants_deduped_and_ordered(self):
        self.assertEqual(capitalization_variants("dog"), ["dog", "DOG", "Dog"])
        # title/capitalize collapse for single words; original preserved
        self.assertIn("hello", capitalization_variants("hello"))

    def test_empty_word(self):
        self.assertEqual(capitalization_variants(""), [""])


class TestVariations(unittest.TestCase):
    def test_basic_shape(self):
        out = generate_variations(
            ["dog"],
            capitalize=False,
            separators=["", "-"],
            prefixes=["", "my"],
            suffixes=["", "123"],
            add_numbers=False,
        )
        # 2 prefixes x 2 suffixes x 2 seps = 8 raw, but ("","") + any sep
        # collapses to bare "dog", so 7 unique.
        self.assertEqual(len(out), 7)
        self.assertIn("dog", out)
        self.assertIn("mydog123", out)
        self.assertIn("my-dog-123", out)

    def test_capitalization_expands(self):
        out = generate_variations(["dog"], capitalize=True, separators=[""],
                                  prefixes=[""], suffixes=[""], add_numbers=False)
        self.assertIn("dog", out)
        self.assertIn("DOG", out)
        self.assertIn("Dog", out)

    def test_numbers_added_as_suffixes(self):
        out = generate_variations(["ab"], capitalize=False, separators=[""],
                                  prefixes=[""], suffixes=[""], add_numbers=True,
                                  number_max=3)
        for n in ("0", "1", "2", "123"):
            self.assertIn(f"ab{n}", out)

    def test_no_numbers_when_disabled(self):
        out = generate_variations(["ab"], capitalize=False, separators=[""],
                                  prefixes=[""], suffixes=[""], add_numbers=False)
        self.assertEqual(out, ["ab"])

    def test_estimate_matches_generate(self):
        kwargs = dict(capitalize=True, separators=["", "-"], prefixes=["", "x"],
                      suffixes=["", "1"], add_numbers=False)
        est = estimate_variation_count(["a", "b"], **kwargs)
        got = len(generate_variations(["a", "b"], **kwargs))
        # "a"/"A" give 2 cores each ("a".upper()=="A"); estimate accounts for that
        self.assertEqual(est, got)

    def test_empty_bases(self):
        self.assertEqual(generate_variations([], capitalize=False), [])


class TestWordlist(unittest.TestCase):
    def test_load_and_count_skip_blanks_and_comments(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as f:
            f.write("apple\n\n  \n# comment\nbanana \nAPPLE\n")
            path = f.name
        try:
            got = list(load_wordlist(path))
            self.assertEqual(got, ["apple", "banana", "APPLE"])
            self.assertEqual(count_wordlist(path), 3)
        finally:
            os.unlink(path)

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            list(load_wordlist("/nonexistent-wordlist-xyz.txt"))

    def test_bases_file(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as f:
            f.write("# c\nsunshine\n\nmydog\n")
            path = f.name
        try:
            self.assertEqual(load_bases_file(path), ["sunshine", "mydog"])
        finally:
            os.unlink(path)


class TestBruteForce(unittest.TestCase):
    def test_order_and_count(self):
        got = list(brute_force_candidates("ab", 1, 2))
        self.assertEqual(got, ["a", "b", "aa", "ab", "ba", "bb"])
        self.assertEqual(estimate_bruteforce_total("ab", 1, 2), 6)

    def test_invalid_params(self):
        with self.assertRaises(ValueError):
            list(brute_force_candidates("", 1, 2))
        with self.assertRaises(ValueError):
            list(brute_force_candidates("ab", 0, 2))
        with self.assertRaises(ValueError):
            list(brute_force_candidates("ab", 3, 2))


if __name__ == "__main__":
    unittest.main()
