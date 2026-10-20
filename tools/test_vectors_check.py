"""Regression tests for the appendix comparison used by vectors-check."""
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest

import vectors_check


class StackVectorTests(unittest.TestCase):
    def go_text(self, vectors):
        return json.dumps({"profiles": [{"profile": "TLS13_SHAKE256",
                                         "vectors": vectors}]})

    def test_formats_preserve_names_and_profiles(self):
        name = 'write_iv  = key_block[16..28]'
        expected = {("TLS13_SHAKE256", name): "abcd"}
        self.assertEqual(vectors_check.from_go_stack(self.go_text([
            {"name": name, "output": "abcd"}])), expected)
        self.assertEqual(vectors_check.from_rust(
            f"TLS13_SHAKE256\t{name}\tabcd\n"), expected)

    def test_duplicate_values_are_rejected(self):
        vector = {"name": "TH_CH", "output": "abcd"}
        with self.assertRaisesRegex(ValueError, "duplicate"):
            vectors_check.from_go_stack(self.go_text([vector, vector]))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            vectors_check.from_rust("TLS13_SHAKE256\tTH_CH\tabcd\n" * 2)

    def test_malformed_values_are_rejected(self):
        for value in ("", "abc", "not-hex"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    vectors_check.from_go_stack(self.go_text([
                        {"name": "TH_CH", "output": value}]))
                with self.assertRaises(ValueError):
                    vectors_check.from_rust(f"TLS13_SHAKE256\tTH_CH\t{value}")
        with self.assertRaises(ValueError):
            vectors_check.from_rust("unexpected output")


class DraftVectorTests(unittest.TestCase):
    def block(self, profile="TLS13_SHAKE256", values="TH_CH:\n  abcd"):
        return f"## {profile} Vectors\n\n~~~~\n{values}\n~~~~\n"

    def test_duplicate_label_rejected(self):
        text = self.block(values="TH_CH:\n  deadbeef\nTH_CH:\n  abcd")
        with self.assertRaisesRegex(ValueError, "duplicate.*TLS13_SHAKE256.*TH_CH"):
            vectors_check.from_draft(text)

    def test_additional_fenced_block_in_profile(self):
        text = self.block() + '\n~~~~\nc_hs_traffic (PSK-only):\n  deadbeef\n~~~~\n'
        self.assertEqual(vectors_check.from_draft(text), {
            ('TLS13_SHAKE256', 'TH_CH'): 'abcd',
            ('TLS13_SHAKE256', 'c_hs_traffic (PSK-only)'): 'deadbeef',
        })

    def test_duplicate_in_additional_fenced_block_rejected(self):
        text = self.block() + '\n~~~~\nTH_CH:\n  abcd\n~~~~\n'
        with self.assertRaisesRegex(ValueError, 'duplicate.*TLS13_SHAKE256.*TH_CH'):
            vectors_check.from_draft(text)

    def test_fenced_block_after_appendix_is_ignored(self):
        text = self.block() + '\n# Next appendix\n\n~~~~\nexample:\n  abcd\n~~~~\n'
        self.assertEqual(vectors_check.from_draft(text), {
            ('TLS13_SHAKE256', 'TH_CH'): 'abcd',
        })

    def test_fenced_block_under_subsection_is_ignored(self):
        for heading in ('## Notes', '### Example'):
            with self.subTest(heading=heading):
                text = (self.block() + f'\n{heading}\n\n~~~~\nexample:\n'
                        '  abcd\n~~~~\n')
                self.assertEqual(vectors_check.from_draft(text), {
                    ('TLS13_SHAKE256', 'TH_CH'): 'abcd',
                })

    def test_duplicate_profile_block_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate.*TLS13_SHAKE256.*TH_CH"):
            vectors_check.from_draft(self.block() + self.block())

    def test_same_label_in_different_profiles_allowed(self):
        values = vectors_check.from_draft(
            self.block() + self.block(profile="TLS13_TURBOSHAKE256"))
        self.assertEqual(values, {
            ("TLS13_SHAKE256", "TH_CH"): "abcd",
            ("TLS13_TURBOSHAKE256", "TH_CH"): "abcd",
        })

    def test_cli_rejects_duplicate_even_when_last_value_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            generator = Path(tmp) / "generator.txt"
            draft.write_text(self.block(values="TH_CH:\n  deadbeef\nTH_CH:\n  abcd"))
            generator.write_text("==== TLS13_SHAKE256 ====\nTH_CH: abcd\n")
            result = subprocess.run([
                sys.executable, str(Path(vectors_check.__file__)),
                "--draft", str(draft), "--go-out", str(generator),
                "--py-out", str(generator),
            ], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("duplicate", result.stderr)
        self.assertIn("TLS13_SHAKE256", result.stderr)
        self.assertIn("TH_CH", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
