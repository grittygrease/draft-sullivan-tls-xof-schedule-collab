"""Prevent missing tests and changed BoGo subtests from passing check-stack."""
import json
import unittest

import stack_check


class StackCheckTests(unittest.TestCase):
    def test_go_json_keeps_terminal_results_only(self):
        events = [{"Action": "run", "Test": "TestBogoSuite/one"},
                  {"Action": "output", "Output": "diagnostic"},
                  {"Action": "skip", "Test": "TestBogoSuite/one"},
                  {"Action": "pass", "Test": "TestBogoSuite"},
                  {"Action": "pass", "Package": "crypto/tls"}]
        self.assertEqual(stack_check.go_test_results(
            "\n".join(map(json.dumps, events))),
            {"TestBogoSuite/one": "SKIP", "TestBogoSuite": "PASS"})

    def test_duplicate_terminal_results_rejected(self):
        event = json.dumps({"Action": "pass", "Test": "TestBogoSuite/one"})
        with self.assertRaisesRegex(ValueError, "duplicate"):
            stack_check.go_test_results(event + "\n" + event)

    def test_every_handshake_and_interop_test_must_pass(self):
        for required in (stack_check.HANDSHAKE_TESTS, stack_check.INTEROP_TESTS):
            results = {name: "PASS" for name in required}
            stack_check.check_passed("label", results, required)
            for name in results:
                for result in (None, "SKIP", "FAIL"):
                    changed = dict(results)
                    if result is None:
                        del changed[name]
                    else:
                        changed[name] = result
                    with self.subTest(name=name, result=result):
                        with self.assertRaises(ValueError):
                            stack_check.check_passed("label", changed, required)

    def test_bogo_compares_names_and_statuses_not_counts(self):
        baseline = "# stock results\nPASS one\nSKIP two\n"
        expected = stack_check.read_baseline(baseline)
        results = {"TestBogoSuite": "PASS", "TestBogoSuite/one": "PASS",
                   "TestBogoSuite/two": "SKIP"}
        stack_check.check_bogo(results, expected)
        mutations = [
            {"TestBogoSuite/one": "SKIP", "TestBogoSuite/two": "PASS"},
            {"TestBogoSuite/one": "PASS", "TestBogoSuite/three": "SKIP"},
            {"TestBogoSuite/one": "PASS", "TestBogoSuite/two": "SKIP",
             "TestBogoSuite/extra": "PASS"},
            {"TestBogoSuite/one": "PASS"},
            {"TestBogoSuite": "SKIP"},
            {},
        ]
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                stack_check.check_bogo({"TestBogoSuite": "PASS", **changed}, expected)
        del results["TestBogoSuite"]
        with self.assertRaises(ValueError):
            stack_check.check_bogo(results, expected)

    def test_baseline_rejects_duplicates_empty_and_invalid(self):
        for text in ("PASS one\nSKIP one", "# only a comment", "oops one"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                stack_check.read_baseline(text)


if __name__ == "__main__":
    unittest.main()
