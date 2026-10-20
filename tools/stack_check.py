#!/usr/bin/env python3
"""Require real XOF handshakes, interop and exact stock-Go BoGo results."""
from collections import Counter
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
STACK = ROOT / ".stack"
README = "tools/stack/README.md"
HANDSHAKE_ROOTS = (
    "TestDecNegotiatedHandshake", "TestDecHandshakeEvidence",
    "TestHKDFHandshakeUnaffected", "TestDecResumptionECH",
)
HANDSHAKE_TESTS = (
    *HANDSHAKE_ROOTS,
    *(f"{test}/{profile}" for test in HANDSHAKE_ROOTS[:2]
      for profile in ("TurboSHAKE256", "SHAKE256")),
    *(f"TestDecResumptionECH/{profile}/ECH={ech}/HRR={hrr}"
      for profile in ("100", "101")
      for ech in ("false", "true") for hrr in ("false", "true")),
)
# Each interop test skips unless its variable names a peer binary.
INTEROP_PEERS = {
    "XOF_INTEROP_RUST_SERVER": STACK / "cargo-target/release/deck-server",
    "XOF_INTEROP_RUST_CLIENT": STACK / "cargo-target/release/deck-client",
    "XOF_INTEROP_STOCK_SERVER": STACK / "bin/stock-server",
}
INTEROP_ROOTS = ("TestXOFInteropRustServer", "TestXOFInteropRustClient",
                 "TestXOFInteropStockServer")
INTEROP_TESTS = (
    *INTEROP_ROOTS,
    *(f"TestXOFInteropRustServer/{profile}" for profile in ("0100", "0101")),
    *(f"TestXOFInteropStockServer/{profile}{case}"
      for profile in ("0100", "0101")
      for case in ("", "/fallback", "/required")),
)


def go_environment():
    env = os.environ.copy()
    for key, path in (("GOROOT", STACK / "go"),
                      ("GOCACHE", STACK / "gocache"),
                      ("GOTMPDIR", STACK / "tmp"),
                      ("TMPDIR", STACK / "tmp"),
                      ("GOMODCACHE", STACK / "modcache")):
        path.mkdir(parents=True, exist_ok=True)
        env[key] = str(path)
    env.update(GOPROXY="off", GOFLAGS="-modcacherw", GOTOOLCHAIN="local")
    return env


def go_test_results(text):
    results = {}
    for line in text.splitlines():
        event = json.loads(line)
        name, action = event.get("Test"), event.get("Action")
        if name and action in ("pass", "skip", "fail"):
            if name in results:
                raise ValueError(f"duplicate test result: {name}")
            results[name] = action.upper()
    return results


def check_passed(label, results, required):
    bad = [f"{name}: {results.get(name, 'MISSING')}"
           for name in required if results.get(name) != "PASS"]
    bad += [f"{name}: {status}" for name, status in results.items()
            if name not in required and status != "PASS"]
    if bad:
        raise ValueError(f"{label} tests did not pass:\n" + "\n".join(bad))


def read_baseline(text):
    results = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        status, name = line.split(maxsplit=1)
        if status not in ("PASS", "SKIP", "FAIL"):
            raise ValueError(f"invalid baseline result: {line}")
        if name in results:
            raise ValueError(f"duplicate baseline result: {name}")
        results[name] = status
    if not results:
        raise ValueError("empty BoGo baseline")
    return results


def check_bogo(results, expected):
    if results.get("TestBogoSuite") != "PASS":
        raise ValueError("TestBogoSuite did not pass")
    prefix = "TestBogoSuite/"
    actual = {name[len(prefix):]: status for name, status in results.items()
              if name.startswith(prefix)}
    bad = [f"{name}: stock={expected.get(name, 'MISSING')} "
           f"patched={actual.get(name, 'MISSING')}"
           for name in sorted(actual.keys() | expected.keys())
           if actual.get(name) != expected.get(name)]
    if bad:
        raise ValueError(f"BoGo: {len(bad)} changed subtest(s):\n" + "\n".join(bad))


def run_tests(label, pattern, env):
    cmd = [str(STACK / "go/bin/go"), "test", "-json", "crypto/tls",
           "-run", pattern, "-count=1", "-timeout=15m"]
    print(f"check-stack: running {label}", flush=True)
    result = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
    log = STACK / f"{label}.jsonl"
    log.write_text(result.stdout)
    (STACK / f"{label}.stderr.log").write_text(result.stderr)
    if result.returncode:
        output = "".join(json.loads(line).get("Output", "")
                         for line in result.stdout.splitlines())
        raise ValueError(f"{label} failed (see {log.relative_to(ROOT)}):\n"
                         + "\n".join((output + result.stderr).splitlines()[-12:]))
    return go_test_results(result.stdout)


def main():
    if not (STACK / "go/bin/go").is_file() or not (STACK / "modcache").is_dir():
        print(f"check-stack: .stack is not set up; see {README}", file=sys.stderr)
        return 1
    env = go_environment()
    failed = 0
    checks = (("handshakes", "^(" + "|".join(HANDSHAKE_ROOTS) + ")$"),
              ("interop", "^(" + "|".join(INTEROP_ROOTS) + ")$"),
              ("bogo", "^TestBogoSuite$"))
    for label, pattern in checks:
        try:
            if label == "handshakes":
                check_passed(label, run_tests(label, pattern, env), HANDSHAKE_TESTS)
                print("check-stack: both XOF profiles passed; 13 handshake cases "
                      "(negotiation, wire Finished, resumption/ECH/HRR, HKDF)")
            elif label == "interop":
                missing = [str(path.relative_to(ROOT))
                           for path in INTEROP_PEERS.values() if not path.is_file()]
                if missing:
                    raise ValueError(f"interop peers missing: {', '.join(missing)}; "
                                     "rebuild .stack with tools/stack/setup.sh")
                peers = {key: str(path) for key, path in INTEROP_PEERS.items()}
                check_passed(label, run_tests(label, pattern, {**env, **peers}),
                             INTEROP_TESTS)
                print("check-stack: interop passed; Go client to the altkdf-rs "
                      "server in both profiles, altkdf-rs client to the Go server, "
                      "HKDF fallback and required-XOF abort against stock Go")
            else:
                results = run_tests(label, pattern, env)
                expected = read_baseline((ROOT / "tools/stack/bogo-baseline.txt").read_text())
                check_bogo(results, expected)
                counts = Counter(expected.values())
                print(f"check-stack: BoGo matches stock go1.26.4 exactly: "
                      f"{counts['PASS']} PASS, {counts['SKIP']} SKIP, "
                      f"{counts['FAIL']} FAIL ({len(expected)} subtests)")
        except (OSError, ValueError) as e:
            print(f"check-stack: {e}", file=sys.stderr)
            failed += 1
    if failed:
        print(f"check-stack: FAILED ({failed}/{len(checks)} checks); "
              f"loopback TCP is required; see {README}", file=sys.stderr)
        return 1
    print("check-stack: PASS (both XOF profiles; altkdf-rs and stock Go "
          "interop; BoGo baseline unchanged)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
