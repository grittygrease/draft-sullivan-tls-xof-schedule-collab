#!/usr/bin/env python3
"""Regenerate the Test Vectors appendix with both generators and compare.

The Go generator (tools/go) and the Python verifier (tools/pyverify) each
print every appendix value as "name: hex" under a "==== PROFILE ===="
header.  This script runs both, reads all per-profile vector blocks of the
draft's Test Vectors appendix, and checks that all three agree on every
value, by profile and name.

Usage: vectors_check.py [--draft FILE] [--go-out FILE] [--py-out FILE]
With no --go-out or --py-out, the generators are run here.
Exit status is 0 only if Go, Python and the appendix agree exactly.
"""
import argparse
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
DRAFT = HERE.parent / "draft-sullivan-tls-xof-schedule.md"
PROFILE = re.compile(r"^=+ (TLS13_\w+) =+$")


def from_generator(text):
    """{(profile, name): hex} from generator output."""
    out, prof = {}, None
    for line in text.splitlines():
        m = PROFILE.match(line.strip())
        if m:
            prof = m.group(1)
            continue
        m = re.match(r"^(.*?):\s+([0-9a-f]+)$", line)
        if prof and m:
            out[(prof, m.group(1).strip())] = m.group(2)
    return out


def from_draft(text):
    """{(profile, name): hex} from the appendix's per-profile blocks."""
    out = {}
    prof, name, fenced = None, None, False
    for line in text.splitlines():
        if line.strip() == "~~~~":
            fenced = not fenced
            name = None
            continue
        if not fenced:
            m = re.fullmatch(r"## (TLS13_\w+) Vectors", line)
            if m:
                prof = m.group(1)
            elif re.match(r"#{1,6} ", line):
                prof = None
            continue
        if prof is None or not line.strip() or line.startswith("#"):
            continue
        if line.startswith("  "):
            out[(prof, name)] += line.strip()
        else:
            name = line.rstrip(":").strip()
            if (prof, name) in out:
                raise ValueError(f"duplicate appendix vector: {prof} {name}")
            out[(prof, name)] = ""
    return out


def run(cmd, cwd):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"vectors-check: {' '.join(cmd)} failed:\n{r.stderr}")
    return r.stdout


def compare(a_name, a, b_name, b):
    bad = []
    for k in sorted(set(a) | set(b)):
        if a.get(k) != b.get(k):
            bad.append(f"  {k[0]} {k[1]}: {a_name}={a.get(k, '(missing)')[:32]}"
                       f" {b_name}={b.get(k, '(missing)')[:32]}")
    return bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--draft", default=str(DRAFT))
    ap.add_argument("--go-out")
    ap.add_argument("--py-out")
    args = ap.parse_args()

    go_text = (pathlib.Path(args.go_out).read_text() if args.go_out
               else run(["go", "run", "."], HERE / "go"))
    py_text = (pathlib.Path(args.py_out).read_text() if args.py_out
               else run([sys.executable, "-I", "verify.py"], HERE / "pyverify"))
    go, py = from_generator(go_text), from_generator(py_text)
    try:
        draft = from_draft(pathlib.Path(args.draft).read_text())
    except ValueError as e:
        print(f"vectors-check: {e}", file=sys.stderr)
        return 1

    bad = (compare("go", go, "python", py)
           + compare("go", go, "appendix", draft))
    if not draft:
        bad.append("  no vector blocks found in the draft")
    if bad:
        print(f"vectors-check: {len(bad)} mismatch(es)")
        print("\n".join(bad))
        return 1
    print(f"vectors-check: Go, Python and the appendix agree on all "
          f"{len(draft)} values")
    return 0


if __name__ == "__main__":
    sys.exit(main())
