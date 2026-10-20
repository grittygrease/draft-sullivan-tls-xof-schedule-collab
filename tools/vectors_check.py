#!/usr/bin/env python3
"""Regenerate the Test Vectors appendix with every available source.

The Go generator (tools/go) and the Python verifier (tools/pyverify) each
print every appendix value as "name: hex" under a "==== PROFILE ===="
header.  This script runs both, reads all per-profile vector blocks of the
draft's Test Vectors appendix, and compares every value by profile and name.
The patched Go TLS stack and altkdf-rs are also run when installed in .stack;
see tools/stack/README.md. The two in-tree generators remain required.

Usage: vectors_check.py [--draft FILE] [--go-out FILE] [--py-out FILE]
With no --go-out or --py-out, the generators are run here.
Exit status is 0 only if every source that ran agrees with the appendix.
"""
import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

from stack_check import README, STACK, go_environment

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


def add_vector(out, profile, name, value):
    if (not isinstance(profile, str) or not re.fullmatch(r"TLS13_\w+", profile)
            or not isinstance(name, str) or not name
            or not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-f]{2})+", value)):
        raise ValueError("invalid stack vector profile, name or hex value")
    if (profile, name) in out:
        raise ValueError(f"duplicate stack vector: {profile} {name}")
    out[(profile, name)] = value


def from_go_stack(text):
    out = {}
    for profile in json.loads(text)["profiles"]:
        for vector in profile["vectors"]:
            add_vector(out, profile["profile"], vector["name"], vector["output"])
    return out


def from_rust(text):
    out = {}
    for line in text.splitlines():
        profile, name, value = line.split("\t")
        add_vector(out, profile, name, value)
    return out


def optional_sources():
    sources = {}
    if (STACK / "go/bin/go").is_file():
        env = go_environment()
        # A new directory prevents stale output from a skipped test from passing.
        with tempfile.TemporaryDirectory(dir=STACK / "tmp", prefix="vectors-") as tmp:
            env["TLS13DEC_VECTOR_DIR"] = tmp
            run([str(STACK / "go/bin/go"), "test", "crypto/tls/internal/tls13dec",
                 "-run", "^TestGenerateVectors$", "-count=1"], HERE.parent, env)
            sources["Go TLS stack"] = from_go_stack((pathlib.Path(tmp) / "vectors.json").read_text())
    else:
        print(f"vectors-check: skipping Go TLS stack (not set up); see {README}")
    if ((STACK / "altkdf-rs/Cargo.toml").is_file()
            and (STACK / "cargo-home").is_dir() and shutil.which("cargo")):
        env = os.environ.copy()
        env.update(CARGO_HOME=str(STACK / "cargo-home"),
                   CARGO_TARGET_DIR=str(STACK / "cargo-target"))
        sources["Rust (altkdf-rs)"] = from_rust(run([
            "cargo", "run", "--offline", "--locked", "-q", "--release",
            "-p", "deck-schedule", "--example", "gen_vectors"], STACK / "altkdf-rs", env))
    else:
        print(f"vectors-check: skipping Rust (altkdf-rs) (not set up); see {README}")
    return sources


def run(cmd, cwd, env=None):
    r = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"vectors-check: {' '.join(cmd)} failed:\n{r.stdout}{r.stderr}")
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
    try:
        draft = from_draft(pathlib.Path(args.draft).read_text())
        sources = {"Go": from_generator(go_text), "Python": from_generator(py_text)}
        sources.update(optional_sources())
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"vectors-check: {e}", file=sys.stderr)
        return 1

    bad = [error for name, values in sources.items()
           for error in compare(name, values, "appendix", draft)]
    if not draft:
        bad.append("  no vector blocks found in the draft")
    if bad:
        print(f"vectors-check: {len(bad)} mismatch(es)")
        print("\n".join(bad))
        return 1
    print(f"vectors-check: {', '.join(sources)} and the appendix agree on all "
          f"{len(draft)} values")
    return 0


if __name__ == "__main__":
    sys.exit(main())
