#!/usr/bin/env python3
"""Manual mutation check: each line of tools/mutants.txt is `file<TAB>from<TAB>to`. The change is applied, the tests run, the file restored. A mutant that the tests do not notice SURVIVES (= a hole in the tests)."""
import subprocess, sys, pathlib
root = pathlib.Path(__file__).resolve().parent.parent
import os, json
src = root / os.environ.get("MUTANTS", "tools/mutants.txt")
if src.suffix == ".json":
    rows = json.loads(src.read_text())
else:
    rows = [l.rstrip("\n").split("\t") for l in src.read_text().splitlines() if l.strip() and not l.startswith("#")]
survived = []
for i, (f, a, b) in enumerate(rows, 1):
    p = root / f
    orig = p.read_text()
    if orig.count(a) != 1:
        print(f"[{i}] SKIP (pattern found {orig.count(a)} times): {a[:50]}"); survived.append((i, "bad pattern", a)); continue
    p.write_text(orig.replace(a, b))
    try:
        try:
            r = subprocess.run(["cargo", "test", "--offline", "-p", "yrl", "--no-fail-fast"] + os.environ.get("TESTARGS", "").split(), cwd=root, capture_output=True, text=True, timeout=int(os.environ.get("MUTANT_TIMEOUT", "400")))
        except subprocess.TimeoutExpired as e:
            # a mutant that makes the tests hang is noticed by them (the correct code finishes within minutes)
            class R: returncode = 1; stdout = ""; stderr = "timeout"
            r = R()
    finally:
        p.write_text(orig)
    out = r.stdout + r.stderr
    if 'error[' in out or 'could not compile' in out:
        print(f'[{i}] COMPILE ERROR (not a valid mutant): {a[:50]!r}'); survived.append((i, 'compile error', a)); continue
    killed = r.returncode != 0
    print(f"[{i}] {'killed' if killed else 'SURVIVED'}: {f}: {a[:60]!r} -> {b[:40]!r}", flush=True)
    if not killed: survived.append((i, f, a))
print(f"\n{len(rows) - len(survived)}/{len(rows)} killed; survivors: {survived}")
sys.exit(1 if survived else 0)
