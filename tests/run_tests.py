#!/usr/bin/env python3
"""
Decodes every vector in tests/vectors_{xrpl,xahau}.json with xd.c (via the
tests/xd_decode harness) and compares the result with what the official
binary codec decoded from the same bytes.

Representation differences that are not errors are normalised:
  - xd.c prints UInt64 as a decimal number, the codecs as a (hex) string
  - xd.c prints IOU / Number values as fixed point, codecs may use exponents
  - xd.c additionally shows each path element's "type" byte (as rippled does)
Everything else (field names, nesting, order-independent values) must match.

Usage: tests/run_tests.py [path/to/xd_decode]
"""
import json
import os
import subprocess
import sys
from decimal import Decimal, InvalidOperation

HERE = os.path.dirname(os.path.abspath(__file__))
DECODER = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "xd_decode")


def decimal_equal(a, b):
    try:
        return Decimal(str(a)) == Decimal(str(b))
    except InvalidOperation:
        return False


def same(actual, expected, where, errors):
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            errors.append(f"{where}: expected object, got {actual!r}")
            return
        extra_ok = {"type"} if ".Paths[" in where else set()  # xd.c also shows the path element type byte
        if set(actual) - extra_ok != set(expected):
            errors.append(f"{where}: keys differ: missing={sorted(set(expected) - set(actual))} "
                          f"extra={sorted(set(actual) - set(expected))}")
        for k in set(actual) & set(expected):
            same(actual[k], expected[k], f"{where}.{k}", errors)
    elif isinstance(expected, list):
        if not isinstance(actual, list) or len(actual) != len(expected):
            errors.append(f"{where}: expected list of {len(expected)}, got {actual!r}"[:300])
            return
        for i, (x, y) in enumerate(zip(actual, expected)):
            same(x, y, f"{where}[{i}]", errors)
    elif isinstance(actual, int) and isinstance(expected, str):
        # UInt64: codec gives hex (or base-10 for a few MPT fields)
        ok = False
        for base in (16, 10):
            try:
                ok = ok or int(expected, base) == actual
            except ValueError:
                pass
        if not ok:
            errors.append(f"{where}: {actual!r} != {expected!r}")
    elif actual != expected:
        if isinstance(actual, str) and isinstance(expected, str) and decimal_equal(actual, expected):
            return
        if isinstance(actual, str) and isinstance(expected, str) and actual.upper() == expected.upper():
            return
        errors.append(f"{where}: {actual!r} != {expected!r}"[:300])


def run(network):
    path = os.path.join(HERE, f"vectors_{network}.json")
    vectors = json.load(open(path))
    args = [DECODER] + (["--xahau"] if network == "xahau" else []) + [v["hex"] for v in vectors]
    proc = subprocess.run(args, capture_output=True, text=True)
    outputs = proc.stdout.split("---\n")[:-1]
    if len(outputs) != len(vectors):
        print(f"[{network}] decoder produced {len(outputs)} outputs for {len(vectors)} vectors\n{proc.stderr}")
        return len(vectors)
    failures = 0
    for v, out in zip(vectors, outputs):
        errors = []
        try:
            actual = json.loads(out)
        except json.JSONDecodeError as e:
            errors.append(f"invalid JSON from decoder: {e}\n{out[:500]}")
        else:
            same(actual, v["expected"], "$", errors)
        status = "ok  " if not errors else "FAIL"
        print(f"[{network}] {status} {v['name']}")
        for e in errors:
            print(f"         {e}")
        failures += bool(errors)
    if proc.stderr.strip():
        print(f"[{network}] decoder stderr:\n{proc.stderr}")
    return failures


if __name__ == "__main__":
    total = run("xrpl") + run("xahau")
    print("ALL PASSED" if total == 0 else f"{total} FAILED")
    sys.exit(1 if total else 0)
