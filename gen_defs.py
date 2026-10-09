#!/usr/bin/env python3
"""
Generate xd_defs.h: per-network lookup tables for the xd.c deserializer.

XRPL and Xahau share the binary format but NOT the field/type tables: several
(type, field-code) pairs, transaction types and ledger entry types mean
different things on each network. So we generate one set of tables per
network, straight from each server's own definition macros:

    include/xrpl/protocol/SField.h                     (STI_* type codes)
    include/xrpl/protocol/detail/sfields.macro          (fields)
    include/xrpl/protocol/detail/transactions.macro     (TransactionType)
    include/xrpl/protocol/detail/ledger_entries.macro   (LedgerEntryType)
    include/xrpl/protocol/TER.h                         (TransactionResult)

Usage:
    ./gen_defs.py --xrpl /path/to/rippled --xahau /path/to/xahaud > xd_defs.h

Only the files above are read, so a sparse checkout is enough.
"""

import argparse
import os
import re
import subprocess
import sys


def read(root, rel):
    path = os.path.join(root, rel)
    with open(path, encoding="utf-8") as f:
        return f.read()


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def parse_stypes(root):
    text = read(root, "include/xrpl/protocol/SField.h")
    out = {}
    for name, val in re.findall(r"STYPE\(\s*STI_(\w+)\s*,\s*(-?\d+)\s*\)", text):
        out[name] = int(val)
    if "UINT32" not in out or "OBJECT" not in out:
        sys.exit(f"could not parse STI_* types from {root}")
    return out


def parse_sfields(root, stypes):
    text = strip_comments(read(root, "include/xrpl/protocol/detail/sfields.macro"))
    fields = {}
    rx = re.compile(r"\b(?:TYPED_SFIELD|UNTYPED_SFIELD)\(\s*sf(\w+)\s*,\s*(\w+)\s*,\s*(\d+)")
    for name, tname, code in rx.findall(text):
        if tname not in stypes:
            sys.exit(f"{root}: field sf{name} has unknown type {tname}")
        t, c = stypes[tname], int(code)
        # Only fields that can actually appear on the wire: one-byte type
        # and field codes. (Untyped 10001+ wrappers and 257+ codes never do.)
        if not (0 < t < 256 and 0 < c < 256):
            continue
        key = (t, c)
        if key in fields and fields[key] != name:
            sys.exit(f"{root}: duplicate field code {key}: {fields[key]} / {name}")
        fields[key] = name
    if len(fields) < 100:
        sys.exit(f"{root}: suspiciously few fields parsed ({len(fields)})")
    return fields


def parse_txtypes(root):
    text = strip_comments(read(root, "include/xrpl/protocol/detail/transactions.macro"))
    out = {}
    for val, name in re.findall(r"\bTRANSACTION\(\s*tt\w+\s*,\s*(\d+)\s*,\s*(\w+)", text):
        v = int(val)
        if v in out and out[v] != name:
            sys.exit(f"{root}: duplicate tx type {v}")
        out[v] = name
    if len(out) < 20:
        sys.exit(f"{root}: suspiciously few transaction types parsed")
    return out


def parse_char_or_int(tok):
    tok = tok.strip()
    m = re.fullmatch(r"'(.)'", tok)
    if m:
        return ord(m.group(1))
    return int(tok, 0)


def parse_letypes(root):
    text = strip_comments(read(root, "include/xrpl/protocol/detail/ledger_entries.macro"))
    out = {}
    rx = re.compile(r"\bLEDGER_ENTRY(?:_DUPLICATE)?\(\s*lt\w+\s*,\s*('.'|0[xX][0-9a-fA-F]+|\d+)\s*,\s*(\w+)")
    for val, name in rx.findall(text):
        v = parse_char_or_int(val)
        if v in out and out[v] != name:
            sys.exit(f"{root}: duplicate ledger entry type {v}")
        out[v] = name
    if len(out) < 15:
        sys.exit(f"{root}: suspiciously few ledger entry types parsed")
    return out


def parse_ter(root):
    """tes and tec codes only: those are the only results stored on ledger
    (TransactionResult is a UInt8 in metadata)."""
    text = strip_comments(read(root, "include/xrpl/protocol/TER.h"))
    out = {}
    for enum in ("TEScodes", "TECcodes"):
        m = re.search(r"enum\s+" + enum + r"\b[^{]*\{(.*?)\};", text, flags=re.S)
        if not m:
            sys.exit(f"{root}: could not find enum {enum}")
        known = {}
        nxt = 0
        for item in m.group(1).split(","):
            item = re.sub(r"\[\[.*?\]\]", "", item).strip()
            if not item:
                continue
            mm = re.fullmatch(r"(\w+)\s*(?:=\s*(.+))?", item, flags=re.S)
            if not mm:
                sys.exit(f"{root}: cannot parse enum item {item!r} in {enum}")
            name, expr = mm.group(1), mm.group(2)
            if expr is not None:
                expr = expr.strip()
                val = known[expr] if expr in known else int(expr, 0)
            else:
                val = nxt
            known[name] = val
            nxt = val + 1
            if 0 <= val <= 255:
                out.setdefault(val, name)
    if 0 not in out or 100 not in out:
        sys.exit(f"{root}: TER parse failed")
    return out


def git_ref(root):
    try:
        return subprocess.check_output(
            ["git", "-C", root, "rev-parse", "HEAD"], stderr=subprocess.DEVNULL, text=True
        ).strip()
    except Exception:
        return "unknown"


def emit_switch(fn, keytype, table, keyfmt, comment):
    lines = [f"/* {comment} */", f"static inline const char* {fn}({keytype})", "{", "    switch (key)", "    {"]
    for k in sorted(table):
        lines.append(f"        case {keyfmt(k)}: return \"{table[k]}\";")
    lines += ["        default: return 0;", "    }", "}", ""]
    return "\n".join(lines)


def emit_network(tag, root, ref):
    stypes = parse_stypes(root)
    fields = parse_sfields(root, stypes)
    tx = parse_txtypes(root)
    le = parse_letypes(root)
    ter = parse_ter(root)
    out = [f"/* ---- {tag}: {len(fields)} fields, {len(tx)} transaction types, "
           f"{len(le)} ledger entry types, {len(ter)} tes/tec codes ---- */", ""]
    fields_by_key = {(t << 8) | c: n for (t, c), n in fields.items()}
    out.append(emit_switch(
        f"xd_field_name_{tag}", "int key", fields_by_key,
        lambda k: f"0x{k:04X}", "key = (type_code << 8) | field_code"))
    out.append(emit_switch(f"xd_tx_name_{tag}", "int key", tx, str, "TransactionType"))
    out.append(emit_switch(f"xd_le_name_{tag}", "int key", le, lambda k: f"0x{k:04X}", "LedgerEntryType"))
    out.append(emit_switch(f"xd_ter_name_{tag}", "int key", ter, str, "TransactionResult (tes/tec)"))
    return "\n".join(out), stypes


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--xrpl", required=True, help="rippled source tree")
    ap.add_argument("--xahau", required=True, help="xahaud source tree")
    ap.add_argument("--xrpl-ref", help="override recorded rippled commit")
    ap.add_argument("--xahau-ref", help="override recorded xahaud commit")
    a = ap.parse_args()

    xrpl_ref = a.xrpl_ref or git_ref(a.xrpl)
    xahau_ref = a.xahau_ref or git_ref(a.xahau)
    xrpl_body, xrpl_st = emit_network("xrpl", a.xrpl, xrpl_ref)
    xahau_body, xahau_st = emit_network("xahau", a.xahau, xahau_ref)

    # The deserializer hard-codes the wire format of each STI type, so the
    # type codes themselves must agree between the two networks.
    for name in set(xrpl_st) & set(xahau_st):
        if xrpl_st[name] != xahau_st[name]:
            sys.exit(f"STI_{name} differs between networks: {xrpl_st[name]} vs {xahau_st[name]}")

    print("/* GENERATED by gen_defs.py -- do not edit by hand.")
    print(f" * XRPL : XRPLF/rippled  {xrpl_ref}")
    print(f" * Xahau: Xahau/xahaud   {xahau_ref}")
    print(" */")
    print("#ifndef XD_DEFS_H\n#define XD_DEFS_H\n")
    print(xrpl_body)
    print(xahau_body)
    print("#endif")


if __name__ == "__main__":
    main()
