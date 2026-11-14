#!/usr/bin/env python3
"""Test-Validation.py - acceptance tests for the cross-build fingerprint hook validator.

8 cases over the synthetic audiodg.exe corpus (lab/). Standard library only.

Usage:
    python tools/hook-validation/Test-Validation.py [--lab <lab-dir>] [--json-out <path>]
"""
import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
EXE = os.path.join(REPO, "build", "hook-validation", "nsp-hook-validate.exe")
DB = os.path.join(HERE, "builds.json")
DEFAULT_LAB = os.path.join(os.path.dirname(REPO), "lab")  # <lead>/lab next to all worktrees

REF = "audiodg-build-26100.9444.exe"
REF_RVA = 0x31930          # pinned by Native-Hook.c / Native-Hook-Control.c
NEW_RVA = 0x32C40          # 9974/9949 series: target function moved

# name, candidate file, expected decision, expected targetChanged, expected rva (or 'moved'/'any')
CASES = [
    ("A-self",        REF,                          "allow", False, REF_RVA),
    ("A-mut-else",    "audiodg-A-mut-else.exe",     "allow", False, REF_RVA),
    ("A-mut-fn",      "audiodg-A-mut-fn.exe",       "deny",  True,  REF_RVA),
    ("B-9711",        "audiodg-build-26100.9711.exe", "allow", False, REF_RVA),
    ("C-9974",        "audiodg-build-26100.9974.exe", "warn",  None,  NEW_RVA),
    ("D-9949",        "audiodg-system-26100.9949.exe", "warn", None,  NEW_RVA),
    ("D-mut-fn",      "audiodg-D-mut-fn.exe",       "deny",  True,  NEW_RVA),
    ("D-mut-else",    "audiodg-D-mut-else.exe",     "warn",  None,  NEW_RVA),
]


def locate_lab(explicit):
    if explicit:
        return explicit
    for cand in (DEFAULT_LAB, os.path.join(REPO, "lab")):
        cand = os.path.abspath(cand)
        if os.path.isfile(os.path.join(cand, REF)):
            return cand
    raise SystemExit("cannot find lab corpus; pass --lab <dir>")


def run_case(exe, db, ref, candidate):
    cmd = [exe, "--method", "crossbuild-fingerprint", "--reference", ref,
           "--candidate", candidate, "--db", db, "--json"]
    t0 = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    wall = (time.perf_counter() - t0) * 1000.0
    out = proc.stdout.strip()
    record = {"candidate": os.path.basename(candidate), "exitCode": proc.returncode,
              "stderr": proc.stderr.strip(), "wallMs": round(wall, 2)}
    if proc.returncode != 0:
        record["error"] = "non-zero exit"
        return record
    try:
        doc = json.loads(out)  # must be ONE json object
        if not isinstance(doc, dict):
            raise ValueError("not a JSON object")
    except ValueError as exc:
        record["error"] = "stdout is not a single JSON object: %s" % exc
        record["stdout"] = out[:400]
        return record
    record["result"] = doc
    return record


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lab", default=None)
    ap.add_argument("--json-out", default=os.path.join(REPO, "out", "results.json"))
    args = ap.parse_args()
    lab = locate_lab(args.lab)
    if not os.path.isfile(EXE):
        raise SystemExit("validator not built: %s (run tools/hook-validation/Build.ps1)" % EXE)
    ref_path = os.path.join(lab, REF)

    rows, failures = [], []
    for name, cand, want_decision, want_changed, want_rva in CASES:
        rec = run_case(EXE, DB, ref_path, os.path.join(lab, cand))
        res = rec.get("result") or {}
        located = res.get("located") or {}
        got_rva = located.get("rva")
        checks = {c["name"]: c["ok"] for c in res.get("checks", [])}
        problems = []
        if rec["exitCode"] != 0:
            problems.append("exit=%d %s" % (rec["exitCode"], rec.get("stderr", "")))
        if res.get("decision") != want_decision:
            problems.append("decision=%r want %r" % (res.get("decision"), want_decision))
        if want_changed is not None and res.get("targetChanged") != want_changed:
            problems.append("targetChanged=%r want %r" % (res.get("targetChanged"), want_changed))
        if want_rva is not None and got_rva != want_rva:
            problems.append("located.rva=%r want 0x%x" % (got_rva, want_rva))
        if want_rva is not None and not located:
            problems.append("function not located")
        ok = not problems
        if not ok:
            failures.append((name, problems))
        rows.append({
            "case": name, "candidate": cand, "ok": ok,
            "decision": res.get("decision"), "targetChanged": res.get("targetChanged"),
            "buildId": (res.get("build") or {}).get("fileVersion"),
            "locatedRva": got_rva, "locatedSize": located.get("size"),
            "confidence": located.get("confidence"), "similarity": res.get("similarity"),
            "timingMs": res.get("timingMs"), "wallMs": rec["wallMs"],
            "aob": checks.get("aob"), "hash": checks.get("normalized-hash"),
            "mutationHeuristic": checks.get("mutation-heuristic"),
            "problems": problems,
        })

    # table
    print("%-12s %-32s %-8s %-6s %-10s %-9s %-7s %s" % (
        "case", "candidate", "decision", "chg", "rva", "sim", "ms", "ok"))
    print("-" * 104)
    for r in rows:
        rva = "0x%x" % r["locatedRva"] if r["locatedRva"] is not None else "-"
        sim = "%.4f" % r["similarity"] if r["similarity"] is not None else "-"
        ms = "%.1f" % r["timingMs"] if r["timingMs"] is not None else "-"
        chg = str(r["targetChanged"])
        print("%-12s %-32s %-8s %-6s %-10s %-9s %-7s %s" % (
            r["case"], r["candidate"], r["decision"], chg, rva, sim, ms,
            "PASS" if r["ok"] else "FAIL"))

    passed = sum(1 for r in rows if r["ok"])
    print("-" * 104)
    print("passed %d/%d" % (passed, len(rows)))
    for name, problems in failures:
        print("  FAIL %s: %s" % (name, "; ".join(problems)))

    os.makedirs(os.path.dirname(os.path.abspath(args.json_out)) or ".", exist_ok=True)
    payload = {"exe": EXE, "db": DB, "lab": lab, "reference": REF,
               "method": "crossbuild-fingerprint", "passed": passed, "total": len(rows),
               "cases": rows, "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%S")}
    with open(args.json_out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print("wrote", args.json_out)
    return 0 if passed == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())