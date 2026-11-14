#!/usr/bin/env python3
r"""Test harness for the NSP hook-validation method "pe-build-identity".

Stdlib only (Python 3.11+).  Runs the compiled helper over the 8-case lab
corpus, prints a table, verifies the JSON contract, and writes out/results.json.

Usage:
    python Test-Validation.py [--exe <path>] [--lab <dir>] [--out <dir>]

The default locations are resolved from this file:
    <repo>/build/hook-validation/nsp-hook-validate.exe
    <repo>/tools/hook-validation/out/results.json
The lab corpus (read-only) defaults to C:\WorkSpace\Claw\scratch\lead\nsp-branches\lab.
"""
import argparse
import datetime
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
DEFAULT_LAB = Path(r"C:\WorkSpace\Claw\scratch\lead\nsp-branches\lab")
CONTRACT_KEYS = {"method", "reference", "candidate", "build", "located",
                 "decision", "targetChanged", "checks", "timingMs"}
DECISIONS = {"allow", "warn", "deny", "unknown"}
BUILD_KEYS = {"fileVersion", "timeDateStamp", "sizeOfImage", "checksum"}

# Expected decisions under the DEFAULT policy (build identity + Microsoft
# Authenticode gate).  The identity-only expectation is what a buildId-only
# gate would decide and is printed separately, because that is where the
# method's blind spot shows up.
CASES = [
    # id, candidate file, expected strict decision, expected identity-only decision, note
    ("ref-self", "audiodg-build-26100.9444.exe", "allow", "allow",
     "pinned build, unmodified"),
    ("A-mut-else", "audiodg-A-mut-else.exe", "deny", "allow",
     "1 byte changed outside target fn; buildId identical"),
    ("A-mut-fn", "audiodg-A-mut-fn.exe", "deny", "allow",
     "1 byte changed INSIDE target fn; buildId identical"),
    ("build-9711", "audiodg-build-26100.9711.exe", "warn", "warn",
     "newer Microsoft build, signature valid"),
    ("build-9974", "audiodg-build-26100.9974.exe", "warn", "warn",
     "newest Microsoft build, signature valid"),
    ("system-9949", "audiodg-system-26100.9949.exe", "warn", "warn",
     "system copy (byte-identical to 9974)"),
    ("D-mut-fn", "audiodg-D-mut-fn.exe", "deny", "warn",
     "9974 plus 1 byte inside target fn; signature broken"),
    ("D-mut-else", "audiodg-D-mut-else.exe", "deny", "warn",
     "9974 plus 1 byte outside target fn; signature broken"),
]

REFERENCE = "audiodg-build-26100.9444.exe"


def run_tool(exe, reference, candidate, ignore_signature=False):
    args = [str(exe), "--method", "pe-build-identity",
            "--reference", str(reference), "--candidate", str(candidate),
            "--json"]
    if ignore_signature:
        args.append("--ignore-signature")
    started = time.perf_counter()
    proc = subprocess.run(args, capture_output=True, text=True, timeout=120)
    wall_ms = (time.perf_counter() - started) * 1000.0
    return proc, wall_ms


def validate_contract(payload, reference, candidate):
    """Return list of schema violations ([] == contract satisfied)."""
    problems = []
    missing = CONTRACT_KEYS - set(payload)
    if missing:
        problems.append("missing keys: " + ",".join(sorted(missing)))
    if payload.get("method") != "pe-build-identity":
        problems.append("method mismatch")
    if payload.get("reference") != str(reference):
        problems.append("reference path mismatch")
    if payload.get("candidate") != str(candidate):
        problems.append("candidate path mismatch")
    build = payload.get("build")
    if not isinstance(build, dict):
        problems.append("build is not an object")
    else:
        miss = BUILD_KEYS - set(build)
        if miss:
            problems.append("build missing keys: " + ",".join(sorted(miss)))
    if payload.get("decision") not in DECISIONS:
        problems.append("invalid decision")
    if payload.get("located") is not None:
        problems.append("located must be null for pe-build-identity")
    if payload.get("targetChanged") is not None:
        problems.append("targetChanged must be null for pe-build-identity")
    if not isinstance(payload.get("checks"), list) or not payload["checks"]:
        problems.append("checks must be a non-empty array")
    else:
        for check in payload["checks"]:
            if not {"name", "ok", "detail"} <= set(check):
                problems.append("check missing name/ok/detail")
                break
    if not isinstance(payload.get("timingMs"), (int, float)):
        problems.append("timingMs is not numeric")
    return problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default=str(REPO / "build" / "hook-validation" / "nsp-hook-validate.exe"))
    ap.add_argument("--lab", default=str(DEFAULT_LAB))
    ap.add_argument("--out", default=str(HERE / "out"))
    args = ap.parse_args()

    exe = Path(args.exe).resolve()
    lab = Path(args.lab).resolve()
    outdir = Path(args.out).resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    reference = lab / REFERENCE
    if not exe.is_file():
        sys.exit(f"tool not built: {exe} (run Build.ps1 first)")
    if not reference.is_file():
        sys.exit(f"reference build missing: {reference}")

    print("=" * 108)
    print(" NSP hook-validation -- method: pe-build-identity (build identity + Microsoft Authenticode gate)")
    print(" tool     :", exe)
    print(" lab      :", lab)
    print("=" * 108)

    rows = []
    strict_passed = strict_total = 0
    identity_passed = identity_total = 0
    print(f"\n{'#':>2}  {'case':<12} {'candidate':<32} {'decision':<8} {'expect':<7} {'res':<5} "
          f"{'buildId':<8} {'sig':<9} {'located':<7} {'ms':>8}")
    print("-" * 108)
    for index, (case_id, cand_name, expected, expected_identity, note) in enumerate(CASES, 1):
        candidate = lab / cand_name
        row = {"index": index, "case": case_id, "candidate": cand_name,
               "candidatePath": str(candidate), "expected": expected,
               "expectedIdentityOnly": expected_identity, "note": note}
        if not candidate.is_file():
            row.update({"error": "candidate file missing", "pass": False})
            rows.append(row)
            strict_total += 1
            identity_total += 1
            print(f"{index:>2}  {case_id:<12} {cand_name:<32} {'-':<8} {expected:<7} {'FAIL':<5} "
                  f"{'-':<8} {'-':<9} {'-':<7} {'-':>8}")
            continue

        proc, wall_ms = run_tool(exe, reference, candidate)
        row["exitCode"] = proc.returncode
        row["wallMs"] = round(wall_ms, 3)
        payload = None
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            row["error"] = f"stdout is not a single JSON object: {exc}"
        if proc.stderr.strip():
            row["stderr"] = proc.stderr.strip()

        if payload is not None:
            problems = validate_contract(payload, reference, candidate)
            decision = payload.get("decision")
            build = payload.get("build") or {}
            sig = payload.get("signature") or {}
            row.update({
                "decision": decision,
                "pass": (not problems and proc.returncode == 0 and decision == expected),
                "contractProblems": problems,
                "buildIdMatch": payload.get("buildIdMatch"),
                "build": {k: build.get(k) for k in
                          ("fileVersion", "timeDateStamp", "sizeOfImage", "checksum", "buildId")},
                "referenceBuild": {k: (payload.get("referenceBuild") or {}).get(k) for k in
                                   ("fileVersion", "timeDateStamp", "sizeOfImage", "checksum", "buildId")},
                "signature": {k: sig.get(k) for k in
                              ("candidateStatus", "candidateSignerSubject",
                               "candidateMicrosoftSigned", "gateEnabled")},
                "located": payload.get("located"),
                "targetChanged": payload.get("targetChanged"),
                "timingMs": payload.get("timingMs"),
                "checksOk": sum(1 for c in payload.get("checks", []) if c.get("ok")),
                "checksTotal": len(payload.get("checks", [])),
                "rationale": payload.get("rationale"),
                "raw": payload,
            })
        else:
            row.update({"pass": False})

        # identity-only diagnostic (buildId-only gate): what the method sees
        # when the signature gate is switched off.
        diag_proc, diag_wall = run_tool(exe, reference, candidate, ignore_signature=True)
        diag = None
        try:
            diag = json.loads(diag_proc.stdout)
        except json.JSONDecodeError:
            pass
        identity = {"exitCode": diag_proc.returncode, "wallMs": round(diag_wall, 3)}
        if diag is not None:
            identity.update({
                "decision": diag.get("decision"),
                "buildIdMatch": diag.get("buildIdMatch"),
                "pass": diag.get("decision") == expected_identity,
                "gateEnabled": (diag.get("signature") or {}).get("gateEnabled"),
                "rationale": diag.get("rationale"),
            })
        else:
            identity["pass"] = False
        row["identityOnly"] = identity

        strict_total += 1
        identity_total += 1
        if row.get("pass"):
            strict_passed += 1
        if identity.get("pass"):
            identity_passed += 1

        decision = row.get("decision", "-")
        sig = (row.get("signature") or {}).get("candidateStatus", "-")
        match = "match" if row.get("buildIdMatch") else ("diff" if row.get("buildIdMatch") is False else "-")
        verdict = "PASS" if row.get("pass") else "FAIL"
        print(f"{index:>2}  {case_id:<12} {cand_name:<32} {decision:<8} {expected:<7} {verdict:<5} "
              f"{match:<8} {sig:<9} {'null':<7} {row.get('timingMs', 0):>8.2f}")
        rows.append(row)

    print("-" * 108)
    print(f" strict policy   : passed {strict_passed}/{strict_total}")
    print(f" identity-only   : passed {identity_passed}/{identity_total}")

    # ---------------------------------------------------------------- tables
    print("\n" + "=" * 108)
    print(" IDENTITY-ONLY VIEW (--ignore-signature, diagnostic): this is what the build identity alone can see")
    print("=" * 108)
    print(f"{'#':>2}  {'case':<12} {'buildId':<8} {'identity decision':<18} {'expected':<9} {'res':<5} why")
    print("-" * 108)
    for row in rows:
        identity = row.get("identityOnly") or {}
        match = "match" if row.get("buildIdMatch") else ("diff" if row.get("buildIdMatch") is False else "-")
        verdict = "PASS" if identity.get("pass") else "FAIL"
        why = row.get("note", "")
        print(f"{row['index']:>2}  {row['case']:<12} {match:<8} {str(identity.get('decision','-')):<18} "
              f"{row['expectedIdentityOnly']:<9} {verdict:<5} {why}")

    print("\n" + "=" * 108)
    print(" LIMITATION (must be read with the table above)")
    print("=" * 108)
    print(" * A-mut-fn and A-mut-else share the reference buildId EXACTLY")
    print("   (966F569F-000D7000-000E370E): build identity is completely blind to")
    print("   same-build byte changes.  A buildId-only gate therefore returns")
    print("   allow for A-mut-fn -> missed detection (see identity-only table).")
    print(" * The default policy adds Authenticode.  Any mutation of a signed image")
    print("   breaks the signature (TRUST_E_BAD_DIGEST), so A-mut-fn is denied --")
    print("   but that is whole-file integrity, NOT proof about the target function.")
    print("   It equally denies A-mut-else (target function untouched): a false")
    print("   positive at function granularity.")
    print(" * A same-build candidate that was re-signed after patching would pass")
    print("   Authenticode and be allowed: this cannot be reproduced offline because")
    print("   the lab has no Microsoft signing key; it stays an unproven residual risk.")
    print(" * located is always null and targetChanged always null: this method does")
    print("   not locate the hooked function and does not measure it.")

    # ------------------------------------------------------------ results.json
    results = {
        "generatedAt": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "method": "pe-build-identity",
        "description": "PE build identity (TimeDateStamp+SizeOfImage+CheckSum+fileVersion) plus Microsoft Authenticode gate",
        "tool": str(exe),
        "labDir": str(lab),
        "reference": str(reference),
        "policy": {
            "default": "buildId match + valid Microsoft Authenticode => allow; invalid/unsigned signature => deny; valid signature + different build => warn; unverifiable => unknown",
            "identityOnlyDiagnostic": "--ignore-signature: decision from buildId only (NOT a security policy)",
        },
        "summary": {
            "cases": len(rows),
            "strictPassed": strict_passed,
            "strictTotal": strict_total,
            "identityOnlyPassed": identity_passed,
            "identityOnlyTotal": identity_total,
            "strictDecisions": {d: sum(1 for r in rows if r.get("decision") == d)
                                for d in ("allow", "warn", "deny", "unknown")},
            "identityOnlyDecisions": {d: sum(1 for r in rows
                                             if (r.get("identityOnly") or {}).get("decision") == d)
                                      for d in ("allow", "warn", "deny", "unknown")},
        },
        "knownLimitation": {
            "buildIdBlindToSameBuildMutations": "A-mut-fn/A-mut-else carry byte-identical build identity to the reference; without the signature gate they are allowed (missed detection).",
            "signatureGateIsWholeFileOnly": "With the signature gate the mutations are denied, but only because Authenticode covers the whole file; A-mut-else (target function untouched) is denied too, and no evidence about the target function body is produced.",
            "sameBuildIdResignedBinary": "A re-signed same-build patched binary would pass and be allowed; not reproducible offline (no Microsoft signing key).",
            "noLocation": "located=null, targetChanged=null by design.",
        },
        "cases": rows,
    }
    results_path = outdir / "results.json"
    results_path.write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\nwrote {results_path}")
    return 0 if strict_passed == strict_total and identity_passed == identity_total else 1


if __name__ == "__main__":
    sys.exit(main())
