#!/usr/bin/env python3
"""Test harness for branch 1: unwind-fn-hash (stdlib only).

Runs the 8 lab cases against the pinned reference build plus two supplementary
same-build cases (reference = build 26100.9974, where the target function lives at
RVA 0x32c40). Prints a table and writes out/results.json.
"""
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

METHOD = "unwind-fn-hash"
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
LAB = REPO.parent / "lab"
EXE = REPO / "build" / "hook-validation" / "nsp-hook-validate.exe"
OUT = HERE / "out"
REFERENCE = LAB / "audiodg-build-26100.9444.exe"
REFERENCE_RVA = "31930"

# (candidate, expected decision, expected targetChanged, note)
CASES = [
    ("audiodg-build-26100.9444.exe", "allow", False, "reference build itself"),
    ("audiodg-A-mut-else.exe", "allow", False, "unrelated .reloc byte flipped; target untouched"),
    ("audiodg-A-mut-fn.exe", "deny", True, "target function body byte flipped"),
    ("audiodg-build-26100.9711.exe", "deny", True, "new build, same RVA+prologue, 4 body bytes changed"),
    ("audiodg-build-26100.9974.exe", "unknown", None, "new build, target moved 0x31930 -> 0x32c40"),
    ("audiodg-system-26100.9949.exe", "unknown", None, "identical file served from another servicing path"),
    ("audiodg-D-mut-else.exe", "unknown", None, "new build + unrelated mutation"),
    ("audiodg-D-mut-fn.exe", "unknown", None, "new build + function mutation (invisible to exact hash vs 9444)"),
]

# Same-build path exercised against the newer build (target RVA differs per build).
SUPPLEMENTARY = [
    ("audiodg-build-26100.9974.exe", "32c40", "audiodg-D-mut-else.exe", "allow", False),
    ("audiodg-build-26100.9974.exe", "32c40", "audiodg-D-mut-fn.exe", "deny", True),
]


def run_tool(reference: Path, candidate: Path, reference_rva: str = None):
    command = [str(EXE), "--method", METHOD, "--reference", str(reference), "--candidate", str(candidate), "--json"]
    if reference_rva:
        command += ["--ref-rva", reference_rva]
    started = time.perf_counter()
    proc = subprocess.run(command, capture_output=True, text=True, encoding="utf-8")
    wall_ms = (time.perf_counter() - started) * 1000.0
    if proc.returncode != 0:
        raise RuntimeError("tool failed (%d): %s / %s" % (proc.returncode, proc.stdout.strip(), proc.stderr.strip()))
    payload = proc.stdout.strip()
    if payload.count("\n"):
        raise RuntimeError("stdout is not a single JSON object: %r" % payload[:200])
    return json.loads(payload), wall_ms


def check_named(checks, name):
    for check in checks:
        if check.get("name") == name:
            return check
    return None


def reference_info(result):
    check = check_named(result["checks"], "referenceTarget")
    match = re.search(r"rva=0x([0-9a-f]+) size=(\d+) normalizedSha256=([0-9a-f]{64})", check["detail"] if check else "")
    if not match:
        return None
    return {"rva": int(match.group(1), 16), "size": int(match.group(2)), "sha256": match.group(3)}


def execute_case(reference: Path, candidate: Path, reference_rva: str = None):
    result, wall_ms = run_tool(reference, candidate, reference_rva)
    located = result.get("located")
    hash_check = check_named(result["checks"], "normalizedHashMatch")
    return {
        "candidate": candidate.name,
        "decision": result["decision"],
        "targetChanged": result["targetChanged"],
        "located": located,
        "referenceHashHit": bool(hash_check["ok"]) if hash_check else None,
        "timingMs": result["timingMs"],
        "processMs": round(wall_ms, 3),
        "build": result.get("build"),
        "checks": result["checks"],
    }


def print_table(title, rows):
    print()
    print(title)
    header = "%-32s %-8s %-14s %-14s %-8s %10s" % ("candidate", "decision", "targetChanged", "located.rva", "hashHit", "timingMs")
    print(header)
    print("-" * len(header))
    for row in rows:
        located = row["located"]
        located_text = ("0x%x/%d" % (located["rva"], located["size"])) if located else "null"
        changed = row["targetChanged"]
        changed_text = "null" if changed is None else ("true" if changed else "false")
        hash_hit = row["referenceHashHit"]
        hash_text = "n/a" if hash_hit is None else ("yes" if hash_hit else "no")
        print("%-32s %-8s %-14s %-14s %-8s %10.3f" % (
            row["candidate"], row["decision"], changed_text, located_text, hash_text, row["timingMs"]))


def main():
    if not EXE.exists():
        raise SystemExit("missing %s -- run tools/hook-validation/Build.ps1 first" % EXE)
    if not LAB.is_dir():
        raise SystemExit("missing lab corpus at %s" % LAB)

    primary = []
    passed = 0
    reference = None
    for name, expected_decision, expected_changed, note in CASES:
        row = execute_case(REFERENCE, LAB / name)
        row["expectedDecision"] = expected_decision
        row["expectedTargetChanged"] = expected_changed
        row["note"] = note
        row["pass"] = row["decision"] == expected_decision and row["targetChanged"] == expected_changed
        if reference is None:
            reference = reference_info({"checks": row["checks"]})
        passed += 1 if row["pass"] else 0
        primary.append(row)

    supplementary = []
    for reference_name, reference_rva, candidate_name, expected_decision, expected_changed in SUPPLEMENTARY:
        row = execute_case(LAB / reference_name, LAB / candidate_name, reference_rva)
        row["reference"] = reference_name
        row["referenceRva"] = reference_rva
        row["expectedDecision"] = expected_decision
        row["expectedTargetChanged"] = expected_changed
        row["pass"] = row["decision"] == expected_decision and row["targetChanged"] == expected_changed
        supplementary.append(row)

    # CLI contract sanity: a missing candidate must fail with non-zero exit and JSON error.
    error_contract = {"checked": False, "ok": False}
    try:
        proc = subprocess.run([str(EXE), "--method", METHOD, "--reference", str(REFERENCE),
                               "--candidate", str(LAB / "does-not-exist.exe"), "--json"],
                              capture_output=True, text=True, encoding="utf-8")
        error_contract["checked"] = True
        error_contract["exitCode"] = proc.returncode
        error_contract["json"] = proc.stdout.strip()
        error_contract["ok"] = proc.returncode != 0 and '"error"' in proc.stdout
    except OSError as exception:  # pragma: no cover - tool must exist by now
        error_contract["detail"] = str(exception)

    print("unwind-fn-hash validation -- reference = %s (target RVA 0x%s)" % (REFERENCE.name, REFERENCE_RVA))
    print("reference function: rva=0x%x size=%d sha256=%s" % (reference["rva"], reference["size"], reference["sha256"]))
    print_table("primary cases (8):", primary)
    print_table("supplementary same-build cases (reference = 26100.9974, target RVA 0x32c40):", supplementary)
    print()
    print("primary expectations: %d/%d passed" % (passed, len(primary)))
    print("supplementary expectations: %d/%d passed" % (sum(1 for r in supplementary if r["pass"]), len(supplementary)))
    print("CLI error contract: %s" % ("ok (non-zero exit + JSON error)" if error_contract["ok"] else "FAILED"))

    OUT.mkdir(parents=True, exist_ok=True)
    report = {
        "method": METHOD,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "tool": str(EXE),
        "reference": {"path": str(REFERENCE), "rva": int(REFERENCE_RVA, 16), "function": reference},
        "cases": primary,
        "supplementary": supplementary,
        "errorContract": error_contract,
        "passed": passed,
        "total": len(primary),
    }
    (OUT / "results.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("wrote %s" % (OUT / "results.json"))
    return 0 if passed == len(primary) and error_contract["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
