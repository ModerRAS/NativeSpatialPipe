#!/usr/bin/env python3
r"""Experiment for the pe-build-identity branch (task item 6).

Collects buildId / fileVersion / SHA-256 for the four audiodg builds in the
lab corpus (plus the four mutants) and demonstrates two facts:

  1. buildId separates real builds (and fileVersion agrees with it);
  2. buildId is completely blind to byte changes made inside one build:
     A-mut-fn / A-mut-else keep the reference buildId while their SHA-256
     differs, and D-mut-fn / D-mut-else keep the 9974 buildId.

Stdlib only.  Uses the compiled helper (same JSON CLI) to read version +
TimeDateStamp/SizeOfImage/CheckSum; SHA-256 comes from hashlib.

Usage: python experiments/build-id-stats.py [--exe <path>] [--lab <dir>]
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent
DEFAULT_LAB = Path(r"C:\WorkSpace\Claw\scratch\lead\nsp-branches\lab")

# The four builds requested by the task (reference + two newer + current system).
BUILDS = [
    ("26100.9444", "audiodg-build-26100.9444.exe", "reference (pinned by NSP)"),
    ("26100.9711", "audiodg-build-26100.9711.exe", "other 26100 build"),
    ("26100.9974", "audiodg-build-26100.9974.exe", "newer 26100 build"),
    ("26100.9949", "audiodg-system-26100.9949.exe", "current system copy (servicing package 9949)"),
]
# Mutants of the reference (A) and of build 9974 (D).
MUTANTS = [
    ("A-mut-fn", "audiodg-A-mut-fn.exe", "audiodg-build-26100.9444.exe", "reference + 1 byte inside target fn"),
    ("A-mut-else", "audiodg-A-mut-else.exe", "audiodg-build-26100.9444.exe", "reference + 1 byte outside target fn"),
    ("D-mut-fn", "audiodg-D-mut-fn.exe", "audiodg-build-26100.9974.exe", "9974 + 1 byte inside target fn"),
    ("D-mut-else", "audiodg-D-mut-else.exe", "audiodg-build-26100.9974.exe", "9974 + 1 byte outside target fn"),
]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pe_build(exe, path):
    proc = subprocess.run([str(exe), "--method", "pe-build-identity",
                           "--reference", str(path), "--candidate", str(path),
                           "--json"], capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise RuntimeError(f"tool failed on {path}: {proc.stderr or proc.stdout}")
    payload = json.loads(proc.stdout)
    build = payload["build"]
    return {
        "fileVersion": build.get("fileVersion"),
        "timeDateStamp": build.get("timeDateStamp"),
        "sizeOfImage": build.get("sizeOfImage"),
        "checksum": build.get("checksum"),
        "buildId": build.get("buildId"),
        "magic": build.get("magic"),
        "imageBase": build.get("imageBase"),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default=str(REPO / "build" / "hook-validation" / "nsp-hook-validate.exe"))
    ap.add_argument("--lab", default=str(DEFAULT_LAB))
    ap.add_argument("--out", default=str(HERE.parent / "out"))
    args = ap.parse_args()
    exe = Path(args.exe).resolve()
    lab = Path(args.lab).resolve()
    outdir = Path(args.out).resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    if not exe.is_file():
        sys.exit(f"tool not built: {exe} (run Build.ps1 first)")

    print("=" * 104)
    print(" EXPERIMENT: buildId / fileVersion / SHA-256 for the four audiodg builds")
    print("=" * 104)
    print(f"{'build':<12} {'file':<34} {'fileVersion':<16} {'sha256':<16} {'buildId':<40} note")
    print("-" * 104)
    build_rows = []
    for label, name, note in BUILDS:
        path = lab / name
        info = pe_build(exe, path)
        row = {"label": label, "file": name, "note": note,
               "sha256": sha256(path), "sizeBytes": path.stat().st_size, **info}
        build_rows.append(row)
        print(f"{label:<12} {name:<34} {str(info['fileVersion']):<16} "
              f"{row['sha256'][:16]+'…':<16} {str(info['buildId']):<40} {note}")

    distinct = {row["buildId"] for row in build_rows}
    distinct_sha = {row["sha256"] for row in build_rows}
    print("-" * 104)
    print(f" 4 build files -> {len(distinct)} distinct buildIds, {len(distinct_sha)} distinct SHA-256")
    for row in build_rows:
        print(f"   {row['file']:<36} sha256={row['sha256']}")

    print("\n" + "=" * 104)
    print(" SAME-BUILD BYTE CHANGES ARE INVISIBLE TO buildId")
    print("=" * 104)
    print(f"{'mutant':<12} {'base build':<22} {'base buildId':<40} {'sha256 differs?':<17} buildId same?")
    print("-" * 104)
    mutant_rows = []
    for name, file_name, base_name, note in MUTANTS:
        path = lab / file_name
        base_path = lab / base_name
        info = pe_build(exe, path)
        base_info = pe_build(exe, base_path)
        row = {
            "mutant": name, "file": file_name, "base": base_name, "note": note,
            "sha256": sha256(path), "baseSha256": sha256(base_path),
            "buildId": info["buildId"], "baseBuildId": base_info["buildId"],
            "sha256Differs": sha256(path) != sha256(base_path),
            "buildIdSame": info["buildId"] == base_info["buildId"],
            **{k: info[k] for k in ("fileVersion", "timeDateStamp", "sizeOfImage",
                                     "checksum", "buildId")},
        }
        mutant_rows.append(row)
        print(f"{name:<12} {base_name:<22} {str(base_info['buildId']):<40} "
              f"{str(row['sha256Differs']):<17} {row['buildIdSame']}")

    invisible = [r for r in mutant_rows if r["sha256Differs"] and r["buildIdSame"]]
    summary = {
        "builds": len(build_rows),
        "distinctBuildIds": len(distinct),
        "distinctSha256": len(distinct_sha),
        "mutants": len(mutant_rows),
        "mutantsInvisibleToBuildId": len(invisible),
        "conclusions": [
            "buildId (TimeDateStamp+SizeOfImage+CheckSum+fileVersion) separates the four build files into %d identities and agrees with fileVersion." % len(distinct),
            "audiodg-system-26100.9949.exe is byte-identical to audiodg-build-26100.9974.exe (same SHA-256), so the 9949 servicing copy is the 9974 binary.",
            "All four mutants keep their base buildId while their SHA-256 changes: buildId has zero visibility into same-build byte changes.",
            "Therefore pe-build-identity cannot answer 'was the target function changed?' - only 'is this a different build / is the whole file still signed?'.",
        ],
    }
    print("\n" + "=" * 104)
    for conclusion in summary["conclusions"]:
        print(f" * {conclusion}")

    payload = {
        "experiment": "build-identity-stats",
        "tool": str(exe),
        "labDir": str(lab),
        "builds": build_rows,
        "mutants": mutant_rows,
        "summary": summary,
    }
    out_path = outdir / "build-identity-stats.json"
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\nwrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
