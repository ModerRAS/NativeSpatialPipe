#!/usr/bin/env python3
"""End-to-end test for the behavioral-shadow NSP1 validator.

1. generate fixtures (gen_fixtures.py)
2. run nsp-shadow-gate.exe over them -> results.json
3. cross-check C DLL against an independent pure-Python implementation
4. exercise the raw-slot DLL entry point (ready/nh/nd + 8192B JSON + payload)
5. measure C-core throughput

Exit code 0 only when every expectation and cross-check passes.
"""
import argparse
import ctypes as C
import json
import struct
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]  # repo root
BUILD = ROOT / "build/hook-validation"
OUT = BUILD / "out"
PY = sys.executable


def run(cmd, **kwargs):
    proc = subprocess.run(cmd, capture_output=True, text=True, **kwargs)
    if proc.returncode not in (0, 2, 3):
        raise SystemExit("command failed: %s\n%s\n%s" % (" ".join(map(str, cmd)), proc.stdout, proc.stderr))
    return proc


class Parts(C.Structure):
    _fields_ = [("count", C.c_uint32), ("frames", C.c_uint32), ("stride", C.c_uint32),
                ("sequence", C.c_uint64), ("capture_qpc_ns", C.c_uint64),
                ("prev_sequence", C.c_uint64), ("prev_qpc_ns", C.c_uint64),
                ("properties", C.POINTER(C.c_ubyte)), ("properties_len", C.c_size_t),
                ("pcm", C.POINTER(C.c_ubyte)), ("pcm_len", C.c_size_t)]


class Result(C.Structure):
    _fields_ = [("count", C.c_uint32), ("frames", C.c_uint32), ("stride", C.c_uint32),
                ("ok", C.c_int32), ("code", C.c_int32),
                ("checks", C.c_uint32), ("warning_count", C.c_uint32),
                ("detail", C.c_char * 512), ("warnings", (C.c_char * 48) * 8)]


def dll(lib, name, argtypes, restype=C.c_int):
    fn = getattr(lib, name)
    fn.argtypes = argtypes
    fn.restype = restype
    return fn


def make_slot(count, frames, seq=1, qpc=1000):
    stride = frames * 4
    props = b""
    for i in range(count):
        props += struct.pack("<IIII", i, frames, 1, 4) + struct.pack("<fff", 0.1, 0.2, -0.3) + struct.pack("<f", 1.0)
    pcm = struct.pack("<%df" % (count * frames), *([0.0] * (count * frames)))
    descriptor = json.dumps({
        "block": "0xdeadbeef", "sequence": seq, "ordinal": 0, "bufferIndex": 0,
        "count": count, "stride": stride, "threadId": 1,
        "captureQpcNs": qpc, "callbackStartQpcNs": qpc - 100,
        "copyDoneQpcNs": qpc + 100, "sendQpcNs": qpc + 200,
        "frames": [frames] * count,
    }, separators=(",", ":"))
    header = descriptor.encode()
    payload = props + pcm
    return struct.pack("<III", 1, len(header), len(payload)) + header.ljust(8192, b"\0") + payload


def check_slot(lib, slot, prev_seq=(1 << 64) - 1, prev_qpc=(1 << 64) - 1):
    buf = (C.c_ubyte * len(slot)).from_buffer_copy(slot)
    result = Result()
    rc = dll(lib, "nsp_shadow_check_ex",
             [C.POINTER(C.c_ubyte), C.c_size_t, C.c_uint64, C.c_uint64, C.c_uint, C.POINTER(Result)])(buf, len(slot), prev_seq, prev_qpc, 0, C.byref(result))
    assert rc == result.code, (rc, result.code)
    return {"ok": int(result.ok), "code": int(result.code),
            "detail": result.detail.decode("utf-8", "replace"),
            "warnings": [bytes(result.warnings[i]).decode("utf-8", "replace").rstrip("\x00")
                         for i in range(int(result.warning_count))]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bench-iterations", type=int, default=5000)
    args = ap.parse_args()
    BUILD.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)

    gate = BUILD / "nsp-shadow-gate.exe"
    gate_dll = BUILD / "nsp-shadow-gate.dll"
    for path in (gate, gate_dll):
        if not path.is_file():
            raise SystemExit("missing %s; run tools/hook-validation/Build.ps1 first" % path)

    fixtures = OUT / "fixtures.jsonl"
    results = OUT / "results.json"
    cross = OUT / "crosscheck.json"

    print("== 1. generate fixtures ==")
    gen = run([PY, str(HERE / "gen_fixtures.py"), "--out", str(fixtures)])
    print(gen.stdout.strip())

    print("\n== 2. nsp-shadow-gate --fixtures ==")
    begin = time.perf_counter()
    gate_run = run([str(gate), "--fixtures", str(fixtures), "--report", str(results)])
    gate_ms = (time.perf_counter() - begin) * 1000.0
    report = json.loads(results.read_text(encoding="utf-8"))

    print("%-34s %-12s %-5s %-8s %-13s %s" % ("case", "expect", "ok", "code", "warnings", "verdict"))
    print("-" * 92)
    for case in report["cases"]:
        print("%-34s %-12s %-5s %-8s %-13d %s" % (
            case["name"], case["expect"], "yes" if case["ok"] else "no",
            case["codeName"], len(case["warnings"]), "PASS" if case["matched"] else "FAIL"))
    totals = report["totals"]
    print("-" * 92)
    print("totals: cases=%d passed=%d failed=%d okCases=%d rejectCases=%d warnings=%d" % (
        totals["cases"], totals["passed"], totals["failed"], totals["okCases"],
        totals["rejectCases"], totals["warnings"]))
    print("gate wall time: %.1f ms for %d blocks (%.1f blocks/s incl. process start)" % (
        gate_ms, totals["cases"], totals["cases"] * 1000.0 / max(gate_ms, 1e-9)))

    print("\n== 3. C DLL vs pure-Python cross-check ==")
    cross_run = run([PY, str(HERE / "shadow_validate.py"), "--fixtures", str(fixtures),
                     "--dll", str(gate_dll), "--table", "--report", str(cross)])
    print(cross_run.stdout.strip())
    cross_summary = json.loads(cross.read_text(encoding="utf-8"))
    ct = cross_summary["totals"]

    print("\n== 4. raw NSP1 slot DLL entry ==")
    lib = C.CDLL(str(gate_dll))
    slot = make_slot(2, 16)
    good = check_slot(lib, slot)
    print("raw slot valid       -> ok=%d code=%d (%s)" % (good["ok"], good["code"], good["detail"]))
    nh = struct.unpack("<I", slot[4:8])[0]
    nd = struct.unpack("<I", slot[8:12])[0]
    payload = slot[12 + 8192:]
    short_payload = payload[:-32]
    truncated = check_slot(lib, struct.pack("<III", 1, nh, len(short_payload)) + slot[12:12 + 8192] + short_payload)
    print("raw slot truncated  -> ok=%d code=%d (%s)" % (truncated["ok"], truncated["code"], truncated["detail"]))
    not_ready = struct.pack("<III", 0, nh, nd) + bytes(slot[12:])
    not_ready_res = check_slot(lib, not_ready)
    print("raw slot ready=0    -> ok=%d code=%d (%s)" % (not_ready_res["ok"], not_ready_res["code"], not_ready_res["detail"]))
    seq_prev = check_slot(lib, slot, prev_seq=0)
    print("raw slot seq=1 prev=0 -> ok=%d code=%d" % (seq_prev["ok"], seq_prev["code"]))

    print("\n== 5. C-core throughput (nsp-shadow-gate --bench) ==")
    bench = json.loads(run([str(gate), "--bench", str(args.bench_iterations)]).stdout)["benchmark"]
    print("bench: %d iterations x (160 objects, 480 frames) -> %.0f blocks/s, %.2f us/block" % (
        bench["iterations"], bench["blocksPerSecond"], bench["usPerBlock"]))

    print("\n== 6. verdict ==")
    checks = {
        "gate_all_cases_match": totals["failed"] == 0,
        "gate_case_count_expected": totals["cases"] == 19,
        "normal_cases_ok": totals["expectedOk"] == 7 and totals["okCases"] == 7,
        "abnormal_cases_rejected": totals["expectedReject"] == 12 and totals["rejectCases"] == 12,
        "crosscheck_all_pass": ct["failed"] == 0,
        "dll_python_agree": ct["dllMismatches"] == 0,
        "raw_slot_valid_ok": good["ok"] == 1 and good["code"] == 0,
        "raw_slot_payload_truncation_rejected": truncated["ok"] == 0 and truncated["code"] == 6,
        "raw_slot_not_ready_rejected": not_ready_res["ok"] == 0 and not_ready_res["code"] == 15,
        "raw_slot_sequence_accepted": seq_prev["ok"] == 1,
        "throughput_floor": bench["blocksPerSecond"] >= 100.0,
    }
    for name, ok in checks.items():
        print("%-40s %s" % (name, "PASS" if ok else "FAIL"))
    failed = [k for k, v in checks.items() if not v]

    # Commit-sized evidence copy (small file).
    evidence = HERE / "out"
    evidence.mkdir(exist_ok=True)
    (evidence / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (evidence / "crosscheck.json").write_text(json.dumps(cross_summary, indent=2), encoding="utf-8")
    summary = {"passed": len(checks) - len(failed), "total": len(checks), "failed": failed,
               "gate": {"cases": totals["cases"], "passed": totals["passed"], "failed": totals["failed"]},
               "crosscheck": ct, "bench": bench, "rawSlot": {"valid": good, "truncated": truncated,
                                                             "notReady": not_ready_res}}
    (evidence / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print("\nresult: %d/%d checks passed" % (len(checks) - len(failed), len(checks)))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
