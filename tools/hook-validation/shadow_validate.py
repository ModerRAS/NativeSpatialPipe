#!/usr/bin/env python3
"""Cross-check the NSP1 behavioral-shadow contract: C DLL vs pure Python.

Reads the JSONL produced by gen_fixtures.py, validates every block twice
(ctypes call into nsp-shadow-gate.dll and an independent pure-Python
implementation of the same rules) and fails when the two disagree or when a
fixture expectation is not met.

Usage:
  python shadow_validate.py --fixtures out/fixtures.jsonl
  python shadow_validate.py --fixtures out/fixtures.jsonl --table --report out/crosscheck.json
"""
import argparse
import ctypes as C
import json
import struct
import sys
from pathlib import Path

MAX_OBJECTS = 160
MAX_FRAMES = 4096
PRODUCTION_FRAMES = 480
FLAG_MASK = 0x0000000D  # bit0 | bit2 | bit3

# Error codes must match shadow_gate.c.
NSP_OK = 0
NSP_E_ARGS = 1
NSP_E_COUNT = 2
NSP_E_FRAMES = 3
NSP_E_STRIDE = 4
NSP_E_STRIDE_FRAMES = 5
NSP_E_PAYLOAD = 6
NSP_E_PROP_FRAMES = 7
NSP_E_TYPE = 8
NSP_E_XYZ = 9
NSP_E_GAIN = 10
NSP_E_PCM = 11
NSP_E_DUP_BED = 12
NSP_E_SEQ = 13
NSP_E_QPC = 14
NSP_E_SLOT = 15
NSP_E_DESCRIPTOR = 16
NSP_E_GAIN_RANGE = 17
NSP_E_FRAMES_PROD = 18
NSP_E_WARN = 19

CODE_NAMES = {0: "OK", 1: "E_ARGS", 2: "E_COUNT", 3: "E_FRAMES", 4: "E_STRIDE",
              5: "E_STRIDE_FRAMES", 6: "E_PAYLOAD", 7: "E_PROP_FRAMES", 8: "E_TYPE",
              9: "E_XYZ", 10: "E_GAIN", 11: "E_PCM", 12: "E_DUP_BED", 13: "E_SEQ",
              14: "E_QPC", 15: "E_SLOT", 16: "E_DESCRIPTOR", 17: "E_GAIN_RANGE",
              18: "E_FRAMES_PROD", 19: "E_WARN"}


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
                ("detail", C.c_char * 512),
                ("warnings", (C.c_char * 48) * 8)]


def f32_finite(bits):
    return ((bits >> 23) & 0xFF) != 0xFF


def _finite_from_hex(h):
    raw = bytes.fromhex(h)
    return all(f32_finite(b) for b in struct.unpack("<%dI" % (len(raw) // 4), raw))


def validate_record(rec, cfg):
    """Independent pure-Python implementation of the same contract."""
    warnings = []
    checks = 0

    def fail(code, detail):
        return {"ok": 0, "code": code, "detail": detail, "warnings": warnings,
                "checks": checks, "count": rec.get("count"), "frames": rec.get("frames"),
                "stride": rec.get("stride")}

    props = b"".join(bytes.fromhex(h) for h in rec.get("properties", []))
    pcm = b"".join(bytes.fromhex(h) for h in rec.get("pcm", []))
    count = int(rec.get("count", 0))
    frames = int(rec.get("frames", 0))
    stride = int(rec.get("stride", 0))

    checks += 1
    if count < 1 or count > MAX_OBJECTS:
        return fail(NSP_E_COUNT, "count %d outside [1,160]" % count)
    checks += 1
    if frames < 1 or frames > MAX_FRAMES:
        return fail(NSP_E_FRAMES, "frames %d outside [1,4096]" % frames)
    checks += 1
    if stride < 4 or stride > 16384 or stride % 4 != 0:
        return fail(NSP_E_STRIDE, "stride %d outside [4,16384] or not 4-byte aligned" % stride)
    checks += 1
    if frames * 4 > stride:
        return fail(NSP_E_STRIDE_FRAMES, "frames*4 (%d) exceeds stride %d" % (frames * 4, stride))
    checks += 1
    if len(props) != count * 32:
        return fail(NSP_E_PAYLOAD, "property payload %d != count(%d)*32" % (len(props), count))
    checks += 1
    if len(pcm) != count * frames * 4:
        return fail(NSP_E_PAYLOAD, "pcm payload %d != count(%d)*frames(%d)*4" % (len(pcm), count, frames))

    seen_bed = [False] * 12
    for i in range(count):
        ident, pf, typ, flags, x, y, z, gain = struct.unpack_from("<IIIIffff", props, i * 32)
        checks += 1
        if pf != frames:
            return fail(NSP_E_PROP_FRAMES, "property[%d].frames %d != block frames %d" % (i, pf, frames))
        checks += 1
        is_bed = typ != 1 and typ >= 2 and typ <= 4096 and (typ & (typ - 1)) == 0
        if typ != 1 and not is_bed:
            return fail(NSP_E_TYPE, "property[%d].type 0x%x invalid" % (i, typ))
        checks += 1
        if flags & ~FLAG_MASK:
            warnings.append("flags[%d]=0x%x has reserved bits" % (i, flags & ~FLAG_MASK))
        for k, value in enumerate((x, y, z)):
            checks += 1
            if not f32_finite(struct.unpack("<I", struct.pack("<f", value))[0]):
                return fail(NSP_E_XYZ, "property[%d].xyz[%d] is not finite" % (i, k))
        checks += 1
        if not f32_finite(struct.unpack("<I", struct.pack("<f", gain))[0]):
            return fail(NSP_E_GAIN, "property[%d].gain is not finite" % i)
        checks += 1
        if gain < 0.0 or gain > 8.0:
            if cfg["strict_gain"]:
                return fail(NSP_E_GAIN_RANGE, "property[%d].gain %.6g outside strict [0,8]" % (i, gain))
            warnings.append("gain[%d]=%.6g outside [0,8]" % (i, gain))
        if is_bed:
            index = typ.bit_length() - 2  # 2 -> 0 ... 4096 -> 11
            checks += 1
            if 0 <= index < 12 and seen_bed[index]:
                return fail(NSP_E_DUP_BED, "duplicate bed type 0x%x at property[%d]" % (typ, i))
            if 0 <= index < 12:
                seen_bed[index] = True

    for off in range(0, len(pcm), 4):
        checks += 1
        if not f32_finite(struct.unpack_from("<I", pcm, off)[0]):
            return fail(NSP_E_PCM, "pcm f32 at byte %d is not finite" % off)

    prev_seq = rec.get("prevSequence")
    if prev_seq is not None:
        checks += 1
        if int(rec["sequence"]) != int(prev_seq) + 1:
            return fail(NSP_E_SEQ, "sequence %d is not prev(%d)+1" % (rec["sequence"], prev_seq))
    prev_qpc = rec.get("prevQpcNs")
    if prev_qpc is not None:
        checks += 1
        if int(rec["captureQpcNs"]) < int(prev_qpc):
            return fail(NSP_E_QPC, "captureQpcNs %d moved backwards from %d" % (rec["captureQpcNs"], prev_qpc))
    checks += 1
    if frames != PRODUCTION_FRAMES:
        if cfg["strict_frames"]:
            return fail(NSP_E_FRAMES_PROD, "frames %d != production 480 (strict)" % frames)
        warnings.append("frames=%d (production expects 480)" % frames)
    if cfg["warnings_as_error"] and warnings:
        return fail(NSP_E_WARN, "%d warning(s) promoted to error" % len(warnings))

    return {"ok": 1, "code": NSP_OK,
            "detail": "OK count=%d frames=%d stride=%d checks=%d warnings=%d" % (count, frames, stride, checks, len(warnings)),
            "warnings": warnings, "checks": checks,
            "count": count, "frames": frames, "stride": stride}


def load_dll(path):
    if not path:
        return None
    lib = C.CDLL(str(path))
    f = lib.nsp_shadow_parts_check
    f.argtypes = [C.POINTER(Parts), C.POINTER(Result)]
    f.restype = C.c_int
    if hasattr(lib, "nsp_shadow_set_config"):
        lib.nsp_shadow_set_config.argtypes = [C.c_int, C.c_int, C.c_int]
        lib.nsp_shadow_set_config.restype = None
    return lib


def call_dll(lib, rec, cfg):
    props = b"".join(bytes.fromhex(h) for h in rec.get("properties", []))
    pcm = b"".join(bytes.fromhex(h) for h in rec.get("pcm", []))
    # Non-null buffers even for empty payloads: the C ABI rejects null pointers.
    pb = (C.c_ubyte * max(1, len(props))).from_buffer_copy(props or b"\0")
    pcmb = (C.c_ubyte * max(1, len(pcm))).from_buffer_copy(pcm or b"\0")
    parts = Parts()
    parts.count = int(rec.get("count", 0))
    parts.frames = int(rec.get("frames", 0))
    parts.stride = int(rec.get("stride", 0))
    parts.sequence = int(rec.get("sequence", 0))
    parts.capture_qpc_ns = int(rec.get("captureQpcNs", 0))
    prev_seq = rec.get("prevSequence")
    prev_qpc = rec.get("prevQpcNs")
    parts.prev_sequence = (1 << 64) - 1 if prev_seq is None else int(prev_seq)
    parts.prev_qpc_ns = (1 << 64) - 1 if prev_qpc is None else int(prev_qpc)
    parts.properties = C.cast(pb, C.POINTER(C.c_ubyte))
    parts.properties_len = len(props)
    parts.pcm = C.cast(pcmb, C.POINTER(C.c_ubyte))
    parts.pcm_len = len(pcm)
    result = Result()
    if hasattr(lib, "nsp_shadow_set_config"):
        lib.nsp_shadow_set_config(int(cfg["strict_frames"]), int(cfg["strict_gain"]), int(cfg["warnings_as_error"]))
    rc = lib.nsp_shadow_parts_check(C.byref(parts), C.byref(result))
    return {"ok": int(result.ok), "code": int(result.code), "rc": int(rc),
            "detail": result.detail.decode("utf-8", "replace"),
            "warning_count": int(result.warning_count),
            "checks": int(result.checks),
            "count": int(result.count), "frames": int(result.frames), "stride": int(result.stride),
            "warnings": [bytes(result.warnings[i]).decode("utf-8", "replace").rstrip("\x00")
                          for i in range(int(result.warning_count))]}


def expect_ok(expect):
    return expect == "ok"


def expect_code(expect):
    if expect.startswith("reject:"):
        return int(expect.split(":", 1)[1])
    return None


def run(fixtures, dll_path, cfg, table=False, report=None):
    lines = [json.loads(line) for line in Path(fixtures).read_text(encoding="utf-8").splitlines() if line.strip()]
    lib = load_dll(dll_path)
    cases = []
    mismatches = []
    passed = 0
    for rec in lines:
        py = validate_record(rec, cfg)
        dll = call_dll(lib, rec, cfg) if lib else None
        exp_ok = expect_ok(rec.get("expect", ""))
        exp_code = expect_code(rec.get("expect", ""))
        expected_match = (bool(py["ok"]) == exp_ok) and (exp_code is None or py["code"] == exp_code)
        dll_match = True
        if dll is not None:
            dll_match = (dll["ok"] == py["ok"] and dll["code"] == py["code"]
                         and dll["warning_count"] == len(py["warnings"])
                         and dll["count"] == py["count"] and dll["frames"] == py["frames"]
                         and dll["stride"] == py["stride"])
            if not dll_match:
                mismatches.append({"name": rec.get("name"), "python": py, "dll": dll})
        ok = expected_match and dll_match
        if ok:
            passed += 1
        cases.append({"name": rec.get("name"), "expect": rec.get("expect"),
                      "python": {"ok": py["ok"], "code": py["code"], "codeName": CODE_NAMES.get(py["code"], "?"),
                                 "detail": py["detail"], "warnings": py["warnings"]},
                      "dll": None if dll is None else {"ok": dll["ok"], "code": dll["code"],
                                                       "codeName": CODE_NAMES.get(dll["code"], "?"),
                                                       "detail": dll["detail"], "warnings": dll["warnings"],
                                                       "checks": dll["checks"]},
                      "expectedMatch": expected_match, "dllMatch": dll_match, "pass": ok})
    summary = {"tool": "shadow_validate.py", "fixtures": str(fixtures),
               "dll": None if dll_path is None else str(dll_path),
               "config": cfg, "totals": {"cases": len(cases), "passed": passed,
                                         "failed": len(cases) - passed, "dllMismatches": len(mismatches)},
               "mismatches": mismatches, "cases": cases}
    if report:
        rp = Path(report)
        rp.parent.mkdir(parents=True, exist_ok=True)
        rp.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    if table:
        print("%-32s %-12s %-6s %-6s %-12s %-6s" % ("case", "expect", "py", "dll", "code", "pass"))
        print("-" * 82)
        for c in cases:
            dll_code = c["dll"]["codeName"] if c["dll"] else "-"
            print("%-32s %-12s %-6s %-6s %-12s %-6s" % (
                c["name"], c["expect"], "ok" if c["python"]["ok"] else "fail",
                ("-" if c["dll"] is None else ("ok" if c["dll"]["ok"] else "fail")),
                c["python"]["codeName"], "PASS" if c["pass"] else "FAIL"))
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures", required=True)
    ap.add_argument("--dll", default=str(Path(__file__).resolve().parents[2] / "build/hook-validation/nsp-shadow-gate.dll"))
    ap.add_argument("--no-dll", action="store_true")
    ap.add_argument("--table", action="store_true")
    ap.add_argument("--strict-frames", action="store_true")
    ap.add_argument("--strict-gain", action="store_true")
    ap.add_argument("--warnings-as-errors", action="store_true")
    ap.add_argument("--report", default=None)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    cfg = {"strict_frames": int(args.strict_frames), "strict_gain": int(args.strict_gain),
           "warnings_as_error": int(args.warnings_as_errors)}
    dll_path = None if args.no_dll else args.dll
    if dll_path and not Path(dll_path).is_file():
        print(json.dumps({"tool": "shadow_validate.py", "error": "dll not found: " + dll_path}))
        return 1
    summary = run(args.fixtures, dll_path, cfg, table=args.table, report=args.report)
    if not args.table:
        core = {k: summary[k] for k in ("tool", "fixtures", "dll", "config", "totals", "mismatches")}
        print(json.dumps(core, separators=(",", ":")))
    return 0 if summary["totals"]["failed"] == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
