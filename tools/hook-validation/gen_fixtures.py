#!/usr/bin/env python3
"""Generate NSP1 behavioral-shadow fixtures as JSONL.

Each line is one capture block:
  name, expect ("ok" | "reject" | "reject:<code>"), sequence, captureQpcNs,
  prevSequence, prevQpcNs (optional explicit history), count, frames, stride,
  properties: [hex(32B), ...], pcm: [hex(frames*4B), ...]

Run: python gen_fixtures.py --out <path.jsonl>
"""
import argparse
import json
import struct
from pathlib import Path

MAX_OBJECTS = 160
MAX_FRAMES = 4096
PRODUCTION_FRAMES = 480
PRODUCTION_STRIDE = PRODUCTION_FRAMES * 4


def f32(value):
    return struct.pack("<f", float(value))


def pcm_hex(frames, values=None):
    if values is None:
        values = [0.0] * frames
    return struct.pack("<%df" % frames, *values).hex()


def property_hex(ident, frames, type_code, flags=0, xyz=(0.0, 0.0, 0.0), gain=1.0):
    body = struct.pack("<IIII", ident & 0xFFFFFFFF, frames, type_code & 0xFFFFFFFF, flags)
    body += struct.pack("<fff", *xyz) + f32(gain)
    assert len(body) == 32, len(body)
    return body.hex()


def make_case(name, expect, sequence, qpc_ns, props, pcm, *, count=None,
              frames=None, stride=None, prev_seq=None, prev_qpc=None):
    if count is None:
        count = len(props)
    if frames is None:
        frames = struct.unpack("<I", bytes.fromhex(props[0])[4:8])[0] if props else PRODUCTION_FRAMES
    if stride is None:
        stride = frames * 4
    record = {
        "name": name,
        "expect": expect,
        "sequence": sequence,
        "captureQpcNs": qpc_ns,
        "count": count,
        "frames": frames,
        "stride": stride,
        "properties": props,
        "pcm": pcm,
    }
    if prev_seq is not None:
        record["prevSequence"] = prev_seq
    if prev_qpc is not None:
        record["prevQpcNs"] = prev_qpc
    return record


def dynamic_object(ident, frames, flags=4, xyz=(0.1, 0.2, -0.3), gain=1.0):
    return property_hex(ident, frames, 1, flags, xyz, gain)


def bed_objects(frames, types):
    return [property_hex(i, frames, t, 0, (0.0, 0.0, 0.0), 1.0) for i, t in enumerate(types)]


def generate():
    cases = []
    seq = 1
    qpc = 1_000_000_000

    # ---- normal blocks (expect ok) ----
    frames = PRODUCTION_FRAMES
    props = [dynamic_object(i, frames) for i in range(MAX_OBJECTS)]
    pcm = [pcm_hex(frames)] * MAX_OBJECTS
    cases.append(make_case("normal_160_objects", "ok", seq, qpc, props, pcm,
                           prev_seq=seq - 1, prev_qpc=qpc - 10_000_000))
    seq += 1; qpc += 10_000_000

    props = bed_objects(frames, [2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096])
    cases.append(make_case("normal_pure_bed_12ch", "ok", seq, qpc, props, [pcm_hex(frames)] * 12,
                           prev_seq=seq - 1, prev_qpc=qpc - 10_000_000))
    seq += 1; qpc += 10_000_000

    props = [dynamic_object(0, frames, flags=1, xyz=(0.0, 0.0, 0.0), gain=0.0)]
    cases.append(make_case("normal_single_object", "ok", seq, qpc, props, [pcm_hex(frames)],
                           prev_seq=seq - 1, prev_qpc=qpc - 10_000_000))
    seq += 1; qpc += 10_000_000

    props = [dynamic_object(0, frames), dynamic_object(1, frames)] + bed_objects(frames, [2, 4, 8, 16])
    cases.append(make_case("normal_mixed_beds_objects", "ok", seq, qpc, props, [pcm_hex(frames)] * 6,
                           prev_seq=seq - 1, prev_qpc=qpc - 10_000_000))
    seq += 1; qpc += 10_000_000

    props = [dynamic_object(i, frames, gain=8.5) for i in range(2)]
    cases.append(make_case("normal_gain_out_of_range_warn", "ok", seq, qpc, props, [pcm_hex(frames)] * 2,
                           prev_seq=seq - 1, prev_qpc=qpc - 10_000_000))
    seq += 1; qpc += 10_000_000

    props = [dynamic_object(0, frames, flags=2)]
    cases.append(make_case("normal_unknown_flag_warn", "ok", seq, qpc, props, [pcm_hex(frames)],
                           prev_seq=seq - 1, prev_qpc=qpc - 10_000_000))
    seq += 1; qpc += 10_000_000

    short = 16
    props = [dynamic_object(i, short) for i in range(4)]
    cases.append(make_case("normal_short_16f_warn", "ok", seq, qpc, props, [pcm_hex(short)] * 4,
                           prev_seq=seq - 1, prev_qpc=qpc - 10_000_000))
    seq += 1; qpc += 10_000_000

    # ---- abnormal blocks (expect reject:code) ----
    cases.append(make_case("bad_count_zero", "reject:2", seq, qpc, [], [], count=0, frames=frames,
                           stride=PRODUCTION_STRIDE, prev_seq=seq - 1, prev_qpc=qpc - 10_000_000))
    seq += 1; qpc += 10_000_000

    props = [dynamic_object(i, short) for i in range(161)]
    cases.append(make_case("bad_count_161", "reject:2", seq, qpc, props, [pcm_hex(short)] * 161,
                           count=161, frames=short, stride=short * 4,
                           prev_seq=seq - 1, prev_qpc=qpc - 10_000_000))
    seq += 1; qpc += 10_000_000

    props = [property_hex(0, 240, 1, 4, (0.0, 0.0, 0.0), 1.0)]
    cases.append(make_case("bad_property_frames_mismatch", "reject:7", seq, qpc, props,
                           [pcm_hex(frames)], frames=frames,
                           prev_seq=seq - 1, prev_qpc=qpc - 10_000_000))
    seq += 1; qpc += 10_000_000

    props = [dynamic_object(0, short)]
    cases.append(make_case("bad_stride_misaligned", "reject:4", seq, qpc, props, [pcm_hex(short)],
                           stride=short * 4 + 2, prev_seq=seq - 1, prev_qpc=qpc - 10_000_000))
    seq += 1; qpc += 10_000_000

    props = [dynamic_object(0, short, xyz=(float("nan"), 0.0, 0.0))]
    cases.append(make_case("bad_xyz_nan", "reject:9", seq, qpc, props, [pcm_hex(short)],
                           prev_seq=seq - 1, prev_qpc=qpc - 10_000_000))
    seq += 1; qpc += 10_000_000

    bad_pcm = [pcm_hex(short, [0.0] * 3 + [float("nan")] + [0.0] * (short - 4))]
    cases.append(make_case("bad_pcm_nan", "reject:11", seq, qpc, [dynamic_object(0, short)], bad_pcm,
                           prev_seq=seq - 1, prev_qpc=qpc - 10_000_000))
    seq += 1; qpc += 10_000_000

    cases.append(make_case("bad_sequence_jump", "reject:13", 7, qpc,
                           [dynamic_object(0, short)], [pcm_hex(short)],
                           prev_seq=5, prev_qpc=qpc - 10_000_000))
    qpc += 10_000_000

    cases.append(make_case("bad_qpc_backwards", "reject:14", seq + 1, 1_000_000,
                           [dynamic_object(0, short)], [pcm_hex(short)],
                           prev_seq=seq, prev_qpc=2_000_000))
    seq += 2; qpc += 10_000_000

    props = [property_hex(0, short, 2), property_hex(1, short, 2)]
    cases.append(make_case("bad_duplicate_bed", "reject:12", seq, qpc, props, [pcm_hex(short)] * 2,
                           prev_seq=seq - 1, prev_qpc=qpc - 10_000_000))
    seq += 1; qpc += 10_000_000

    props = [dynamic_object(0, short)]
    cases.append(make_case("bad_payload_truncated", "reject:6", seq, qpc, props, [],
                           prev_seq=seq - 1, prev_qpc=qpc - 10_000_000))
    seq += 1; qpc += 10_000_000

    props = [property_hex(0, short, 0x80000000)]
    cases.append(make_case("bad_illegal_type", "reject:8", seq, qpc, props, [pcm_hex(short)],
                           prev_seq=seq - 1, prev_qpc=qpc - 10_000_000))
    seq += 1; qpc += 10_000_000

    props = [dynamic_object(0, short)]
    cases.append(make_case("bad_stride_out_of_range", "reject:4", seq, qpc, props, [pcm_hex(short)],
                           stride=16385, prev_seq=seq - 1, prev_qpc=qpc - 10_000_000))
    return cases


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(Path(__file__).resolve().parents[2] / "build/hook-validation/out/fixtures.jsonl"))
    args = ap.parse_args()
    cases = generate()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for case in cases:
            fh.write(json.dumps(case, separators=(",", ":")) + "\n")
    normal = sum(1 for c in cases if c["expect"] == "ok")
    print(json.dumps({"fixtures": str(out), "cases": len(cases), "normal": normal,
                      "abnormal": len(cases) - normal, "bytes": out.stat().st_size}))


if __name__ == "__main__":
    main()
