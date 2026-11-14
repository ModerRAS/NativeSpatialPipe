#!/usr/bin/env python3
"""Regression table for the structural-invariants hook validation method.

Runs nsp-hook-validate.exe against every audiodg variant in the read-only lab
corpus and checks the decision + located RVA. Stdlib only.

Usage:
  python tools/hook-validation/Test-Validation.py [--lab DIR] [--out FILE]
"""
import argparse, json, os, re, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, '..', '..'))
EXE = os.path.join(REPO, 'build', 'hook-validation', 'nsp-hook-validate.exe')
DEFAULT_LAB = os.path.abspath(os.path.join(REPO, '..', 'lab'))

REF = 'audiodg-build-26100.9444.exe'

# name, candidate, expected decision, expected located rva (0 = None), note
CASES = [
    ('reference-self',      REF,                             'allow', 0x31930, 'fingerprint: same build+layout'),
    ('A-mut-else',          'audiodg-A-mut-else.exe',        'allow', 0x31930, 'unrelated section mutated'),
    ('A-mut-fn',            'audiodg-A-mut-fn.exe',          'allow', 0x31930, 'LIMITATION: body byte at +0x60 not covered'),
    ('B-build-26100.9711',  'audiodg-build-26100.9711.exe',  'warn',  0x31930, 'same layout, recompiled build'),
    ('C-build-26100.9974',  'audiodg-build-26100.9974.exe',  'warn',  0x32c40, 'target moved, located structurally'),
    ('system-26100.9949',   'audiodg-system-26100.9949.exe', 'warn',  0x32c40, 'system servicing copy of C'),
    ('D-mut-fn',            'audiodg-D-mut-fn.exe',          'warn',  0x32c40, 'LIMITATION: body byte at +0x60 not covered'),
    ('D-mut-else',          'audiodg-D-mut-else.exe',        'warn',  0x32c40, 'unrelated section mutated'),
]

LIMITATIONS = {'A-mut-fn', 'D-mut-fn'}


def run_case(lab, candidate):
    cmd = [EXE, '--method', 'structural-invariants',
           '--reference', os.path.join(lab, REF),
           '--candidate', os.path.join(lab, candidate), '--json']
    t0 = time.perf_counter()
    p = subprocess.run(cmd, capture_output=True, text=True)
    wall = (time.perf_counter() - t0) * 1000.0
    if p.returncode != 0:
        return None, p.returncode, p.stderr.strip(), wall
    try:
        data = json.loads(p.stdout)
    except json.JSONDecodeError as exc:
        return None, p.returncode, 'invalid JSON: %s' % exc, wall
    return data, p.returncode, p.stderr.strip(), wall


def check_detail(data, name):
    for c in data.get('checks', []):
        if c.get('name') == name:
            return c
    return {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--lab', default=DEFAULT_LAB)
    ap.add_argument('--out', default=os.path.join(HERE, 'out', 'results.json'))
    args = ap.parse_args()

    if not os.path.isfile(EXE):
        sys.exit('tool not built: %s (run tools/hook-validation/Build.ps1)' % EXE)
    if not os.path.isdir(args.lab):
        sys.exit('lab corpus not found: %s (pass --lab DIR)' % args.lab)

    rows, failures, raw = [], 0, []
    print('structural-invariants regression: %d cases, reference=%s' % (len(CASES), REF))
    print('lab=%s' % args.lab)
    hdr = ('%-22s %-7s %-9s %-9s %-5s %-5s %-7s %s' %
           ('case', 'decision', 'rva', 'size', 'sig', 'refs', 'ms', 'verdict'))
    print(hdr)
    print('-' * len(hdr))
    for name, cand, want_dec, want_rva, note in CASES:
        data, code, err, wall = run_case(args.lab, cand)
        if data is None:
            print('%-22s ERROR exit=%s %s' % (name, code, err))
            failures += 1
            raw.append({'name': name, 'error': err, 'exitCode': code})
            continue
        located = data.get('located') or {}
        rva = located.get('rva')
        size = located.get('size')
        sig_detail = check_detail(data, 'field-access-signature').get('detail', '')
        m = re.search(r'signature functions=(\d+)', sig_detail)
        sig = int(m.group(1)) if m else 0
        tgt = check_detail(data, 'target-located').get('detail', '')
        m = re.search(r'refs=(\d+)', tgt)
        refs = int(m.group(1)) if m else 0
        dec = data.get('decision')
        ok = dec == want_dec and rva == want_rva
        if not ok:
            failures += 1
        verdict = 'PASS' if ok else 'FAIL'
        if name in LIMITATIONS and ok:
            verdict = 'PASS*'
        print('%-22s %-7s 0x%-8x %-9s %-5d %-5d %-7.2f %s' %
              (name, dec, rva or 0, size if size is not None else '-', sig, refs,
               data.get('timingMs', wall), verdict))
        raw.append({
            'name': name, 'candidate': cand, 'expectedDecision': want_dec,
            'expectedRva': want_rva, 'decision': dec, 'located': located,
            'signatureFunctions': sig, 'targetRefs': refs,
            'timingMs': data.get('timingMs'), 'passed': ok, 'note': note,
            'checks': data.get('checks'), 'build': data.get('build'),
        })

    print('-' * len(hdr))
    print('passed=%d/%d  (* = expected limitation of this method: 1-byte body mutation not covered)'
          % (len(CASES) - failures, len(CASES)))

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    payload = {
        'method': 'structural-invariants',
        'tool': EXE,
        'lab': args.lab,
        'reference': REF,
        'cases': raw,
        'passed': len(CASES) - failures,
        'total': len(CASES),
        'limitations': sorted(LIMITATIONS),
        'generatedAt': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
    }
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    print('results: %s' % args.out)
    return 0 if failures == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
