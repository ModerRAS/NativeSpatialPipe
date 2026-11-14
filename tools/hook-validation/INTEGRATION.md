# Cross-build fingerprint validation for the NSP audiodg hook

This directory contains the `crossbuild-fingerprint` method: instead of trusting a whole-file
SHA-256 (which changes on every Windows servicing update), it locates the hooked function inside
whatever `audiodg.exe` is on the machine and validates *that function* against a small per-build
fingerprint database.

## 1. Wiring it in front of `Native-Hook.c`

Today the hook target is hardcoded:

* `tools/endpoint-probe/Native-Hook.c:70` — `(char*)image + 0x31930`
* `tools/endpoint-probe/Native-Hook-Control.c:72-74` — 16-byte prologue check at `image_base + 0x31930`

Replace the constant with a fingerprint lookup at hook-install time (before `MH_CreateHook`,
`Native-Hook.c:83`):

```c
/* Native-Hook.c, inside nsp_hook_start(), replacing line 70. */
uint32_t rva = 0, size = 0;
NspFingerprintVerdict verdict = nsp_fingerprint_locate(image_path, &rva, &size);
if (verdict != NSP_FP_ALLOW && verdict != NSP_FP_WARN_CONFIRMED) { result = fail(c, 6); goto done; }
void *address = (char *)image + rva;
```

The library entry point is what the CLI uses internally:

* `nsp_fingerprint_locate()` = `pe_load` + `locate()` from `tools/hook-validation/main.c`
  (returns the RVA/size/confidence and the decision enum);
* keep the existing 16-byte prologue assertion as a cheap second gate — it still holds for every
  build we tested (`A-self`, `B-9711`, `C-9974`, `D-9949` all start with
  `48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18 57`), but treat it as an *additional* check,
  not the identity criterion;
* the `target_created` / resident-build checks in `Native-Hook-Control.c:45-49, 91-97`
  (`TimeDateStamp` + `SizeOfImage` + `CheckSum` match) remain the right guard for the
  *remote* module: they answer "is the resident image the same file I validated?", not
  "is this function the one I expect?".

A minimal integration therefore has two layers:

| layer | question | mechanism |
|---|---|---|
| in-process (new) | which RVA is the object-submit function in *this* build? | fingerprint locate + decision |
| remote controller (existing) | is the loaded module the same binary I inspected? | `TimeDateStamp/SizeOfImage/CheckSum` comparison |

## 2. Generating and shipping `builds.json`

The database is plain JSON, one entry per shipped `audiodg.exe` build:

```json
{
  "schemaVersion": 1,
  "function": "audiodg-object-submit",
  "referenceBuildId": "10.0.26100.9444",
  "builds": [
    {"buildId": "10.0.26100.9444", "rva": 203056, "size": 474,
     "sha256": "<reloc-normalised function hash>",
     "aobs": [{"offset": 7, "pattern": "6c 24 10 48 89 ..."}, ...]}
  ]
}
```

* `buildId` = `VS_FIXEDFILEINFO` file version (`10.0.26100.9444`);
* `sha256` = SHA-256 over the `.pdata` function body with `.reloc` bytes zeroed, so a moved
  relocation does not change the identity;
* `aobs` = 3–5 windows of 32 bytes selected from the function body. Bytes belonging to
  `rel32` (`E8/E9/0F 8x`) and RIP-relative `disp32` operands are written as `??` because those
  are exactly the bytes that move when the rest of the image is rebuilt.

Generation workflow (one new build = one command + paste):

```powershell
# locate the function in the new build, print a ready-to-paste DB entry
build\hook-validation\nsp-hook-validate.exe --method crossbuild-fingerprint \
  --reference C:\Windows\System32\audiodg.exe --candidate .\new-audiodg.exe --emit-entry
```

`--emit-entry` re-runs the locator (so the RVA may differ from the reference build), derives the
AOB set from the *candidate*, prints the normalized hash and emits one JSON object to paste into
`builds["builds"]`. The `10.0.26100.9711` entry in this repo was produced exactly this way; it
shows the growth model: same RVA, function body drifted by 4 bytes, hash differs, still `allow`
once the entry exists.

Distribution: `builds.json` is small (a few hundred bytes per build) and belongs next to the
binary; it is data, not code, so it can be updated without re-signing the hook DLL. Ship a
"last known good" DB and refresh it via the same FSA/Web control plane that already distributes
configuration.

## 3. Unknown-build policy

The validator never denies *just* because the whole-file hash is unknown. Recommended policy:

| situation | decision | meaning for the hook |
|---|---|---|
| buildId in DB + normalized hash matches | `allow` | known build, function intact — install hook |
| buildId in DB + normalized hash differs | `deny` (+ `targetChanged`) | same build, function patched — refuse |
| unknown build, located, similarity ≥ 0.98, no anomaly | `warn` | new Windows build, function looks intact — ask the user once, then add to DB |
| unknown build, located, 0.85 ≤ similarity < 0.98, no anomaly | `warn` | drift, needs confirmation |
| unknown build + modification evidence (AOB miss or isolated 1-byte diff) | `deny` (+ `targetChanged`) | likely patched function |
| not located / similarity < 0.5 | `deny` | cannot prove the target, fail closed |

Default for unattended startup is **deny on unknown** (fail closed) with an override that records
the decision in the telemetry report; the `warn` state exists for an interactive "new build
detected, confirm and add to DB" prompt. Do not silently hook on `warn`.

## 4. Fallback when the AOB set fails

* AOBs are a fast pre-filter, not the final answer. Even when 0/5 AOB windows match exactly the
  locator still scores every `.pdata` function by *tolerant* AOB hits (≤2 literal mismatches) and
  by aligned similarity, so a function with one changed window still wins if it is the true
  target.
* If the function grew/shrank, similarity is computed on `min(refSize, candSize)` and the
  candidate range always comes from `.pdata` (so we never read across a function boundary);
  a size delta > 25 % drops confidence below the ambiguity gate and the tool reports
  `located: null` + `deny`.
* If the prologue assertion in `Native-Hook.c` fails while the fingerprint validator says
  `allow`, trust the *validator* only after the user re-confirms: prologue bytes are a proxy,
  the normalized hash is the identity.
* Last resort is unchanged behaviour: refuse to hook, report `hookBackend: none` in the
  status JSON, and keep the pipeline running in non-spatial mode.
