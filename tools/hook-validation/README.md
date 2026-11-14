# hook-validation (branch 1: unwind-fn-hash)

Function-level hook target validation for the pinned audiodg NSP hook. Locates the
target through the PE .pdata unwind table and compares a relocation-normalized
SHA-256 of the whole function body against the pinned reference build.

## Files

| File | Purpose |
|---|---|
| src/pe.h, src/pe.c | On-disk PE32+ reader: DOS/COFF/Optional headers, sections, ImageBase, TimeDateStamp/SizeOfImage/CheckSum, .pdata (exception dir), .reloc (base relocation dir) |
| src/fn_hash.h, src/fn_hash.c | .pdata lookup (Begin == RVA), relocation-normalized SHA-256 via BCrypt (bcrypt.lib), .pdata-wide exact-hash scan, in-memory SHA-256 helper |
| src/main.c | nsp-hook-validate.exe CLI (method unwind-fn-hash, single JSON object on stdout) |
| Build.ps1 | gcc build -> build/hook-validation/nsp-hook-validate.exe |
| Test-Validation.py | 8 lab cases + 2 supplementary cases, stdout table, out/results.json |
| INTEGRATION.md | Minimal changes for tools/endpoint-probe/Native-Hook.c and Native-Hook-Control.c |
| out/results.json | Last measured results (committed as evidence) |

## Build

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/hook-validation/Build.ps1
~~~

Requires gcc (MinGW-w64) on PATH. Links bcrypt, version, shell32.

## Run

~~~powershell
build/hook-validation/nsp-hook-validate.exe --method unwind-fn-hash \
  --reference <pinned audiodg.exe> --candidate <candidate audiodg.exe> --json
~~~

Optional: --ref-rva HEX (default 0x31930), --max-function-size N (default 8192).

## Test

~~~powershell
python tools/hook-validation/Test-Validation.py
~~~

Expects the read-only lab corpus as a sibling of this worktree
(<branch-worktrees>/lab/audiodg-*.exe). Prints a table and writes out/results.json.

## Method summary

1. Parse both PEs from disk; compare TimeDateStamp+SizeOfImage+CheckSum.
2. Reference: require a .pdata RUNTIME_FUNCTION with Begin == 0x31930 and the 16-byte
   NSP prologue (Native-Hook.c:71); hash [Begin,End) with .reloc targets zeroed.
3. Same build identity: lock the same RVA, require prologue + normalized hash match;
   a hash mismatch is denied (target changed).
4. Different build identity: scan every candidate .pdata function (<= 8 KiB) for an
   exact normalized-hash match -> allow with the located RVA. No match:
   same-RVA prologue match but a different body hash -> deny; otherwise unknown.
