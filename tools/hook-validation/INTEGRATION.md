# Structural-invariants hook validation — integration notes

Locate the NSP hook target and its object vtables in a (possibly recompiled) audiodg.exe from structure, not from the pinned RVA. Tool lives in tools/hook-validation/ (pe.c + structural-invariants.c + main.c), built by Build.ps1 with gcc to build/hook-validation/nsp-hook-validate.exe; regression is Test-Validation.py.

## 1. Replace the hard-coded vtable RVAs in nsp_hook_start

tools/endpoint-probe/Native-Hook.c:70-80 currently does:

```c
void *address=c->fixture?(void*)GetProcAddress(image,"boundary"):(char*)image+0x31930;   // :70 target RVA
...
ctx=create((char*)image+0x9f4f8,(char*)image+0xa2d58,publish,link,c->budget);            // :80 hard-coded vtables
```

Integration: keep the prologue fallback, but derive vtables and target at runtime from structure (HMODULE image = loaded base):

```c
/* new helper in tools/endpoint-probe/ (same algorithm as structural-invariants.c) */
typedef struct { uintptr_t vt1, vt2, target; uint32_t target_slot, signature_functions; } NspStructure;
int nsp_structural_locate(HMODULE image, NspStructure *out);
```

Implementation rules (all verified on the pinned 26100.9444 build):
- walk .pdata for function candidates;
- scan .rdata/.data qwords for ImageBase+candidate (vtable/code-pointer refs);
- structural-signature function = referenced >=2 times and containing >=3 of 0x510/0x5d0/0x5d4/0x5d8/0xC/0x14/0x28/0x38 as genuine disp32 operands (byte before disp32 has ModRM mod=10);
- on the reference build exactly four such functions exist and they are vtable slots 3..6 (vt1+0x18..0x30, vt2+0x18..0x30);
- infer vt1 = min(cluster slots) - 0x18 (also equals start of contiguous code-pointer run + 0x350), same formula for vt2;
- the hook target is the function referenced at vt1+0x100 (slot 32) with >=2 refs (second one in the vt2 family).

```c
if(!c->fixture){
  NspStructure s;
  if(!nsp_structural_locate(image,&s)){result=fail(c,6);goto done;}
  address=(void*)s.target;                 /* replaces (char*)image+0x31930 */
  ctx=create((void*)s.vt1,(void*)s.vt2,publish,link,c->budget);  /* :80 */
} else { ...existing fixture path... }
```

Fallback: when structure is not found, keep the pinned constants only for the exact 9444 build (timestamp/sizeOfImage/checksum check, see Native-Hook-Control.c:97); otherwise fail closed (fail(c,6)).

## 2. Add slot/field signature checks to Native-Capture.c:31-32

tools/endpoint-probe/Native-Capture.c:31-32:

```c
static void capture_inner(Capture *c,uint8_t *b,uint64_t start){
 uintptr_t vt=*(uintptr_t*)b;if(vt!=c->vt1&&vt!=c->vt2)return;
```

The field reads at Native-Capture.c:33-39 already touch the exact block offsets (0x5d4/0x5d0/0x5d8/0x510) and descriptor offsets (desc+0xC/0x14/0x28/0x38) but only reject bad values. Two additions make the vtable check a structural signature:

1. Slot signature (after vt match, before line 33):
```c
 /* The object vtable must carry the submit method at slot 32 and that slot
    must point into the audiodg image. c->image/c->image_size are captured in
    nsp_capture_create from the structural locator. */
 uintptr_t submit=*(uintptr_t*)(vt+0x100);
 if(submit<(uintptr_t)c->image||submit>=(uintptr_t)c->image+c->image_size){c->signature_misses++;c->invalid++;return;}
```
2. Field-signature accounting: increment one counter per expected displacement when the block/descriptor probe succeeds (0x5d4 count, 0x5d0 index, 0x5d8 flag, 0x510 desc pointer, desc+0xC width, desc+0x38 pcm); expose "structuralSignature":true in nsp_capture_report once all six probes were observed at least once. Treat the first N blocks as validation samples, not as a per-block hard gate, to avoid rejecting legitimate variation.

This turns the old vt1/vt2 equality check into "object-vtable + slot + field layout" evidence, matching what the offline validator verifies.

## 3. Build / CI wiring

```powershell
# build the standalone validator (gcc only)
powershell -NoProfile -ExecutionPolicy Bypass -File tools/hook-validation/Build.ps1
# run the 8-case regression against the lab corpus
python tools/hook-validation/Test-Validation.py --lab <lab-dir>
```

tools/Build-Core.ps1 / CI can call Build.ps1 and assert Test-Validation.py exits 0; the regression writes out/results.json (decision, located.rva, timingMs per case).

## 4. Known integration caveat

The locator is calibrated on the pinned 9444 build (REF_VT1_RVA / REF_TARGET_RVA in structural-invariants.c) only for the sanity check "the reference build still matches the pinned layout". Candidate builds are located from structure alone. If a future build reorders the vtable itself (cluster slots not 3..6), the base estimate shifts and the tool reports warn/unknown instead of silently hooking a wrong function.
