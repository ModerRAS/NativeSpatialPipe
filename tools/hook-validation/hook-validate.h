#ifndef NSP_HOOK_VALIDATE_H
#define NSP_HOOK_VALIDATE_H
/* Minimal read-only PE32+ parser used by the isolated hook-validation tools.
   Intentionally dependency-free (no pefile/bfd) so the tool builds with plain gcc. */
#include <stdint.h>
#include <stddef.h>

#define HV_MAX_SECTIONS 32
#define HV_MAX_FUNCS 8192
#define HV_MAX_REFS 65536
#define HV_MAX_SLOTS_PER_FN 16

typedef struct {
  char name[9];
  uint32_t va, vsize, rawsize, rawptr;
} HvSection;

typedef struct {
  uint8_t *data;
  size_t size;
  uint64_t image_base;
  uint32_t size_of_image;
  uint32_t checksum;
  uint32_t timestamp;
  int nsec;
  HvSection sec[HV_MAX_SECTIONS];
  uint16_t file_version[4]; /* major, minor, build, revision (0 when absent) */
} HvPeImage;

typedef struct {
  uint32_t begin, end;
  uint16_t ref_count;
  uint8_t kind_count;
  uint8_t kinds_mask;
  uint16_t slot_count;
  uint32_t slots[HV_MAX_SLOTS_PER_FN];
} HvFunction;

typedef struct {
  uint32_t slot_rva;
  uint32_t func_rva;
} HvRef;

int hv_pe_load(HvPeImage *pe, const char *path);
void hv_pe_free(HvPeImage *pe);
const HvSection *hv_pe_section(const HvPeImage *pe, uint32_t rva);
size_t hv_pe_read(const HvPeImage *pe, uint32_t rva, void *out, size_t n);
int hv_pe_functions(const HvPeImage *pe, HvFunction *fns, int max);
int hv_pe_scan_refs(const HvPeImage *pe, HvFunction *fns, int nfun, HvRef *refs, int maxrefs);
int hv_kinds(const HvPeImage *pe, const HvFunction *fn);
void hv_run_bounds(const HvPeImage *pe, uint32_t slot_rva, uint32_t *run_begin, uint32_t *run_end);
int hv_find_function(const HvFunction *fns, int nfun, uint32_t rva);
#endif
