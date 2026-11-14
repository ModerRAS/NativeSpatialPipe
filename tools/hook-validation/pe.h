/* PE on-disk parser shared by the NSP hook validation tools (MinGW / gcc, no deps). */
#ifndef NSP_HOOK_VALIDATION_PE_H
#define NSP_HOOK_VALIDATION_PE_H

#include <stddef.h>
#include <stdint.h>
#ifdef _WIN32
#include <windows.h>
#endif

typedef struct PeSection {
  char name[9];
  uint32_t va;
  uint32_t vsize;
  uint32_t rawptr;
  uint32_t rawsize;
} PeSection;

typedef struct PdataEntry {
  uint32_t begin; /* RVA */
  uint32_t end;   /* RVA */
  uint32_t unwind;
} PdataEntry;

typedef struct PeImage {
  uint8_t *data;
  size_t size;
  uint16_t machine;
  uint32_t timeDateStamp;
  uint32_t sizeOfImage;
  uint32_t checkSum;
  uint64_t imageBase;
  uint32_t entryPoint;
  uint32_t sizeOfCode;
  PeSection *sections;
  uint32_t sectionCount;
  uint32_t dirRva[16];
  uint32_t dirSize[16];
  PdataEntry *pdata;
  uint32_t pdataCount;
  uint8_t *relocMap; /* one byte per image RVA: 1 = byte covered by a .reloc fixup */
} PeImage;

int pe_load(const wchar_t *path, PeImage *img);
void pe_free(PeImage *img);
int pe_rva_off(const PeImage *img, uint32_t rva, uint32_t len, uint32_t *off);
const PeSection *pe_section(const PeImage *img, const char *name);
int pe_reloc_byte(const PeImage *img, uint32_t rva);
/* File version "a.b.c.d" from the VERSIONINFO resource; falls back to "0.0.<tds hi>.<tds lo>". */
void pe_file_version(const wchar_t *path, const PeImage *img, char *buf, size_t buflen);

#endif
