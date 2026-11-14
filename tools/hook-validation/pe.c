#include "pe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t rd64(const uint8_t *p) { return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32); }

static int read_file(const wchar_t *path, uint8_t **out, size_t *outSize) {
  FILE *f = _wfopen(path, L"rb");
  long n;
  uint8_t *buf;
  if (!f) return -1;
  if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
  n = ftell(f);
  if (n <= 0) { fclose(f); return -1; }
  if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }
  buf = (uint8_t *)malloc((size_t)n);
  if (!buf) { fclose(f); return -1; }
  if (fread(buf, 1, (size_t)n, f) != (size_t)n) { free(buf); fclose(f); return -1; }
  fclose(f);
  *out = buf;
  *outSize = (size_t)n;
  return 0;
}

int pe_rva_off(const PeImage *img, uint32_t rva, uint32_t len, uint32_t *off) {
  uint32_t i;
  for (i = 0; i < img->sectionCount; i++) {
    const PeSection *s = &img->sections[i];
    uint32_t span = s->vsize > s->rawsize ? s->vsize : s->rawsize;
    if (rva >= s->va && (rva - s->va) < span) {
      uint32_t delta = rva - s->va;
      if (delta + len > s->rawsize) return -1; /* no backing file bytes (bss / tail) */
      if ((size_t)s->rawptr + delta + len > img->size) return -1;
      *off = s->rawptr + delta;
      return 0;
    }
  }
  return -1;
}

const PeSection *pe_section(const PeImage *img, const char *name) {
  uint32_t i;
  for (i = 0; i < img->sectionCount; i++)
    if (strncmp(img->sections[i].name, name, 8) == 0) return &img->sections[i];
  return NULL;
}

int pe_reloc_byte(const PeImage *img, uint32_t rva) {
  if (!img->relocMap || rva >= img->sizeOfImage) return 0;
  return img->relocMap[rva] != 0;
}

static int load_pdata(PeImage *img) {
  uint32_t rva = img->dirRva[3], size = img->dirSize[3], off, i, n;
  if (!rva || size < 12) return 0;
  if (pe_rva_off(img, rva, size, &off) != 0) return -1;
  n = size / 12;
  img->pdata = (PdataEntry *)calloc(n ? n : 1, sizeof(PdataEntry));
  if (!img->pdata) return -1;
  img->pdataCount = n;
  for (i = 0; i < n; i++) {
    const uint8_t *p = img->data + off + (size_t)i * 12;
    img->pdata[i].begin = rd32(p);
    img->pdata[i].end = rd32(p + 4);
    img->pdata[i].unwind = rd32(p + 8);
    if (img->pdata[i].begin >= img->pdata[i].end || img->pdata[i].end > img->sizeOfImage) {
      img->pdata[i].begin = img->pdata[i].end = 0; /* drop malformed */
    }
  }
  return 0;
}

static void reloc_mark(PeImage *img, uint32_t rva, uint32_t bytes) {
  uint32_t i;
  for (i = 0; i < bytes; i++) {
    if (rva + i < img->sizeOfImage) img->relocMap[rva + i] = 1;
  }
}

static int load_relocs(PeImage *img) {
  uint32_t rva = img->dirRva[5], size = img->dirSize[5], off, pos;
  if (!rva || size < 8) return 0;
  if (pe_rva_off(img, rva, size, &off) != 0) return -1;
  img->relocMap = (uint8_t *)calloc(img->sizeOfImage ? img->sizeOfImage : 1, 1);
  if (!img->relocMap) return -1;
  pos = 0;
  while (pos + 8 <= size) {
    const uint8_t *blk = img->data + off + pos;
    uint32_t page = rd32(blk);
    uint32_t blockSize = rd32(blk + 4);
    uint32_t i, entries;
    if (blockSize < 8 || pos + blockSize > size) break;
    entries = (blockSize - 8) / 2;
    for (i = 0; i < entries; i++) {
      uint16_t e = rd16(blk + 8 + (size_t)i * 2);
      uint32_t type = e >> 12, ofs = e & 0xfff;
      switch (type) {
        case 1: reloc_mark(img, page + ofs, 2); break;          /* HIGH */
        case 2: reloc_mark(img, page + ofs, 2); break;          /* LOW */
        case 3: reloc_mark(img, page + ofs, 4); break;          /* HIGHLOW */
        case 4: reloc_mark(img, page + ofs, 2); break;          /* HIGHADJ */
        case 10: reloc_mark(img, page + ofs, 8); break;         /* DIR64 */
        default: break;                                          /* ABSOLUTE / unsupported */
      }
    }
    pos += blockSize;
  }
  return 0;
}

int pe_load(const wchar_t *path, PeImage *img) {
  const uint8_t *dos, *opt;
  uint32_t e_lfanew, nsections, optSize, optOff, secOff, i;
  uint16_t magic;
  memset(img, 0, sizeof(*img));
  if (read_file(path, &img->data, &img->size) != 0) return -2;
  if (img->size < 0x40 || img->data[0] != 'M' || img->data[1] != 'Z') return -1;
  e_lfanew = rd32(img->data + 0x3c);
  if (e_lfanew + 24 > img->size) return -1;
  dos = img->data + e_lfanew;
  if (memcmp(dos, "PE\0\0", 4) != 0) return -1;
  img->machine = rd16(dos + 4);
  nsections = rd16(dos + 6);
  img->timeDateStamp = rd32(dos + 8);
  optSize = rd16(dos + 20);
  optOff = e_lfanew + 24;
  if (optOff + optSize > img->size || optSize < 96) return -1;
  opt = img->data + optOff;
  magic = rd16(opt);
  if (magic == 0x20b) { /* PE32+ */
    img->imageBase = rd64(opt + 24);
    img->sizeOfImage = rd32(opt + 56);
    img->checkSum = rd32(opt + 64);
    img->entryPoint = rd32(opt + 16);
    img->sizeOfCode = rd32(opt + 4);
    for (i = 0; i < 16; i++) {
      img->dirRva[i] = rd32(opt + 112 + i * 8);
      img->dirSize[i] = rd32(opt + 116 + i * 8);
    }
  } else if (magic == 0x10b) {
    img->imageBase = rd32(opt + 28);
    img->sizeOfImage = rd32(opt + 56);
    img->checkSum = rd32(opt + 64);
    img->entryPoint = rd32(opt + 16);
    img->sizeOfCode = rd32(opt + 4);
    for (i = 0; i < 16; i++) {
      img->dirRva[i] = rd32(opt + 96 + i * 8);
      img->dirSize[i] = rd32(opt + 100 + i * 8);
    }
  } else {
    return -1;
  }
  if (img->sizeOfImage == 0 || img->sizeOfImage > (256u << 20)) return -1;
  secOff = optOff + optSize;
  if (secOff + (size_t)nsections * 40 > img->size) return -1;
  img->sections = (PeSection *)calloc(nsections ? nsections : 1, sizeof(PeSection));
  if (!img->sections) return -1;
  img->sectionCount = nsections;
  for (i = 0; i < nsections; i++) {
    const uint8_t *s = img->data + secOff + (size_t)i * 40;
    memcpy(img->sections[i].name, s, 8);
    img->sections[i].vsize = rd32(s + 8);
    img->sections[i].va = rd32(s + 12);
    img->sections[i].rawsize = rd32(s + 16);
    img->sections[i].rawptr = rd32(s + 20);
    if ((size_t)img->sections[i].rawptr + img->sections[i].rawsize > img->size + 0x1000) return -1;
  }
  if (load_pdata(img) != 0) return -1;
  if (load_relocs(img) != 0) return -1;
  return 0;
}

void pe_free(PeImage *img) {
  free(img->data);
  free(img->sections);
  free(img->pdata);
  free(img->relocMap);
  memset(img, 0, sizeof(*img));
}

void pe_file_version(const wchar_t *path, const PeImage *img, char *buf, size_t buflen) {
  DWORD dummy = 0, size = 0;
  VS_FIXEDFILEINFO *fixed = NULL;
  UINT fixedLen = 0;
  buf[0] = 0;
  size = GetFileVersionInfoSizeW(path, &dummy);
  if (size) {
    void *block = malloc(size);
    if (block && GetFileVersionInfoW(path, 0, size, block) &&
        VerQueryValueW(block, L"\\", (LPVOID *)&fixed, &fixedLen) && fixed) {
      snprintf(buf, buflen, "%u.%u.%u.%u",
               (unsigned)(fixed->dwFileVersionMS >> 16), (unsigned)(fixed->dwFileVersionMS & 0xffff),
               (unsigned)(fixed->dwFileVersionLS >> 16), (unsigned)(fixed->dwFileVersionLS & 0xffff));
    }
    free(block);
  }
  if (!buf[0] && img)
    snprintf(buf, buflen, "0.0.%u.%u", (unsigned)((img->timeDateStamp >> 16) & 0xffff),
             (unsigned)(img->timeDateStamp & 0xffff));
}