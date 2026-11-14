#include "pe.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t rd64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}
static int set_err(char *err, size_t cap, const char *message) {
    if (err && cap) snprintf(err, cap, "%s", message);
    return 0;
}

static int load_bytes(const wchar_t *path, uint8_t **out, size_t *out_size, char *err, size_t cap) {
    FILE *file = _wfopen(path, L"rb");
    if (!file) return set_err(err, cap, "cannot open file");
    if (fseek(file, 0, SEEK_END) != 0) { fclose(file); return set_err(err, cap, "cannot seek file"); }
    long end = ftell(file);
    if (end < 0) { fclose(file); return set_err(err, cap, "cannot tell file size"); }
    if ((unsigned long)end > PE_MAX_IMAGE_BYTES) { fclose(file); return set_err(err, cap, "image exceeds 512 MiB limit"); }
    if (fseek(file, 0, SEEK_SET) != 0) { fclose(file); return set_err(err, cap, "cannot rewind file"); }
    size_t want = (size_t)end;
    uint8_t *data = (uint8_t *)malloc(want ? want : 1);
    if (!data) { fclose(file); return set_err(err, cap, "out of memory"); }
    size_t got = fread(data, 1, want, file);
    int bad = got != want || ferror(file);
    fclose(file);
    if (bad) { free(data); return set_err(err, cap, "short read"); }
    *out = data;
    *out_size = want;
    return 1;
}

int pe_load(const wchar_t *path, PeImage *pe, char *err, size_t err_cap) {
    memset(pe, 0, sizeof(*pe));
    uint8_t *data = NULL;
    size_t size = 0;
    if (!load_bytes(path, &data, &size, err, err_cap)) return 0;
    if (size < 0x40) { free(data); return set_err(err, err_cap, "file too small for DOS header"); }
    if (rd16(data) != 0x5a4d) { free(data); return set_err(err, err_cap, "missing MZ signature"); }
    uint32_t pe_off = rd32(data + 0x3c);
    if (pe_off > size || size - pe_off < 24) { free(data); return set_err(err, err_cap, "e_lfanew out of range"); }
    const uint8_t *nt = data + pe_off;
    if (rd32(nt) != 0x00004550u) { free(data); return set_err(err, err_cap, "missing PE signature"); }
    uint16_t section_count = rd16(nt + 6);
    uint16_t opt_size = rd16(nt + 20);
    size_t opt = (size_t)pe_off + 24;
    if (opt > size || size - opt < opt_size || opt_size < 112) {
        free(data);
        return set_err(err, err_cap, "truncated optional header");
    }
    const uint8_t *oh = data + opt;
    uint16_t magic = rd16(oh);
    if (magic != 0x20b) { free(data); return set_err(err, err_cap, "only PE32+ (x64) images are supported"); }
    if (section_count == 0 || section_count > PE_MAX_SECTIONS) {
        free(data);
        return set_err(err, err_cap, "unsupported section count");
    }
    size_t table = opt + opt_size;
    if (table > size || size - table < (size_t)section_count * 40) {
        free(data);
        return set_err(err, err_cap, "truncated section table");
    }
    pe->data = data;
    pe->size = size;
    pe->machine = rd16(nt + 4);
    pe->optional_magic = magic;
    pe->time_date_stamp = rd32(nt + 8);
    pe->image_base = rd64(oh + 24);
    pe->size_of_image = rd32(oh + 56);
    pe->checksum = rd32(oh + 64);
    uint32_t directory_count = rd32(oh + 108);
    pe->directory_count = directory_count > PE_DIR_COUNT ? PE_DIR_COUNT : directory_count;
    for (uint32_t i = 0; i < pe->directory_count; ++i) {
        pe->directory_rva[i] = rd32(oh + 112 + 8 * i);
        pe->directory_size[i] = rd32(oh + 116 + 8 * i);
    }
    pe->section_count = section_count;
    for (uint16_t i = 0; i < section_count; ++i) {
        const uint8_t *raw = data + table + (size_t)i * 40;
        PeSection *section = &pe->sections[i];
        memcpy(section->name, raw, 8);
        section->name[8] = 0;
        section->virtual_size = rd32(raw + 8);
        section->virtual_address = rd32(raw + 12);
        section->raw_size = rd32(raw + 16);
        section->raw_pointer = rd32(raw + 20);
    }
    return 1;
}

void pe_free(PeImage *pe) {
    if (!pe) return;
    free(pe->data);
    pe->data = NULL;
    pe->size = 0;
}

int pe_rva_to_offset(const PeImage *pe, uint32_t rva, size_t len, size_t *offset) {
    if (!pe || !pe->data) return 0;
    for (uint16_t i = 0; i < pe->section_count; ++i) {
        const PeSection *section = &pe->sections[i];
        uint64_t span = section->virtual_size > section->raw_size ? section->virtual_size : section->raw_size;
        if (rva < section->virtual_address || (uint64_t)rva >= (uint64_t)section->virtual_address + span) continue;
        uint64_t delta = (uint64_t)rva - section->virtual_address;
        if (delta + len > section->raw_size) return 0;
        uint64_t raw_off = (uint64_t)section->raw_pointer + delta;
        if (raw_off + len > pe->size) return 0;
        if (offset) *offset = (size_t)raw_off;
        return 1;
    }
    return 0;
}

const uint8_t *pe_rva_ptr(const PeImage *pe, uint32_t rva, size_t len) {
    size_t offset = 0;
    if (!pe_rva_to_offset(pe, rva, len, &offset)) return NULL;
    return pe->data + offset;
}
