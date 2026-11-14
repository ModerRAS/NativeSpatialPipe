#include "fn_hash.h"
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const uint8_t fn_reference_prologue[REFERENCE_PROLOGUE_SIZE] = {
    0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0x6c, 0x24, 0x10,
    0x48, 0x89, 0x74, 0x24, 0x18, 0x57
};

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static int set_err(char *err, size_t cap, const char *message) {
    if (err && cap) snprintf(err, cap, "%s", message);
    return 0;
}

/* Width in bytes of the value written by an IMAGE_REL_BASED_* entry. Type 0 is padding
   and writes nothing. Unknown types are conservatively masked as 4 bytes. */
static uint32_t reloc_width(uint16_t type) {
    switch (type) {
        case 0: return 0;   /* IMAGE_REL_BASED_ABSOLUTE: padding, no fixup */
        case 3: return 4;   /* IMAGE_REL_BASED_HIGHLOW */
        case 10: return 8;  /* IMAGE_REL_BASED_DIR64 */
        default: return 4;
    }
}

void fn_hash_hex(const uint8_t hash[FN_HASH_BYTES], char out[FN_HASH_BYTES * 2 + 1]) {
    static const char digits[] = "0123456789abcdef";
    for (int i = 0; i < FN_HASH_BYTES; ++i) {
        out[2 * i] = digits[hash[i] >> 4];
        out[2 * i + 1] = digits[hash[i] & 0x0f];
    }
    out[FN_HASH_BYTES * 2] = 0;
}

int fn_hash_equal(const uint8_t a[FN_HASH_BYTES], const uint8_t b[FN_HASH_BYTES]) {
    return memcmp(a, b, FN_HASH_BYTES) == 0;
}

/* Standalone SHA-256 of an arbitrary buffer. Used by the hook DLL to re-hash the
   in-memory function after MH_DisableHook restored the original bytes. */
int fn_sha256_bytes(const uint8_t *data, size_t size, uint8_t out[FN_HASH_BYTES], char *err, size_t err_cap) {
    BCRYPT_ALG_HANDLE algorithm = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return set_err(err, err_cap, "BCryptOpenAlgorithmProvider(SHA256) failed");
    BCRYPT_HASH_HANDLE hash_handle = NULL;
    status = BCryptCreateHash(algorithm, &hash_handle, NULL, 0, NULL, 0, 0);
    if (BCRYPT_SUCCESS(status)) status = BCryptHashData(hash_handle, (PUCHAR)data, (ULONG)size, 0);
    if (BCRYPT_SUCCESS(status)) status = BCryptFinishHash(hash_handle, out, FN_HASH_BYTES, 0);
    if (hash_handle) BCryptDestroyHash(hash_handle);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (!BCRYPT_SUCCESS(status)) return set_err(err, err_cap, "BCrypt SHA-256 hashing failed");
    return 1;
}

uint32_t fn_pdata_count(const PeImage *pe) {
    uint32_t rva = pe->directory_rva[PE_DIR_EXCEPTION];
    uint32_t bytes = pe->directory_size[PE_DIR_EXCEPTION];
    if (!rva || bytes < 12) return 0;
    size_t offset = 0;
    if (!pe_rva_to_offset(pe, rva, bytes, &offset)) return 0;
    return bytes / 12;
}

int fn_lookup_exact(const PeImage *pe, uint32_t rva, uint32_t *begin, uint32_t *end) {
    uint32_t count = fn_pdata_count(pe);
    if (!count) return 0;
    size_t offset = 0;
    if (!pe_rva_to_offset(pe, pe->directory_rva[PE_DIR_EXCEPTION], (size_t)count * 12, &offset)) return 0;
    const uint8_t *table = pe->data + offset;
    for (uint32_t i = 0; i < count; ++i) {
        const uint8_t *entry = table + (size_t)i * 12;
        uint32_t entry_begin = rd32(entry);
        uint32_t entry_end = rd32(entry + 4);
        if (entry_begin != rva || entry_end <= entry_begin) continue;
        if (begin) *begin = entry_begin;
        if (end) *end = entry_end;
        return 1;
    }
    return 0;
}

int fn_prologue_matches(const PeImage *pe, uint32_t rva) {
    const uint8_t *bytes = pe_rva_ptr(pe, rva, REFERENCE_PROLOGUE_SIZE);
    if (!bytes) return 0;
    return memcmp(bytes, fn_reference_prologue, REFERENCE_PROLOGUE_SIZE) == 0;
}

int fn_engine_init(FnHashEngine *engine, const PeImage *pe, char *err, size_t err_cap) {
    memset(engine, 0, sizeof(*engine));
    engine->pe = pe;
    BCRYPT_ALG_HANDLE algorithm = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return set_err(err, err_cap, "BCryptOpenAlgorithmProvider(SHA256) failed");
    engine->bcrypt_algorithm = algorithm;
    engine->bcrypt_ready = 1;

    uint32_t rva = pe->directory_rva[PE_DIR_BASERELOC];
    uint32_t bytes = pe->directory_size[PE_DIR_BASERELOC];
    if (!rva || bytes < 8) return 1; /* no relocations: nothing to normalize */
    size_t offset = 0;
    if (!pe_rva_to_offset(pe, rva, bytes, &offset)) return set_err(err, err_cap, "base relocation directory is not file-backed");

    /* First pass: count entries, second pass: store them. */
    const uint8_t *directory = pe->data + offset;
    uint32_t total = 0;
    for (uint32_t pos = 0; pos + 8 <= bytes;) {
        uint32_t block_size = rd32(directory + pos + 4);
        if (block_size < 8 || pos + block_size > bytes) break;
        total += (block_size - 8) / 2;
        pos += block_size;
    }
    if (!total) return 1;
    PeRelocation *relocations = (PeRelocation *)malloc((size_t)total * sizeof(PeRelocation));
    if (!relocations) return set_err(err, err_cap, "out of memory for relocation index");
    uint32_t cursor = 0;
    for (uint32_t pos = 0; pos + 8 <= bytes;) {
        uint32_t page_rva = rd32(directory + pos);
        uint32_t block_size = rd32(directory + pos + 4);
        if (block_size < 8 || pos + block_size > bytes) break;
        uint32_t entries = (block_size - 8) / 2;
        for (uint32_t i = 0; i < entries && cursor < total; ++i) {
            uint16_t entry = rd16(directory + pos + 8 + i * 2);
            relocations[cursor].rva = page_rva + (entry & 0x0fff);
            relocations[cursor].type = (uint16_t)(entry >> 12);
            ++cursor;
        }
        pos += block_size;
    }
    engine->relocations = relocations;
    engine->relocation_count = cursor;
    return 1;
}

void fn_engine_free(FnHashEngine *engine) {
    if (!engine) return;
    if (engine->bcrypt_algorithm) BCryptCloseAlgorithmProvider((BCRYPT_ALG_HANDLE)engine->bcrypt_algorithm, 0);
    free(engine->relocations);
    memset(engine, 0, sizeof(*engine));
}

int fn_engine_hash(FnHashEngine *engine, uint32_t begin, uint32_t end, FunctionHash *out, char *err, size_t err_cap) {
    if (end <= begin) return set_err(err, err_cap, "empty function range");
    uint32_t size = end - begin;
    if (size > FN_MAX_FUNCTION_BYTES) return set_err(err, err_cap, "function range exceeds 1 MiB sanity limit");
    const uint8_t *source = pe_rva_ptr(engine->pe, begin, size);
    if (!source) return set_err(err, err_cap, "function range is not file-backed");
    uint8_t *buffer = (uint8_t *)malloc(size);
    if (!buffer) return set_err(err, err_cap, "out of memory for function bytes");
    memcpy(buffer, source, size);

    uint32_t masked = 0;
    for (uint32_t i = 0; i < engine->relocation_count; ++i) {
        uint32_t target = engine->relocations[i].rva;
        if (target < begin || target >= end) continue;
        uint32_t width = reloc_width(engine->relocations[i].type);
        if (!width) continue;
        uint32_t delta = target - begin;
        if (width > size - delta) width = size - delta;
        memset(buffer + delta, 0, width);
        ++masked;
    }

    BCRYPT_HASH_HANDLE hash_handle = NULL;
    NTSTATUS status = BCryptCreateHash((BCRYPT_ALG_HANDLE)engine->bcrypt_algorithm, &hash_handle, NULL, 0, NULL, 0, 0);
    if (BCRYPT_SUCCESS(status)) status = BCryptHashData(hash_handle, buffer, size, 0);
    if (BCRYPT_SUCCESS(status)) status = BCryptFinishHash(hash_handle, out->hash, FN_HASH_BYTES, 0);
    if (hash_handle) BCryptDestroyHash(hash_handle);
    free(buffer);
    if (!BCRYPT_SUCCESS(status)) return set_err(err, err_cap, "BCrypt SHA-256 hashing failed");
    out->begin = begin;
    out->end = end;
    out->size = size;
    out->relocations_masked = masked;
    return 1;
}

int fn_engine_hash_at(FnHashEngine *engine, uint32_t rva, FunctionHash *out, char *err, size_t err_cap) {
    uint32_t begin = 0, end = 0;
    if (!fn_lookup_exact(engine->pe, rva, &begin, &end)) return set_err(err, err_cap, "no .pdata RUNTIME_FUNCTION with Begin == RVA");
    return fn_engine_hash(engine, begin, end, out, err, err_cap);
}

int fn_engine_scan(FnHashEngine *engine, const uint8_t reference_hash[FN_HASH_BYTES], uint32_t max_size,
                   uint32_t *found_rva, uint32_t *found_size, uint32_t *scanned, uint32_t *skipped) {
    uint32_t count = fn_pdata_count(engine->pe);
    size_t offset = 0;
    *scanned = 0;
    *skipped = 0;
    if (!count) return 0;
    if (!pe_rva_to_offset(engine->pe, engine->pe->directory_rva[PE_DIR_EXCEPTION], (size_t)count * 12, &offset)) return 0;
    const uint8_t *table = engine->pe->data + offset;
    for (uint32_t i = 0; i < count; ++i) {
        const uint8_t *entry = table + (size_t)i * 12;
        uint32_t begin = rd32(entry);
        uint32_t end = rd32(entry + 4);
        if (end <= begin) { ++*skipped; continue; }
        uint32_t size = end - begin;
        if (size > max_size) { ++*skipped; continue; }
        FunctionHash candidate;
        char hash_err[128];
        if (!fn_engine_hash(engine, begin, end, &candidate, hash_err, sizeof(hash_err))) { ++*skipped; continue; }
        ++*scanned;
        if (fn_hash_equal(candidate.hash, reference_hash)) {
            *found_rva = begin;
            *found_size = size;
            return 1;
        }
    }
    return 0;
}
