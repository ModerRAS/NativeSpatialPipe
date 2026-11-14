#ifndef NSP_HOOK_VALIDATION_FN_HASH_H
#define NSP_HOOK_VALIDATION_FN_HASH_H
/* .pdata-scoped function lookup + relocation-normalized SHA-256. */
#include "pe.h"

#define FN_HASH_BYTES 32
#define REFERENCE_RVA 0x31930u
#define REFERENCE_PROLOGUE_SIZE 16
#define DEFAULT_MAX_FUNCTION_SIZE 8192u
#define FN_MAX_FUNCTION_BYTES (1024u * 1024u)

typedef struct {
    uint32_t begin;
    uint32_t end;
    uint32_t size;
    uint32_t relocations_masked;
    uint8_t hash[FN_HASH_BYTES];
} FunctionHash;

typedef struct {
    uint32_t rva;
    uint16_t type;
} PeRelocation;

typedef struct {
    const PeImage *pe;
    PeRelocation *relocations;
    uint32_t relocation_count;
    int bcrypt_ready;
    void *bcrypt_algorithm;
} FnHashEngine;

extern const uint8_t fn_reference_prologue[REFERENCE_PROLOGUE_SIZE];

void fn_hash_hex(const uint8_t hash[FN_HASH_BYTES], char out[FN_HASH_BYTES * 2 + 1]);
int fn_sha256_bytes(const uint8_t *data, size_t size, uint8_t out[FN_HASH_BYTES], char *err, size_t err_cap);
int fn_hash_equal(const uint8_t a[FN_HASH_BYTES], const uint8_t b[FN_HASH_BYTES]);
uint32_t fn_pdata_count(const PeImage *pe);
int fn_lookup_exact(const PeImage *pe, uint32_t rva, uint32_t *begin, uint32_t *end);
int fn_prologue_matches(const PeImage *pe, uint32_t rva);

int fn_engine_init(FnHashEngine *engine, const PeImage *pe, char *err, size_t err_cap);
void fn_engine_free(FnHashEngine *engine);
int fn_engine_hash(FnHashEngine *engine, uint32_t begin, uint32_t end, FunctionHash *out, char *err, size_t err_cap);
int fn_engine_hash_at(FnHashEngine *engine, uint32_t rva, FunctionHash *out, char *err, size_t err_cap);
int fn_engine_scan(FnHashEngine *engine, const uint8_t reference_hash[FN_HASH_BYTES], uint32_t max_size,
                   uint32_t *found_rva, uint32_t *found_size, uint32_t *scanned, uint32_t *skipped);

#endif
