/* nsp-hook-validate: branch-1 hook validation method "unwind-fn-hash".
 *
 * Locates the pinned NSP hook target through the .pdata unwind table and compares a
 * relocation-normalized SHA-256 of the whole function body against the reference build.
 * Emits a single JSON object on stdout (see ../INTEGRATION.md and ../README.md). */
#include "pe.h"
#include "fn_hash.h"
#include <windows.h>
#include <shellapi.h>
#include <winver.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CHECKS 24
#define JSON_BUFFER_BYTES (64u * 1024u)

typedef struct {
    char buffer[JSON_BUFFER_BYTES];
    size_t length;
    int overflow;
} Json;

typedef struct {
    const char *name;
    int ok;
    char detail[768];
} Check;

typedef struct {
    Check items[MAX_CHECKS];
    int count;
} Checks;

typedef struct {
    const wchar_t *method;
    const wchar_t *reference;
    const wchar_t *candidate;
    uint32_t reference_rva;
    uint32_t max_function_size;
    int help;
} Options;

static void json_init(Json *json) {
    json->buffer[0] = 0;
    json->length = 0;
    json->overflow = 0;
}

static void json_raw(Json *json, const char *text) {
    if (json->overflow) return;
    size_t length = strlen(text);
    if (json->length + length + 1 > sizeof(json->buffer)) { json->overflow = 1; return; }
    memcpy(json->buffer + json->length, text, length);
    json->length += length;
    json->buffer[json->length] = 0;
}

static void json_string(Json *json, const char *text) {
    if (!text) { json_raw(json, "null"); return; }
    json_raw(json, "\"");
    for (const unsigned char *cursor = (const unsigned char *)text; *cursor; ++cursor) {
        char escape[8];
        switch (*cursor) {
            case '"': json_raw(json, "\\\""); break;
            case '\\': json_raw(json, "\\\\"); break;
            case '\n': json_raw(json, "\\n"); break;
            case '\r': json_raw(json, "\\r"); break;
            case '\t': json_raw(json, "\\t"); break;
            default:
                if (*cursor < 0x20) {
                    snprintf(escape, sizeof(escape), "\\u%04x", (unsigned)*cursor);
                    json_raw(json, escape);
                } else {
                    char byte[2] = { (char)*cursor, 0 };
                    json_raw(json, byte);
                }
        }
    }
    json_raw(json, "\"");
}

static void json_printf(Json *json, const char *format, ...) {
    char temporary[1024];
    va_list arguments;
    va_start(arguments, format);
    vsnprintf(temporary, sizeof(temporary), format, arguments);
    va_end(arguments);
    json_raw(json, temporary);
}

static char *utf8_dup(const wchar_t *text) {
    if (!text) return NULL;
    int bytes = WideCharToMultiByte(CP_UTF8, 0, text, -1, NULL, 0, NULL, NULL);
    if (bytes <= 0) return NULL;
    char *copy = (char *)malloc((size_t)bytes);
    if (!copy) return NULL;
    if (!WideCharToMultiByte(CP_UTF8, 0, text, -1, copy, bytes, NULL, NULL)) { free(copy); return NULL; }
    return copy;
}

static int add_check(Checks *checks, const char *name, int ok, const char *format, ...) {
    if (checks->count >= MAX_CHECKS) return 0;
    Check *check = &checks->items[checks->count++];
    check->name = name;
    check->ok = ok ? 1 : 0;
    va_list arguments;
    va_start(arguments, format);
    vsnprintf(check->detail, sizeof(check->detail), format, arguments);
    va_end(arguments);
    return 1;
}

static int emit_failure(const char *message, const char *method) {
    Json json;
    json_init(&json);
    json_raw(&json, "{\"error\":");
    json_string(&json, message);
    if (method) { json_raw(&json, ",\"method\":"); json_string(&json, method); }
    json_raw(&json, "}\n");
    fwrite(json.buffer, 1, json.length, stdout);
    return 2;
}

static int file_version(const wchar_t *path, char *out, size_t capacity) {
    DWORD ignored = 0;
    DWORD size = GetFileVersionInfoSizeW(path, &ignored);
    if (!size) return 0;
    void *info = malloc(size);
    if (!info) return 0;
    int ok = 0;
    VS_FIXEDFILEINFO *fixed = NULL;
    UINT fixed_length = 0;
    if (GetFileVersionInfoW(path, 0, size, info) &&
        VerQueryValueW(info, L"\\", (LPVOID *)&fixed, &fixed_length) &&
        fixed && fixed->dwSignature == 0xFEEF04BDu) {
        snprintf(out, capacity, "%u.%u.%u.%u",
                 (unsigned)HIWORD(fixed->dwFileVersionMS), (unsigned)LOWORD(fixed->dwFileVersionMS),
                 (unsigned)HIWORD(fixed->dwFileVersionLS), (unsigned)LOWORD(fixed->dwFileVersionLS));
        ok = 1;
    }
    free(info);
    return ok;
}

static int parse_options(int argc, wchar_t **argv, Options *options, char *error, size_t error_capacity) {
    for (int i = 1; i < argc; ++i) {
        const wchar_t *argument = argv[i];
        if (!wcscmp(argument, L"--method") || !wcscmp(argument, L"-m")) {
            if (++i >= argc) { snprintf(error, error_capacity, "--method requires a value"); return 0; }
            options->method = argv[i];
        } else if (!wcscmp(argument, L"--reference") || !wcscmp(argument, L"-r")) {
            if (++i >= argc) { snprintf(error, error_capacity, "--reference requires a value"); return 0; }
            options->reference = argv[i];
        } else if (!wcscmp(argument, L"--candidate") || !wcscmp(argument, L"-c")) {
            if (++i >= argc) { snprintf(error, error_capacity, "--candidate requires a value"); return 0; }
            options->candidate = argv[i];
        } else if (!wcscmp(argument, L"--json")) {
            /* JSON is the only output format; accepted for CLI-contract compatibility. */
        } else if (!wcscmp(argument, L"--ref-rva")) {
            if (++i >= argc) { snprintf(error, error_capacity, "--ref-rva requires a hexadecimal RVA"); return 0; }
            options->reference_rva = (uint32_t)wcstoul(argv[i], NULL, 16);
        } else if (!wcscmp(argument, L"--max-function-size")) {
            if (++i >= argc) { snprintf(error, error_capacity, "--max-function-size requires a byte count"); return 0; }
            options->max_function_size = (uint32_t)wcstoul(argv[i], NULL, 10);
        } else if (!wcscmp(argument, L"--help") || !wcscmp(argument, L"-h")) {
            options->help = 1;
        } else {
            snprintf(error, error_capacity, "unknown argument: %ls", argument);
            return 0;
        }
    }
    if (!options->method) { snprintf(error, error_capacity, "missing --method"); return 0; }
    if (!options->reference) { snprintf(error, error_capacity, "missing --reference"); return 0; }
    if (!options->candidate) { snprintf(error, error_capacity, "missing --candidate"); return 0; }
    if (!options->max_function_size) { snprintf(error, error_capacity, "--max-function-size must be positive"); return 0; }
    return 1;
}

int main(void) {
    int argc = 0;
    wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return emit_failure("CommandLineToArgvW failed", NULL);

    Options options;
    memset(&options, 0, sizeof(options));
    options.reference_rva = REFERENCE_RVA;
    options.max_function_size = DEFAULT_MAX_FUNCTION_SIZE;
    char parse_error[512];
    if (!parse_options(argc, argv, &options, parse_error, sizeof(parse_error))) {
        LocalFree(argv);
        return emit_failure(parse_error, NULL);
    }
    if (options.help) {
        printf("usage: nsp-hook-validate --method unwind-fn-hash --reference <ref.exe> --candidate <cand.exe> [--json] [--ref-rva HEX] [--max-function-size N]\n");
        LocalFree(argv);
        return 0;
    }
    char *method_utf8 = utf8_dup(options.method);
    char *reference_path = utf8_dup(options.reference);
    char *candidate_path = utf8_dup(options.candidate);
    if (!method_utf8 || !reference_path || !candidate_path) {
        free(method_utf8); free(reference_path); free(candidate_path); LocalFree(argv);
        return emit_failure("out of memory converting argument paths", NULL);
    }
    if (wcscmp(options.method, L"unwind-fn-hash")) {
        int code = emit_failure("unsupported --method (this tool implements unwind-fn-hash)", method_utf8);
        free(method_utf8); free(reference_path); free(candidate_path); LocalFree(argv);
        return code;
    }

    LARGE_INTEGER frequency, started, finished;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&started);

    Json json;
    json_init(&json);
    Checks checks;
    memset(&checks, 0, sizeof(checks));
    PeImage reference_image;
    PeImage candidate_image;
    memset(&reference_image, 0, sizeof(reference_image));
    memset(&candidate_image, 0, sizeof(candidate_image));
    FnHashEngine reference_engine;
    FnHashEngine candidate_engine;
    memset(&reference_engine, 0, sizeof(reference_engine));
    memset(&candidate_engine, 0, sizeof(candidate_engine));
    int reference_engine_ready = 0;
    int candidate_engine_ready = 0;
    int exit_code = 2;
    char failure[1024] = "analysis did not complete";
    char scratch[512];
    const char *decision = "unknown";
    int target_changed = -1; /* -1 emits JSON null */
    int have_located = 0;
    uint32_t located_rva = 0;
    uint32_t located_size = 0;
    double located_confidence = 0.0;
    char reference_hash_hex[FN_HASH_BYTES * 2 + 1] = { 0 };
    char version[64] = { 0 };
    int have_version = 0;
    FunctionHash reference_function;
    memset(&reference_function, 0, sizeof(reference_function));

    if (!pe_load(options.reference, &reference_image, scratch, sizeof(scratch))) {
        snprintf(failure, sizeof(failure), "reference PE load failed: %s", scratch);
        goto cleanup;
    }
    add_check(&checks, "loadReference", 1,
              "PE32+ machine=0x%04x sections=%u .pdataEntries=%u imageBase=0x%llx",
              (unsigned)reference_image.machine, (unsigned)reference_image.section_count,
              (unsigned)fn_pdata_count(&reference_image),
              (unsigned long long)reference_image.image_base);
    {
        uint32_t begin = 0, end = 0;
        if (!fn_lookup_exact(&reference_image, options.reference_rva, &begin, &end)) {
            snprintf(failure, sizeof(failure), "reference PE has no .pdata entry with Begin == 0x%x", options.reference_rva);
            goto cleanup;
        }
        if (!fn_prologue_matches(&reference_image, options.reference_rva)) {
            snprintf(failure, sizeof(failure), "reference PE prologue at 0x%x does not match the pinned NSP 16-byte prologue", options.reference_rva);
            goto cleanup;
        }
        if (!fn_engine_init(&reference_engine, &reference_image, scratch, sizeof(scratch))) {
            snprintf(failure, sizeof(failure), "reference relocation index failed: %s", scratch);
            goto cleanup;
        }
        reference_engine_ready = 1;
        if (!fn_engine_hash(&reference_engine, begin, end, &reference_function, scratch, sizeof(scratch))) {
            snprintf(failure, sizeof(failure), "reference function hashing failed: %s", scratch);
            goto cleanup;
        }
        fn_hash_hex(reference_function.hash, reference_hash_hex);
        add_check(&checks, "referenceTarget", 1, "rva=0x%x size=%u normalizedSha256=%s",
                  (unsigned)begin, (unsigned)reference_function.size, reference_hash_hex);
        add_check(&checks, "referencePrologue", 1, "16-byte NSP prologue matches Native-Hook.c:71 constant");
        add_check(&checks, "relocNormalization", 1,
                  "reference target masks %u relocation slot(s); image .reloc table has %u entries",
                  (unsigned)reference_function.relocations_masked, (unsigned)reference_engine.relocation_count);
    }

    if (!pe_load(options.candidate, &candidate_image, scratch, sizeof(scratch))) {
        snprintf(failure, sizeof(failure), "candidate PE load failed: %s", scratch);
        goto cleanup;
    }
    if (!fn_engine_init(&candidate_engine, &candidate_image, scratch, sizeof(scratch))) {
        snprintf(failure, sizeof(failure), "candidate relocation index failed: %s", scratch);
        goto cleanup;
    }
    candidate_engine_ready = 1;
    add_check(&checks, "loadCandidate", 1,
              "PE32+ machine=0x%04x sections=%u .pdataEntries=%u imageBase=0x%llx",
              (unsigned)candidate_image.machine, (unsigned)candidate_image.section_count,
              (unsigned)fn_pdata_count(&candidate_image),
              (unsigned long long)candidate_image.image_base);
    have_version = file_version(options.candidate, version, sizeof(version));

    int same_identity = reference_image.time_date_stamp == candidate_image.time_date_stamp &&
                        reference_image.size_of_image == candidate_image.size_of_image &&
                        reference_image.checksum == candidate_image.checksum;
    add_check(&checks, "buildIdentity", same_identity,
              "candidate TimeDateStamp=0x%08x SizeOfImage=0x%x CheckSum=0x%x %s reference (0x%08x/0x%x/0x%x)",
              (unsigned)candidate_image.time_date_stamp, (unsigned)candidate_image.size_of_image,
              (unsigned)candidate_image.checksum,
              same_identity ? "matches" : "differs from",
              (unsigned)reference_image.time_date_stamp, (unsigned)reference_image.size_of_image,
              (unsigned)reference_image.checksum);

    {
        uint32_t candidate_begin = 0, candidate_end = 0;
        int has_same_rva_entry = fn_lookup_exact(&candidate_image, options.reference_rva, &candidate_begin, &candidate_end);
        int prologue_ok = fn_prologue_matches(&candidate_image, options.reference_rva);
        FunctionHash candidate_function;
        memset(&candidate_function, 0, sizeof(candidate_function));
        int have_candidate_function = 0;
        if (has_same_rva_entry) {
            if (!fn_engine_hash(&candidate_engine, candidate_begin, candidate_end, &candidate_function, scratch, sizeof(scratch))) {
                snprintf(failure, sizeof(failure), "candidate .pdata entry hashing failed: %s", scratch);
                goto cleanup;
            }
            have_candidate_function = 1;
        }

        if (same_identity) {
            int hash_match = have_candidate_function && fn_hash_equal(reference_function.hash, candidate_function.hash);
            add_check(&checks, "sameRvaTarget", has_same_rva_entry,
                      has_same_rva_entry ? "candidate .pdata has Begin==0x%x size=%u" : "candidate .pdata has no entry with Begin==0x%x",
                      (unsigned)options.reference_rva, (unsigned)candidate_function.size);
            add_check(&checks, "prologue", prologue_ok,
                      prologue_ok ? "candidate bytes at 0x%x match the 16-byte NSP prologue" : "candidate bytes at 0x%x do NOT match the 16-byte NSP prologue",
                      (unsigned)options.reference_rva);
            add_check(&checks, "normalizedHashMatch", hash_match,
                      hash_match ? "candidate normalized function hash equals reference (%s)" : "candidate normalized function hash differs from reference (%s)",
                      hash_match ? reference_hash_hex : "target bytes changed");
            if (has_same_rva_entry && prologue_ok && hash_match) {
                decision = "allow";
                target_changed = 0;
                have_located = 1;
                located_rva = candidate_begin;
                located_size = candidate_function.size;
                located_confidence = 1.0;
                add_check(&checks, "decisionRule", 1,
                          "same build identity + pinned RVA + prologue + normalized function hash match => allow (target unchanged)");
            } else {
                decision = "deny";
                target_changed = 1;
                if (has_same_rva_entry) {
                    have_located = 1;
                    located_rva = candidate_begin;
                    located_size = candidate_function.size;
                    located_confidence = 1.0;
                }
                add_check(&checks, "decisionRule", 0,
                          "same build identity but %s => deny (function at pinned RVA changed)",
                          !has_same_rva_entry ? "the pinned RVA is absent from .pdata"
                                              : (!prologue_ok ? "the prologue was overwritten" : "the normalized function hash differs"));
            }
        } else {
            uint32_t found_rva = 0, found_size = 0, scanned = 0, skipped = 0;
            int found = fn_engine_scan(&candidate_engine, reference_function.hash, options.max_function_size,
                                       &found_rva, &found_size, &scanned, &skipped);
            if (found) {
                decision = "allow";
                target_changed = 0;
                have_located = 1;
                located_rva = found_rva;
                located_size = found_size;
                located_confidence = 0.95;
                add_check(&checks, "crossBuildExactMatch", 1,
                          "cross-build exact function match: normalized SHA-256 found at rva=0x%x size=%u", (unsigned)found_rva, (unsigned)found_size);
                add_check(&checks, "normalizedHashMatch", 1, "reference normalized hash found in candidate");
                add_check(&checks, "decisionRule", 1, "different build identity but exact normalized function hash match => allow");
            } else {
                add_check(&checks, "crossBuildExactMatch", 0,
                          "no exact normalized SHA-256 match among %u scanned function(s) (%u skipped: empty or larger than %u bytes)",
                          (unsigned)scanned, (unsigned)skipped, (unsigned)options.max_function_size);
                add_check(&checks, "normalizedHashMatch", 0, "reference normalized hash not found in candidate");
                if (has_same_rva_entry) {
                    add_check(&checks, "sameRvaPrologue", prologue_ok,
                              prologue_ok ? "same RVA .pdata entry and prologue match reference but body hash differs"
                                          : "same RVA .pdata entry exists but prologue differs");
                }
                if (has_same_rva_entry && prologue_ok) {
                    decision = "deny";
                    target_changed = 1;
                    have_located = 1;
                    located_rva = candidate_begin;
                    located_size = candidate_function.size;
                    located_confidence = 0.6;
                    add_check(&checks, "decisionRule", 0,
                              "different build identity, matching same-RVA prologue, different body hash => deny (pinned function changed; a recompiled build at the same RVA produces the same signal)");
                } else {
                    decision = "unknown";
                    target_changed = -1;
                    add_check(&checks, "decisionRule", 0,
                              "new build: no exact hash match and no matching pinned-RVA prologue => unknown (manual review required)");
                }
            }
        }
    }
    exit_code = 0;

cleanup:
    if (exit_code == 0) {
        QueryPerformanceCounter(&finished);
        json_init(&json);
        json_raw(&json, "{\"method\":");
        json_string(&json, method_utf8);
        json_raw(&json, ",\"reference\":");
        json_string(&json, reference_path);
        json_raw(&json, ",\"candidate\":");
        json_string(&json, candidate_path);
        json_raw(&json, ",\"build\":{\"fileVersion\":");
        if (have_version) json_string(&json, version); else json_raw(&json, "null");
        json_printf(&json, ",\"timeDateStamp\":%u,\"sizeOfImage\":%u,\"checksum\":%u}",
                    (unsigned)candidate_image.time_date_stamp,
                    (unsigned)candidate_image.size_of_image,
                    (unsigned)candidate_image.checksum);
        json_raw(&json, ",\"located\":");
        if (have_located) {
            json_printf(&json, "{\"rva\":%u,\"size\":%u,\"confidence\":%.2f}",
                        (unsigned)located_rva, (unsigned)located_size, located_confidence);
        } else {
            json_raw(&json, "null");
        }
        json_raw(&json, ",\"decision\":");
        json_string(&json, decision);
        json_printf(&json, ",\"targetChanged\":%s", target_changed < 0 ? "null" : (target_changed ? "true" : "false"));
        json_raw(&json, ",\"checks\":[");
        for (int i = 0; i < checks.count; ++i) {
            if (i) json_raw(&json, ",");
            json_raw(&json, "{\"name\":");
            json_string(&json, checks.items[i].name);
            json_printf(&json, ",\"ok\":%s,\"detail\":", checks.items[i].ok ? "true" : "false");
            json_string(&json, checks.items[i].detail);
            json_raw(&json, "}");
        }
        json_raw(&json, "]");
        json_printf(&json, ",\"timingMs\":%.3f}",
                    (double)(finished.QuadPart - started.QuadPart) * 1000.0 / (double)frequency.QuadPart);
        json_raw(&json, "\n");
        if (json.overflow) {
            exit_code = emit_failure("JSON output buffer overflow", method_utf8);
        } else {
            fwrite(json.buffer, 1, json.length, stdout);
        }
    } else {
        emit_failure(failure, method_utf8);
    }
    if (reference_engine_ready) fn_engine_free(&reference_engine);
    if (candidate_engine_ready) fn_engine_free(&candidate_engine);
    pe_free(&reference_image);
    pe_free(&candidate_image);
    free(method_utf8);
    free(reference_path);
    free(candidate_path);
    LocalFree(argv);
    return exit_code;
}
