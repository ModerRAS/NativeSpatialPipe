/* nsp-shadow-gate: behavioral shadow validator for the NSP1 capture contract.
 *
 * Build modes:
 *   gcc -O2 -Wall -Wextra -std=c11 shadow_gate.c -o nsp-shadow-gate.exe
 *   gcc -O2 -Wall -Wextra -std=c11 -DNSP_SHADOW_DLL -shared shadow_gate.c -o nsp-shadow-gate.dll
 *
 * The DLL exports two entry points:
 *   nsp_shadow_parts_check(const nsp_shadow_parts *in, nsp_shadow_result *out)
 *   nsp_shadow_check_ex(const unsigned char *slot, size_t len,
 *                       uint64_t prev_sequence, uint64_t prev_qpc_ns,
 *                       unsigned reserved flags (must be 0),
 *                       nsp_shadow_result *out)
 *   nsp_shadow_check(slot, len, out) == nsp_shadow_check_ex(..., UINT64_MAX, UINT64_MAX, 0, out)
 *
 * The validator is a pure data-contract checker: it never reads a PE file and
 * never touches audiodg. It is intended to be run over blocks that a capture
 * hook has already published into the NSP1 shared-memory ring.
 */
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#ifdef _WIN32
#define NSP_EXPORT __declspec(dllexport)
#else
#define NSP_EXPORT
#endif

#define NSP_CAP 16u
#define NSP_MAX_OBJECTS 160u
#define NSP_MAX_FRAMES 4096u
#define NSP_HEADER 8192u
#define NSP_PAYLOAD (NSP_MAX_OBJECTS * (32u + NSP_MAX_FRAMES * 4u))
#define NSP_SLOT (12u + NSP_HEADER + NSP_PAYLOAD)
#define NSP_MAGIC 0x3150534eu
#define NSP_PRODUCTION_FRAMES 480u
#define NSP_FLAG_MASK 0x0000000du /* bit0 | bit2 | bit3 */

enum {
    NSP_OK = 0,
    NSP_E_ARGS = 1,
    NSP_E_COUNT = 2,
    NSP_E_FRAMES = 3,
    NSP_E_STRIDE = 4,
    NSP_E_STRIDE_FRAMES = 5,
    NSP_E_PAYLOAD = 6,
    NSP_E_PROP_FRAMES = 7,
    NSP_E_TYPE = 8,
    NSP_E_XYZ = 9,
    NSP_E_GAIN = 10,
    NSP_E_PCM = 11,
    NSP_E_DUP_BED = 12,
    NSP_E_SEQ = 13,
    NSP_E_QPC = 14,
    NSP_E_SLOT = 15,
    NSP_E_DESCRIPTOR = 16,
    NSP_E_GAIN_RANGE = 17,
    NSP_E_FRAMES_PROD = 18,
    NSP_E_WARN = 19
};

typedef struct nsp_shadow_parts {
    uint32_t count;
    uint32_t frames;
    uint32_t stride;
    uint64_t sequence;
    uint64_t capture_qpc_ns;
    uint64_t prev_sequence; /* UINT64_MAX = no history */
    uint64_t prev_qpc_ns;   /* UINT64_MAX = no history */
    const unsigned char *properties; /* count * 32 */
    size_t properties_len;
    const unsigned char *pcm; /* count * frames * 4 */
    size_t pcm_len;
} nsp_shadow_parts;

#define NSP_MAX_WARN 8
typedef struct nsp_shadow_result {
    uint32_t count;
    uint32_t frames;
    uint32_t stride;
    int32_t ok;
    int32_t code;
    uint32_t checks;
    uint32_t warning_count;
    char detail[512];
    char warnings[NSP_MAX_WARN][48];
} nsp_shadow_result;

typedef struct nsp_shadow_config {
    int strict_frames;    /* frames != 480 becomes an error */
    int strict_gain;      /* gain outside [0,8] becomes an error */
    int warnings_as_error;
} nsp_shadow_config;

static nsp_shadow_config g_cfg = {0, 0, 0};

NSP_EXPORT void nsp_shadow_set_config(int strict_frames, int strict_gain, int warnings_as_error)
{
    g_cfg.strict_frames = strict_frames ? 1 : 0;
    g_cfg.strict_gain = strict_gain ? 1 : 0;
    g_cfg.warnings_as_error = warnings_as_error ? 1 : 0;
}
NSP_EXPORT void nsp_shadow_get_config(int *strict_frames, int *strict_gain, int *warnings_as_error)
{
    if (strict_frames) *strict_frames = g_cfg.strict_frames;
    if (strict_gain) *strict_gain = g_cfg.strict_gain;
    if (warnings_as_error) *warnings_as_error = g_cfg.warnings_as_error;
}

static uint32_t rd_u32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static int f32_finite(uint32_t bits)
{
    return ((bits >> 23) & 0xffu) != 0xffu;
}

#ifndef NSP_SHADOW_DLL
static const char *code_name(int code)
{
    switch (code) {
    case NSP_OK: return "OK";
    case NSP_E_ARGS: return "E_ARGS";
    case NSP_E_COUNT: return "E_COUNT";
    case NSP_E_FRAMES: return "E_FRAMES";
    case NSP_E_STRIDE: return "E_STRIDE";
    case NSP_E_STRIDE_FRAMES: return "E_STRIDE_FRAMES";
    case NSP_E_PAYLOAD: return "E_PAYLOAD";
    case NSP_E_PROP_FRAMES: return "E_PROP_FRAMES";
    case NSP_E_TYPE: return "E_TYPE";
    case NSP_E_XYZ: return "E_XYZ";
    case NSP_E_GAIN: return "E_GAIN";
    case NSP_E_PCM: return "E_PCM";
    case NSP_E_DUP_BED: return "E_DUP_BED";
    case NSP_E_SEQ: return "E_SEQ";
    case NSP_E_QPC: return "E_QPC";
    case NSP_E_SLOT: return "E_SLOT";
    case NSP_E_DESCRIPTOR: return "E_DESCRIPTOR";
    case NSP_E_GAIN_RANGE: return "E_GAIN_RANGE";
    case NSP_E_FRAMES_PROD: return "E_FRAMES_PROD";
    case NSP_E_WARN: return "E_WARN";
    default: return "E_UNKNOWN";
    }
}
#endif /* NSP_SHADOW_DLL: code_name is only used by the CLI report writer */

static int warn_add(nsp_shadow_result *r, const char *fmt, ...)
{
    if (r->warning_count >= NSP_MAX_WARN) {
        return -1;
    }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(r->warnings[r->warning_count], sizeof(r->warnings[0]), fmt, ap);
    va_end(ap);
    r->warning_count++;
    return 0;
}

static int is_bed_type(uint32_t type)
{
    if (type < 2u || type > 4096u) {
        return 0;
    }
    return (type & (type - 1u)) == 0u;
}

/* Core contract check. Never reads outside the supplied buffers. */
NSP_EXPORT int nsp_shadow_parts_check(const nsp_shadow_parts *in, nsp_shadow_result *out)
{
    if (!out) {
        return NSP_E_ARGS;
    }
    memset(out, 0, sizeof(*out));
    out->ok = 0;
    out->code = NSP_E_ARGS;
    out->checks = 0;
    if (!in) {
        snprintf(out->detail, sizeof(out->detail), "null request");
        return out->code;
    }
    out->count = in->count;
    out->frames = in->frames;
    out->stride = in->stride;
    if (!in->properties && in->count) {
        snprintf(out->detail, sizeof(out->detail), "null properties");
        return out->code;
    }
    if (!in->pcm && in->count && in->frames) {
        snprintf(out->detail, sizeof(out->detail), "null pcm");
        return out->code;
    }

    #define CHECK() (out->checks++)
    #define FAIL(c, ...) do { out->ok = 0; out->code = (c); \
        snprintf(out->detail, sizeof(out->detail), __VA_ARGS__); \
        return out->code; } while (0)

    CHECK();
    if (in->count < 1u || in->count > NSP_MAX_OBJECTS) {
        FAIL(NSP_E_COUNT, "count %u outside [1,160]", in->count);
    }
    CHECK();
    if (in->frames < 1u || in->frames > NSP_MAX_FRAMES) {
        FAIL(NSP_E_FRAMES, "frames %u outside [1,4096]", in->frames);
    }
    CHECK();
    if (in->stride < 4u || in->stride > 16384u || (in->stride % 4u) != 0u) {
        FAIL(NSP_E_STRIDE, "stride %u outside [4,16384] or not 4-byte aligned", in->stride);
    }
    CHECK();
    if (in->frames * 4u > in->stride) {
        FAIL(NSP_E_STRIDE_FRAMES, "frames*4 (%u) exceeds stride %u", in->frames * 4u, in->stride);
    }
    CHECK();
    if (in->properties_len != (size_t)in->count * 32u) {
        FAIL(NSP_E_PAYLOAD, "property payload %zu != count(%u)*32", in->properties_len, in->count);
    }
    CHECK();
    if (in->pcm_len != (size_t)in->count * (size_t)in->frames * 4u) {
        FAIL(NSP_E_PAYLOAD, "pcm payload %zu != count(%u)*frames(%u)*4", in->pcm_len, in->count, in->frames);
    }

    unsigned seen_bed[12];
    memset(seen_bed, 0, sizeof(seen_bed));
    for (uint32_t i = 0; i < in->count; i++) {
        const unsigned char *p = in->properties + (size_t)i * 32u;
        uint32_t frames = rd_u32(p + 4u);
        uint32_t type = rd_u32(p + 8u);
        uint32_t flags = rd_u32(p + 12u);
        uint32_t gain = rd_u32(p + 28u);
        CHECK();
        if (frames != in->frames) {
            FAIL(NSP_E_PROP_FRAMES, "property[%u].frames %u != block frames %u", i, frames, in->frames);
        }
        CHECK();
        if (type != 1u && !is_bed_type(type)) {
            FAIL(NSP_E_TYPE, "property[%u].type 0x%x is neither dynamic(1) nor bed power-of-two 2..4096", i, type);
        }
        CHECK();
        if ((flags & ~NSP_FLAG_MASK) != 0u) {
            warn_add(out, "flags[%u]=0x%x has reserved bits", i, flags & ~NSP_FLAG_MASK);
        }
        for (int k = 0; k < 3; k++) {
            CHECK();
            if (!f32_finite(rd_u32(p + 16u + (uint32_t)k * 4u))) {
                FAIL(NSP_E_XYZ, "property[%u].xyz[%d] is not finite", i, k);
            }
        }
        CHECK();
        if (!f32_finite(gain)) {
            FAIL(NSP_E_GAIN, "property[%u].gain is not finite", i);
        }
        float g;
        uint32_t gb = gain;
        memcpy(&g, &gb, sizeof(g));
        CHECK();
        if (g < 0.0f || g > 8.0f) {
            if (g_cfg.strict_gain) {
                FAIL(NSP_E_GAIN_RANGE, "property[%u].gain %.6g outside strict [0,8]", i, (double)g);
            }
            warn_add(out, "gain[%u]=%.6g outside [0,8]", i, (double)g);
        }
        if (type != 1u) {
            uint32_t index = 0, t = type;
            while (t > 1u) { t >>= 1; index++; }
            index -= 1u; /* 2 -> 0 ... 4096 -> 11 */
            CHECK();
            if (index < 12u && seen_bed[index]) {
                FAIL(NSP_E_DUP_BED, "duplicate bed type 0x%x at property[%u]", type, i);
            }
            if (index < 12u) {
                seen_bed[index] = 1;
            }
        }
    }

    const unsigned char *pcm = in->pcm;
    for (size_t b = 0; b + 4u <= in->pcm_len; b += 4u) {
        CHECK();
        if (!f32_finite(rd_u32(pcm + b))) {
            FAIL(NSP_E_PCM, "pcm f32 at byte %zu is not finite", b);
        }
    }

    if (in->prev_sequence != UINT64_MAX) {
        CHECK();
        if (in->sequence != in->prev_sequence + 1u) {
            FAIL(NSP_E_SEQ, "sequence %llu is not prev(%llu)+1",
                 (unsigned long long)in->sequence, (unsigned long long)in->prev_sequence);
        }
    }
    if (in->prev_qpc_ns != UINT64_MAX) {
        CHECK();
        if (in->capture_qpc_ns < in->prev_qpc_ns) {
            FAIL(NSP_E_QPC, "captureQpcNs %llu moved backwards from %llu",
                 (unsigned long long)in->capture_qpc_ns, (unsigned long long)in->prev_qpc_ns);
        }
    }
    CHECK();
    if (in->frames != NSP_PRODUCTION_FRAMES) {
        if (g_cfg.strict_frames) {
            FAIL(NSP_E_FRAMES_PROD, "frames %u != production 480 (strict)", in->frames);
        }
        warn_add(out, "frames=%u (production expects 480)", in->frames);
    }
    if (g_cfg.warnings_as_error && out->warning_count > 0u) {
        FAIL(NSP_E_WARN, "%u warning(s) promoted to error", out->warning_count);
    }

    out->ok = 1;
    out->code = NSP_OK;
    snprintf(out->detail, sizeof(out->detail), "OK count=%u frames=%u stride=%u checks=%u warnings=%u",
             out->count, out->frames, out->stride, out->checks, out->warning_count);
    return NSP_OK;
}

/* ---- Minimal descriptor extraction (only the keys the NSP1 wire format emits). ---- */
static const char *json_find_key(const char *json, size_t len, const char *key)
{
    size_t klen = strlen(key);
    for (size_t i = 0; i + klen + 2u < len; i++) {
        if (json[i] != '"') continue;
        if (memcmp(json + i + 1u, key, klen) != 0) continue;
        if (json[i + 1u + klen] != '"') continue;
        size_t j = i + 2u + klen;
        while (j < len && (json[j] == ' ' || json[j] == '\t' || json[j] == '\r' || json[j] == '\n')) j++;
        if (j >= len || json[j] != ':') continue;
        j++;
        while (j < len && (json[j] == ' ' || json[j] == '\t' || json[j] == '\r' || json[j] == '\n')) j++;
        return json + j;
    }
    return NULL;
}
static int json_u64(const char *json, size_t len, const char *key, uint64_t *out)
{
    const char *p = json_find_key(json, len, key);
    if (!p) return 0;
    char *end = NULL;
    unsigned long long v = strtoull(p, &end, 0);
    if (end == p || end > json + len) return 0;
    *out = (uint64_t)v;
    return 1;
}
static int json_frames_array(const char *json, size_t len, uint32_t *frames, uint32_t *count)
{
    const char *p = json_find_key(json, len, "frames");
    if (!p || *p != '[') return 0;
    p++;
    uint32_t n = 0, first = 0, uniform = 1;
    for (;;) {
        while (p < json + len && (*p == ' ' || *p == ',' || *p == '\t')) p++;
        if (p >= json + len) return 0;
        if (*p == ']') break;
        char *end = NULL;
        unsigned long v = strtoul(p, &end, 10);
        if (end == p) return 0;
        if (n == 0) first = (uint32_t)v;
        else if ((uint32_t)v != first) uniform = 0;
        n++;
        p = end;
        if (n > NSP_MAX_OBJECTS) return 0;
    }
    if (n == 0 || !uniform) return 0;
    *frames = first;
    *count = n;
    return 1;
}

/* Raw NSP1 slot: ready(4) | nh(4) | nd(4) | header[8192] | payload. */
NSP_EXPORT int nsp_shadow_check_ex(const unsigned char *slot, size_t len,
                                   uint64_t prev_sequence, uint64_t prev_qpc_ns,
                                   unsigned reserved, nsp_shadow_result *out)
{
    (void)reserved;
    if (!out) return NSP_E_ARGS;
    memset(out, 0, sizeof(*out));
    out->code = NSP_E_SLOT;
    if (!slot || len < 12u + NSP_HEADER) {
        snprintf(out->detail, sizeof(out->detail), "slot too small: %zu", len);
        return out->code;
    }
    uint32_t ready = rd_u32(slot);
    uint32_t nh = rd_u32(slot + 4u);
    uint32_t nd = rd_u32(slot + 8u);
    if (ready != 1u) {
        snprintf(out->detail, sizeof(out->detail), "slot ready=%u (expected 1)", ready);
        return out->code;
    }
    if (nh == 0u || nh > NSP_HEADER || nd == 0u || (size_t)nd > len - 12u - NSP_HEADER) {
        snprintf(out->detail, sizeof(out->detail), "invalid nh=%u nd=%u len=%zu", nh, nd, len);
        return out->code;
    }
    const unsigned char *payload = slot + 12u + NSP_HEADER;
    if (nd > NSP_PAYLOAD) {
        snprintf(out->detail, sizeof(out->detail), "nd %u > payload cap %u", nd, NSP_PAYLOAD);
        return out->code;
    }
    char header[NSP_HEADER + 1u];
    memcpy(header, slot + 12u, nh);
    header[nh] = '\0';

    uint64_t sequence = 0, qpc = 0, copy_done = 0, send_ns = 0;
    uint32_t count = 0, frames = 0, stride = 0;
    uint32_t frames_array_count = 0;
    out->code = NSP_E_DESCRIPTOR;
    if (!json_u64(header, nh, "sequence", &sequence)) {
        snprintf(out->detail, sizeof(out->detail), "descriptor missing sequence");
        return out->code;
    }
    {
        uint64_t v = 0;
        if (!json_u64(header, nh, "count", &v) || v < 1u || v > 255u) {
            snprintf(out->detail, sizeof(out->detail), "descriptor missing/invalid count");
            return out->code;
        }
        count = (uint32_t)v;
    }
    if (!json_u64(header, nh, "captureQpcNs", &qpc)) {
        snprintf(out->detail, sizeof(out->detail), "descriptor missing captureQpcNs");
        return out->code;
    }
    {
        uint64_t v = 0;
        if (json_u64(header, nh, "framesUniform", &v)) {
            frames = (uint32_t)v;
            frames_array_count = count;
        } else if (!json_frames_array(header, nh, &frames, &frames_array_count)) {
            snprintf(out->detail, sizeof(out->detail), "descriptor has no usable frames/framesUniform");
            return out->code;
        }
        if (frames_array_count != count) {
            snprintf(out->detail, sizeof(out->detail), "descriptor count %u != frames entries %u", count, frames_array_count);
            return out->code;
        }
        if (json_u64(header, nh, "stride", &v)) stride = (uint32_t)v;
        else stride = count ? frames * 4u : 0u;
    }
    {
        uint64_t v = 0;
        if (json_u64(header, nh, "copyDoneQpcNs", &v)) copy_done = v;
        if (json_u64(header, nh, "sendQpcNs", &v)) send_ns = v;
        if ((copy_done && copy_done < qpc) || (send_ns && send_ns < copy_done)) {
            memset(out, 0, sizeof(*out));
            out->ok = 0; out->code = NSP_E_QPC;
            snprintf(out->detail, sizeof(out->detail), "descriptor timestamps not ordered qpc<=copyDone<=send");
            return out->code;
        }
    }

    nsp_shadow_parts parts;
    memset(&parts, 0, sizeof(parts));
    parts.count = count;
    parts.frames = frames;
    parts.stride = stride;
    parts.sequence = sequence;
    parts.capture_qpc_ns = qpc;
    parts.prev_sequence = prev_sequence;
    parts.prev_qpc_ns = prev_qpc_ns;
    size_t props_avail = (size_t)nd < (size_t)count * 32u ? (size_t)nd : (size_t)count * 32u;
    parts.properties = payload;
    parts.properties_len = props_avail;
    parts.pcm = payload + props_avail;
    parts.pcm_len = (size_t)nd - props_avail;
    int rc = nsp_shadow_parts_check(&parts, out);
    return rc;
}

NSP_EXPORT int nsp_shadow_check(const unsigned char *slot, size_t len, nsp_shadow_result *out)
{
    return nsp_shadow_check_ex(slot, len, UINT64_MAX, UINT64_MAX, 0u, out);
}

/* ============================== CLI ============================== */
#ifndef NSP_SHADOW_DLL

static char *read_line(FILE *f, size_t *cap)
{
    size_t n = 0;
    if (*cap == 0) { *cap = 1u << 20; }
    char *buf = (char *)malloc(*cap);
    if (!buf) return NULL;
    int ch;
    while ((ch = fgetc(f)) != EOF) {
        if (n + 2u > *cap) {
            size_t next = *cap * 2u;
            char *grown = (char *)realloc(buf, next);
            if (!grown) { free(buf); return NULL; }
            buf = grown;
            *cap = next;
        }
        buf[n++] = (char)ch;
        if (ch == '\n') break;
    }
    if (n == 0) { free(buf); return NULL; }
    buf[n] = '\0';
    return buf;
}

static const char *line_key(const char *line, const char *key)
{
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(line, pat);
    if (!p) return NULL;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t') p++;
    if (*p != ':') return NULL;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    return p;
}
static int line_string(const char *line, const char *key, char *dst, size_t cap)
{
    const char *p = line_key(line, key);
    if (!p || *p != '"') return 0;
    p++;
    size_t n = 0;
    while (*p && *p != '"') {
        char c = *p++;
        if (c == '\\' && *p) {
            char e = *p++;
            switch (e) {
            case 'n': c = '\n'; break;
            case 't': c = '\t'; break;
            case 'r': c = '\r'; break;
            default: c = e; break;
            }
        }
        if (n + 1u < cap) dst[n++] = c;
    }
    if (*p != '"') return 0;
    dst[n] = '\0';
    return 1;
}
static int line_u64(const char *line, const char *key, uint64_t *out)
{
    const char *p = line_key(line, key);
    if (!p) return 0;
    char *end = NULL;
    unsigned long long v = strtoull(p, &end, 0);
    if (end == p) return 0;
    *out = (uint64_t)v;
    return 1;
}
static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
/* Decode a JSON array of hex strings into dst. Returns item count, sets *bytes. */
static size_t parse_hex_array(const char *value, unsigned char *dst, size_t dst_cap, size_t *bytes)
{
    size_t items = 0, total = 0;
    const char *p = value;
    if (!p || *p != '[') { *bytes = 0; return 0; }
    p++;
    for (;;) {
        while (*p == ' ' || *p == ',' || *p == '\t') p++;
        if (!*p) break;
        if (*p == ']') break;
        if (*p != '"') break;
        p++;
        while (*p && *p != '"') {
            int hi = hexval((unsigned char)p[0]);
            int lo = p[0] ? hexval((unsigned char)p[1]) : -1;
            if (hi < 0 || lo < 0) { *bytes = total; return items; }
            if (total < dst_cap) dst[total] = (unsigned char)((hi << 4) | lo);
            total++;
            p += 2;
        }
        if (*p == '"') p++;
        items++;
    }
    *bytes = total;
    return items;
}

static void json_escape(char *dst, size_t cap, const char *src)
{
    size_t n = 0;
    for (; *src && n + 7u < cap; src++) {
        unsigned char c = (unsigned char)*src;
        if (c == '"' || c == '\\') { dst[n++] = '\\'; dst[n++] = (char)c; }
        else if (c == '\n') { memcpy(dst + n, "\\n", 2); n += 2; }
        else if (c == '\r') { memcpy(dst + n, "\\r", 2); n += 2; }
        else if (c == '\t') { memcpy(dst + n, "\\t", 2); n += 2; }
        else if (c < 0x20) { snprintf(dst + n, cap - n, "\\u%04x", c); n += 6; }
        else dst[n++] = (char)c;
    }
    dst[n] = '\0';
}

typedef struct case_result {
    char name[96];
    char expect[32];
    int expected_ok;
    int expected_code;
    nsp_shadow_result r;
    int matched;
} case_result;

static int expect_match(const char *expect, const nsp_shadow_result *r)
{
    if (strcmp(expect, "ok") == 0) return r->ok ? 1 : 0;
    if (strcmp(expect, "reject") == 0) return r->ok ? 0 : 1;
    if (strncmp(expect, "reject:", 7) == 0) {
        return (!r->ok && r->code == atoi(expect + 7)) ? 1 : 0;
    }
    return 0;
}

static int bench_mode(unsigned iterations, unsigned count, unsigned frames)
{
    if (count < 1u || count > NSP_MAX_OBJECTS || frames < 1u || frames > NSP_MAX_FRAMES) {
        fprintf(stderr, "invalid bench geometry\n");
        return 1;
    }
    size_t props_len = (size_t)count * 32u;
    size_t pcm_len = (size_t)count * (size_t)frames * 4u;
    unsigned char *props = (unsigned char *)calloc(1, props_len);
    unsigned char *pcm = (unsigned char *)calloc(1, pcm_len);
    if (!props || !pcm) { free(props); free(pcm); fprintf(stderr, "oom\n"); return 1; }
    for (uint32_t i = 0; i < count; i++) {
        unsigned char *p = props + (size_t)i * 32u;
        uint32_t frames_bits = frames, type = (i < 12u) ? (2u << i) : 1u;
        memcpy(p, &i, 4); memcpy(p + 4, &frames_bits, 4); memcpy(p + 8, &type, 4);
        /* little-endian host assumed (Windows x64) */
        float x = 0.25f + 0.001f * (float)i;
        memcpy(p + 16, &x, 4); memcpy(p + 20, &x, 4); memcpy(p + 24, &x, 4);
        float gain = 1.0f; memcpy(p + 28, &gain, 4);
    }
    nsp_shadow_parts parts;
    memset(&parts, 0, sizeof(parts));
    parts.count = count; parts.frames = frames; parts.stride = frames * 4u;
    parts.sequence = 100; parts.capture_qpc_ns = 1000u;
    parts.prev_sequence = UINT64_MAX; parts.prev_qpc_ns = UINT64_MAX;
    parts.properties = props; parts.properties_len = props_len;
    parts.pcm = pcm; parts.pcm_len = pcm_len;
    nsp_shadow_result r;
    if (nsp_shadow_parts_check(&parts, &r) != NSP_OK) {
        fprintf(stderr, "bench block invalid: %s\n", r.detail);
        free(props); free(pcm);
        return 1;
    }
    clock_t begin = clock();
    for (unsigned i = 0; i < iterations; i++) {
        parts.sequence = 100u + i;
        nsp_shadow_parts_check(&parts, &r);
    }
    clock_t end = clock();
    double secs = (double)(end - begin) / (double)CLOCKS_PER_SEC;
    if (secs <= 0.0) secs = 1e-9;
    printf("{\"tool\":\"nsp-shadow-gate\",\"benchmark\":{\"iterations\":%u,\"count\":%u,\"frames\":%u,"
           "\"elapsedMs\":%.3f,\"blocksPerSecond\":%.0f,\"usPerBlock\":%.2f}}\n",
           iterations, count, frames, secs * 1000.0, (double)iterations / secs,
           secs * 1e6 / (double)iterations);
    free(props); free(pcm);
    return 0;
}

int main(int argc, char **argv)
{
    const char *fixtures = NULL, *report = NULL;
    unsigned bench = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--fixtures") == 0 && i + 1 < argc) fixtures = argv[++i];
        else if (strcmp(argv[i], "--report") == 0 && i + 1 < argc) report = argv[++i];
        else if (strcmp(argv[i], "--bench") == 0 && i + 1 < argc) bench = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--strict-frames") == 0) g_cfg.strict_frames = 1;
        else if (strcmp(argv[i], "--strict-gain") == 0) g_cfg.strict_gain = 1;
        else if (strcmp(argv[i], "--warnings-as-errors") == 0) g_cfg.warnings_as_error = 1;
        else {
            fprintf(stderr, "usage: nsp-shadow-gate --fixtures <in.jsonl> [--report <out.json>] "
                            "[--strict-frames] [--strict-gain] [--warnings-as-errors] | --bench <n>\n");
            return 1;
        }
    }
    if (bench) return bench_mode(bench, NSP_MAX_OBJECTS, NSP_PRODUCTION_FRAMES);
    if (!fixtures) {
        fprintf(stderr, "missing --fixtures\n");
        return 1;
    }
    FILE *f = fopen(fixtures, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", fixtures); return 1; }

    size_t cap = 0, line_cap = 0;
    char *line = NULL;
    case_result *cases = NULL;
    size_t case_count = 0;
    clock_t begin = clock();

    unsigned char *properties = (unsigned char *)malloc((NSP_MAX_OBJECTS + 8u) * 32u);
    unsigned char *pcm = (unsigned char *)malloc((size_t)(NSP_MAX_OBJECTS + 8u) * 4096u * 4u);
    if (!properties || !pcm) { fprintf(stderr, "oom\n"); return 1; }

    while ((line = read_line(f, &line_cap)) != NULL) {
        (void)cap;
        char *start = line;
        while (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n') start++;
        if (*start == '\0' || *start == '#') { free(line); continue; }
        char name[96] = "", expect[32] = "ok";
        uint64_t sequence = 0, qpc = 0, prev_seq = UINT64_MAX, prev_qpc = UINT64_MAX;
        uint64_t count = 0, frames = 0, stride = 0;
        if (!line_string(start, "name", name, sizeof(name))) snprintf(name, sizeof(name), "case_%zu", case_count);
        line_string(start, "expect", expect, sizeof(expect));
        if (line_u64(start, "sequence", &sequence)) { }
        line_u64(start, "captureQpcNs", &qpc);
        line_u64(start, "prevSequence", &prev_seq);
        line_u64(start, "prevQpcNs", &prev_qpc);
        line_u64(start, "count", &count);
        line_u64(start, "frames", &frames);
        line_u64(start, "stride", &stride);

        nsp_shadow_parts parts;
        memset(&parts, 0, sizeof(parts));
        parts.count = (uint32_t)count;
        parts.frames = (uint32_t)frames;
        parts.stride = (uint32_t)stride;
        parts.sequence = sequence;
        parts.capture_qpc_ns = qpc;
        parts.prev_sequence = prev_seq;
        parts.prev_qpc_ns = prev_qpc;
        parts.properties = properties;
        parts.pcm = pcm;

        const char *pv = line_key(start, "properties");
        size_t prop_bytes = 0;
        parse_hex_array(pv, properties, (NSP_MAX_OBJECTS + 8u) * 32u, &prop_bytes);
        parts.properties_len = prop_bytes;
        pv = line_key(start, "pcm");
        size_t pcm_bytes = 0;
        parse_hex_array(pv, pcm, (size_t)(NSP_MAX_OBJECTS + 8u) * 4096u * 4u, &pcm_bytes);
        parts.pcm_len = pcm_bytes;

        case_result *grown = (case_result *)realloc(cases, (case_count + 1u) * sizeof(case_result));
        if (!grown) { fprintf(stderr, "oom\n"); return 1; }
        cases = grown;
        case_result *c = &cases[case_count];
        memset(c, 0, sizeof(*c));
        snprintf(c->name, sizeof(c->name), "%s", name);
        snprintf(c->expect, sizeof(c->expect), "%s", expect);
        nsp_shadow_parts_check(&parts, &c->r);
        c->matched = expect_match(expect, &c->r);
        case_count++;
        free(line);
    }
    fclose(f);
    clock_t end = clock();
    double secs = (double)(end - begin) / (double)CLOCKS_PER_SEC;
    if (secs <= 0.0) secs = 1e-9;

    size_t passed = 0, failed = 0, ok_cases = 0, reject_cases = 0, warnings = 0, expected_ok = 0;
    for (size_t i = 0; i < case_count; i++) {
        if (cases[i].matched) passed++; else failed++;
        if (cases[i].r.ok) ok_cases++; else reject_cases++;
        if (strcmp(cases[i].expect, "ok") == 0) expected_ok++;
        warnings += cases[i].r.warning_count;
    }

    FILE *out = report ? fopen(report, "wb") : stdout;
    if (!out) { fprintf(stderr, "cannot write %s\n", report); return 1; }
    fprintf(out, "{\"tool\":\"nsp-shadow-gate\",\"method\":\"behavioral-shadow\",\"contract\":\"NSP1\",");
    fprintf(out, "\"config\":{\"strictFrames\":%d,\"strictGain\":%d,\"warningsAsError\":%d},",
            g_cfg.strict_frames, g_cfg.strict_gain, g_cfg.warnings_as_error);
    fprintf(out, "\"totals\":{\"cases\":%zu,\"passed\":%zu,\"failed\":%zu,\"expectedOk\":%zu,"
                 "\"expectedReject\":%zu,\"okCases\":%zu,\"rejectCases\":%zu,\"warnings\":%zu},",
            case_count, passed, failed, expected_ok, case_count - expected_ok, ok_cases, reject_cases, warnings);
    fprintf(out, "\"elapsedMs\":%.3f,\"blocksPerSecond\":%.1f,\"cases\":[",
            secs * 1000.0, (double)case_count / secs);
    for (size_t i = 0; i < case_count; i++) {
        case_result *c = &cases[i];
        char detail[1024], name[256];
        json_escape(detail, sizeof(detail), c->r.detail);
        json_escape(name, sizeof(name), c->name);
        fprintf(out, "%s{\"name\":\"%s\",\"expect\":\"%s\",\"expectedOk\":%d,\"ok\":%s,\"code\":%d,"
                     "\"codeName\":\"%s\",\"matched\":%s,\"detail\":\"%s\",\"warnings\":[",
                i ? "," : "", name, c->expect, strcmp(c->expect, "ok") == 0, c->r.ok ? "true" : "false",
                c->r.code, code_name(c->r.code), c->matched ? "true" : "false", detail);
        for (uint32_t w = 0; w < c->r.warning_count; w++) {
            char esc[128];
            json_escape(esc, sizeof(esc), c->r.warnings[w]);
            fprintf(out, "%s\"%s\"", w ? "," : "", esc);
        }
        fprintf(out, "],\"stats\":{\"count\":%u,\"frames\":%u,\"stride\":%u,\"checks\":%u}}",
                c->r.count, c->r.frames, c->r.stride, c->r.checks);
    }
    fprintf(out, "]}\n");
    if (report) fclose(out);
    free(cases);
    free(properties);
    free(pcm);
    return failed == 0 ? 0 : 3;
}
#endif /* NSP_SHADOW_DLL */
