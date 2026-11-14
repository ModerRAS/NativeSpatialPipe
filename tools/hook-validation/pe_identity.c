/*
 * NSP hook-validation - method "pe-build-identity"
 *
 * Answers one question only: is the candidate audiodg.exe the same *build* as
 * the pinned reference build, and is it still a valid Microsoft Authenticode
 * image?  It performs no function-level analysis and never locates the hooked
 * function, so "located" is always null and "targetChanged" is always unknown.
 *
 * Build: see Build.ps1 (gcc -lversion -lwintrust -lcrypt32).
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winver.h>
#include <wintrust.h>
#include <softpub.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <string.h>
#include <stdarg.h>

#define NSP_METHOD L"pe-build-identity"
#define MAX_CHECKS 8

/* ------------------------------------------------------------------------- */
/* small growable string buffer                                              */
/* ------------------------------------------------------------------------- */

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} StrBuf;

static void sb_init(StrBuf *sb) {
    sb->cap = 1024;
    sb->len = 0;
    sb->data = (char *)malloc(sb->cap);
    if (!sb->data) {
        fprintf(stderr, "out of memory\n");
        exit(3);
    }
    sb->data[0] = '\0';
}

static void sb_puts(StrBuf *sb, const char *s) {
    size_t n = strlen(s);
    if (sb->len + n + 1 > sb->cap) {
        while (sb->len + n + 1 > sb->cap) sb->cap *= 2;
        char *grown = (char *)realloc(sb->data, sb->cap);
        if (!grown) {
            fprintf(stderr, "out of memory\n");
            exit(3);
        }
        sb->data = grown;
    }
    memcpy(sb->data + sb->len, s, n + 1);
    sb->len += n;
}

static void sb_printf(StrBuf *sb, const char *fmt, ...) {
    char stack[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(stack, sizeof(stack), fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n < sizeof(stack)) {
        sb_puts(sb, stack);
        return;
    }
    char *heap = (char *)malloc((size_t)n + 1);
    if (!heap) {
        fprintf(stderr, "out of memory\n");
        exit(3);
    }
    va_start(ap, fmt);
    vsnprintf(heap, (size_t)n + 1, fmt, ap);
    va_end(ap);
    sb_puts(sb, heap);
    free(heap);
}

/* Append a quoted JSON string from a wide string (UTF-8, RFC 8259 escapes). */
static void sb_put_wjson(StrBuf *sb, const wchar_t *w) {
    if (!w) {
        sb_puts(sb, "null");
        return;
    }
    int need = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    if (need <= 0) {
        sb_puts(sb, "\"\"");
        return;
    }
    char *tmp = (char *)malloc((size_t)need);
    if (!tmp) {
        fprintf(stderr, "out of memory\n");
        exit(3);
    }
    WideCharToMultiByte(CP_UTF8, 0, w, -1, tmp, need, NULL, NULL);
    sb_puts(sb, "\"");
    for (const char *p = tmp; *p; p++) {
        unsigned char ch = (unsigned char)*p;
        switch (ch) {
        case '"':  sb_puts(sb, "\\\""); break;
        case '\\': sb_puts(sb, "\\\\"); break;
        case '\b': sb_puts(sb, "\\b"); break;
        case '\f': sb_puts(sb, "\\f"); break;
        case '\n': sb_puts(sb, "\\n"); break;
        case '\r': sb_puts(sb, "\\r"); break;
        case '\t': sb_puts(sb, "\\t"); break;
        default:
            if (ch < 0x20) sb_printf(sb, "\\u%04x", ch);
            else {
                char one[2] = { (char)ch, '\0' };
                sb_puts(sb, one);
            }
        }
    }
    sb_puts(sb, "\"");
    free(tmp);
}

/* ------------------------------------------------------------------------- */
/* PE build identity                                                         */
/* ------------------------------------------------------------------------- */

typedef struct {
    int parsed;
    DWORD timeDateStamp;
    DWORD sizeOfImage;
    DWORD checksum;
    WORD magic;
    WORD machine;
    ULONGLONG imageBase;
    int hasFileVersion;
    wchar_t fileVersion[64];
    wchar_t buildId[192];
} PeBuild;

/* Read a whole file into memory (caller frees).  Returns 0 on failure. */
static int read_file(const wchar_t *path, BYTE **out, DWORD *outSize) {
    HANDLE f = CreateFileW(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    LARGE_INTEGER size;
    if (!GetFileSizeEx(f, &size) || size.QuadPart <= 0 ||
        size.QuadPart > 0x7fffffffLL) {
        CloseHandle(f);
        return 0;
    }
    DWORD n = (DWORD)size.QuadPart;
    BYTE *buf = (BYTE *)malloc(n);
    if (!buf) {
        CloseHandle(f);
        return 0;
    }
    DWORD got = 0;
    DWORD total = 0;
    while (total < n) {
        if (!ReadFile(f, buf + total, n - total, &got, NULL) || got == 0) break;
        total += got;
    }
    CloseHandle(f);
    if (total != n) {
        free(buf);
        return 0;
    }
    *out = buf;
    *outSize = n;
    return 1;
}

static void read_file_version(PeBuild *b, const wchar_t *path) {
    DWORD handle = 0;
    DWORD size = GetFileVersionInfoSizeW(path, &handle);
    if (!size) return;
    void *data = malloc(size);
    if (!data) return;
    if (GetFileVersionInfoW(path, 0, size, data)) {
        VS_FIXEDFILEINFO *info = NULL;
        UINT len = 0;
        if (VerQueryValueW(data, L"\\", (LPVOID *)&info, &len) &&
            info && len >= sizeof(VS_FIXEDFILEINFO) &&
            info->dwSignature == 0xfeef04bd) {
            swprintf(b->fileVersion, sizeof(b->fileVersion) / sizeof(b->fileVersion[0]),
                     L"%u.%u.%u.%u",
                     (unsigned)HIWORD(info->dwFileVersionMS),
                     (unsigned)LOWORD(info->dwFileVersionMS),
                     (unsigned)HIWORD(info->dwFileVersionLS),
                     (unsigned)LOWORD(info->dwFileVersionLS));
            b->hasFileVersion = 1;
        }
    }
    free(data);
}

static void format_build_id(PeBuild *b) {
    if (b->hasFileVersion) {
        swprintf(b->buildId, sizeof(b->buildId) / sizeof(b->buildId[0]),
                 L"%08lX-%08lX-%08lX-v%s",
                 (unsigned long)b->timeDateStamp,
                 (unsigned long)b->sizeOfImage,
                 (unsigned long)b->checksum,
                 b->fileVersion);
    } else {
        swprintf(b->buildId, sizeof(b->buildId) / sizeof(b->buildId[0]),
                 L"%08lX-%08lX-%08lX",
                 (unsigned long)b->timeDateStamp,
                 (unsigned long)b->sizeOfImage,
                 (unsigned long)b->checksum);
    }
}

static int parse_pe(PeBuild *b, const wchar_t *path, const wchar_t **why) {
    memset(b, 0, sizeof(*b));
    BYTE *data = NULL;
    DWORD size = 0;
    if (!read_file(path, &data, &size)) {
        *why = L"cannot read file";
        return 0;
    }
    const wchar_t *err = NULL;
    do {
        if (size < 0x40 || data[0] != 'M' || data[1] != 'Z') {
            err = L"missing MZ header";
            break;
        }
        DWORD peOff = *(const DWORD *)(data + 0x3c);
        if (peOff > size - 24 || memcmp(data + peOff, "PE\0\0", 4) != 0) {
            err = L"missing PE signature";
            break;
        }
        const BYTE *coff = data + peOff + 4;
        b->machine = *(const WORD *)(coff + 0);
        b->timeDateStamp = *(const DWORD *)(coff + 4);
        WORD optSize = *(const WORD *)(coff + 16);
        DWORD optOff = peOff + 24;
        if (optSize < 68 || optOff > size - 68) {
            err = L"truncated optional header";
            break;
        }
        const BYTE *opt = data + optOff;
        b->magic = *(const WORD *)(opt + 0);
        if (b->magic == 0x20b) {        /* PE32+ */
            b->imageBase = *(const ULONGLONG *)(opt + 24);
        } else if (b->magic == 0x10b) { /* PE32 */
            b->imageBase = *(const DWORD *)(opt + 28);
        } else {
            err = L"unknown optional header magic";
            break;
        }
        b->sizeOfImage = *(const DWORD *)(opt + 56);
        b->checksum = *(const DWORD *)(opt + 64);
        b->parsed = 1;
    } while (0);
    free(data);
    if (!b->parsed) {
        *why = err ? err : L"PE parse failure";
        return 0;
    }
    read_file_version(b, path);
    format_build_id(b);
    return 1;
}

/* ------------------------------------------------------------------------- */
/* Authenticode + Microsoft signer                                           */
/* ------------------------------------------------------------------------- */

typedef enum {
    SIG_VALID = 0,
    SIG_INVALID,
    SIG_UNSIGNED,
    SIG_UNKNOWN
} SigStatus;

static const wchar_t *sig_status_name(SigStatus s) {
    switch (s) {
    case SIG_VALID: return L"valid";
    case SIG_INVALID: return L"invalid";
    case SIG_UNSIGNED: return L"unsigned";
    default: return L"unknown";
    }
}

/* Offline-safe WinVerifyTrust: no network, no revocation fetching. */
static LONG winverifytrust_file(const wchar_t *path) {
    WINTRUST_FILE_INFO fileInfo;
    memset(&fileInfo, 0, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path;

    WINTRUST_DATA data;
    memset(&data, 0, sizeof(data));
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &fileInfo;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(NULL, &action, &data);

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &action, &data);
    return status;
}

static SigStatus classify_trust(LONG status) {
    if (status == ERROR_SUCCESS) return SIG_VALID;
    switch ((DWORD)status) {
    case TRUST_E_NOSIGNATURE:
    case TRUST_E_SUBJECT_FORM_UNKNOWN:
    case TRUST_E_PROVIDER_UNKNOWN:
        return SIG_UNSIGNED;
    case TRUST_E_BAD_DIGEST:
    case TRUST_E_EXPLICIT_DISTRUST:
    case TRUST_E_SUBJECT_NOT_TRUSTED:
    case CERT_E_REVOKED:
    case CERT_E_CHAINING:
        return SIG_INVALID;
    default:
        /* e.g. CERT_E_UNTRUSTEDROOT / CERT_E_REVOCATION_FAILURE: the embedded
         * signature may be cryptographically fine but the chain could not be
         * established offline.  Report unknown instead of guessing. */
        return SIG_UNKNOWN;
    }
}

/* Extract the embedded signer certificate subject (CN/display name). */
static int extract_signer_subject(const wchar_t *path, wchar_t *out,
                                  size_t cch, int *outExtracted) {
    *outExtracted = 0;
    out[0] = L'\0';
    HCERTSTORE store = NULL;
    HCRYPTMSG msg = NULL;
    DWORD encObj = 0, content = 0, format = 0;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path,
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encObj, &content,
                          &format, &store, &msg, NULL)) {
        return 0;
    }
    int ok = 0;
    DWORD need = 0;
    if (CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &need) && need) {
        CMSG_SIGNER_INFO *si = (CMSG_SIGNER_INFO *)malloc(need);
        if (si && CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, si, &need)) {
            CERT_INFO ci;
            memset(&ci, 0, sizeof(ci));
            ci.Issuer = si->Issuer;
            ci.SerialNumber = si->SerialNumber;
            PCCERT_CONTEXT cert = CertFindCertificateInStore(
                store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                CERT_FIND_SUBJECT_CERT, &ci, NULL);
            if (cert) {
                DWORD n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                             0, NULL, out, (DWORD)cch);
                if (n > 1) {
                    ok = 1;
                    *outExtracted = 1;
                }
                CertFreeCertificateContext(cert);
            }
        }
        free(si);
    }
    if (msg) CryptMsgClose(msg);
    if (store) CertCloseStore(store, 0);
    return ok;
}

static int wcsistr(const wchar_t *haystack, const wchar_t *needle) {
    if (!haystack || !needle || !*needle) return 0;
    size_t n = wcslen(needle);
    for (const wchar_t *p = haystack; *p; p++) {
        if (_wcsnicmp(p, needle, n) == 0) return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* checks + result                                                           */
/* ------------------------------------------------------------------------- */

typedef struct {
    const wchar_t *name;
    int ok;
    wchar_t detail[700];
} Check;

typedef struct {
    Check items[MAX_CHECKS];
    int count;
} CheckList;

static void add_check(CheckList *list, const wchar_t *name, int ok,
                      const wchar_t *fmt, ...) {
    if (list->count >= MAX_CHECKS) return;
    Check *c = &list->items[list->count++];
    c->name = name;
    c->ok = ok;
    va_list ap;
    va_start(ap, fmt);
    vswprintf(c->detail, sizeof(c->detail) / sizeof(c->detail[0]), fmt, ap);
    va_end(ap);
}

static void emit_error(const wchar_t *message, int code) {
    StrBuf sb;
    sb_init(&sb);
    sb_puts(&sb, "{\"error\":");
    sb_put_wjson(&sb, message);
    sb_printf(&sb, ",\"method\":");
    sb_put_wjson(&sb, NSP_METHOD);
    sb_puts(&sb, "}\n");
    fputs(sb.data, stdout);
    fflush(stdout);
    free(sb.data);
    exit(code);
}

int wmain(int argc, wchar_t **argv) {
    const wchar_t *method = NULL;
    const wchar_t *refPath = NULL;
    const wchar_t *candPath = NULL;
    int jsonOut = 0;
    int ignoreSignature = 0;

    for (int i = 1; i < argc; i++) {
        if (!wcscmp(argv[i], L"--method")) {
            if (++i >= argc) emit_error(L"--method requires a value", 2);
            method = argv[i];
        } else if (!wcscmp(argv[i], L"--reference")) {
            if (++i >= argc) emit_error(L"--reference requires a path", 2);
            refPath = argv[i];
        } else if (!wcscmp(argv[i], L"--candidate")) {
            if (++i >= argc) emit_error(L"--candidate requires a path", 2);
            candPath = argv[i];
        } else if (!wcscmp(argv[i], L"--json")) {
            jsonOut = 1;
        } else if (!wcscmp(argv[i], L"--ignore-signature")) {
            /* Diagnostic only: reproduce a buildId-only gate (shows what the
             * method alone can see).  Never use this as a security policy. */
            ignoreSignature = 1;
        } else if (!wcscmp(argv[i], L"--help") || !wcscmp(argv[i], L"-h") ||
                   !wcscmp(argv[i], L"/?")) {
            wprintf(L"usage: nsp-hook-validate --method pe-build-identity "
                    L"--reference <ref.exe> --candidate <cand.exe> [--json] "
                    L"[--ignore-signature]\n");
            return 0;
        } else {
            emit_error(L"unknown argument", 2);
        }
    }
    (void)jsonOut;
    if (!method) method = NSP_METHOD;
    if (wcscmp(method, NSP_METHOD))
        emit_error(L"unsupported method (this binary implements pe-build-identity)", 2);
    if (!refPath || !candPath)
        emit_error(L"--reference and --candidate are required", 2);

    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);

    PeBuild refBuild, candBuild;
    const wchar_t *refWhy = L"";
    const wchar_t *candWhy = L"";
    int refOk = parse_pe(&refBuild, refPath, &refWhy);
    int candOk = parse_pe(&candBuild, candPath, &candWhy);

    CheckList checks;
    memset(&checks, 0, sizeof(checks));

    add_check(&checks, L"pe_parse", refOk && candOk,
              L"reference=%ls candidate=%ls",
              refOk ? L"parsed" : refWhy, candOk ? L"parsed" : candWhy);

    /* Per the CLI contract, unreadable/invalid inputs are IO/format errors:
     * emit an error object and a non-zero exit code instead of a decision. */
    if (!refOk || !candOk) {
        wchar_t message[512];
        swprintf(message, sizeof(message) / sizeof(message[0]),
                 L"cannot read/parse PE: reference=%ls candidate=%ls",
                 refOk ? L"ok" : refWhy, candOk ? L"ok" : candWhy);
        emit_error(message, 2);
    }

    if (refOk && candOk) {
        add_check(&checks, L"pe_headers", 1,
                  L"ref magic=0x%lX machine=0x%lX imageBase=0x%llX; "
                  L"cand magic=0x%lX machine=0x%lX imageBase=0x%llX",
                  (unsigned long)refBuild.magic, (unsigned long)refBuild.machine,
                  (unsigned long long)refBuild.imageBase,
                  (unsigned long)candBuild.magic, (unsigned long)candBuild.machine,
                  (unsigned long long)candBuild.imageBase);
    }

    add_check(&checks, L"file_version", candBuild.hasFileVersion,
              L"%ls", candBuild.hasFileVersion ? candBuild.fileVersion
                                               : L"unavailable (fileVersion=null)");

    int buildIdMatch = 0;
    if (refOk && candOk) {
        buildIdMatch = refBuild.timeDateStamp == candBuild.timeDateStamp &&
                       refBuild.sizeOfImage == candBuild.sizeOfImage &&
                       refBuild.checksum == candBuild.checksum;
        if (buildIdMatch && refBuild.hasFileVersion && candBuild.hasFileVersion &&
            wcscmp(refBuild.fileVersion, candBuild.fileVersion) != 0) {
            buildIdMatch = 0;
        }
        add_check(&checks, L"build_id", buildIdMatch,
                  L"reference=%ls candidate=%ls%s",
                  refBuild.buildId, candBuild.buildId,
                  buildIdMatch ? L" (identical build identity)" : L" (different build)");
    } else {
        add_check(&checks, L"build_id", 0, L"cannot compare: PE parse failed");
    }

    /* Authenticode on the candidate (and reference for information). */
    SigStatus candSig = SIG_UNKNOWN;
    SigStatus refSig = SIG_UNKNOWN;
    LONG candTrust = 0, refTrust = 0;
    wchar_t candSubject[256] = L"";
    wchar_t refSubject[256] = L"";
    int candSubjectOk = 0, refSubjectOk = 0;
    long candMs = -1, refMs = -1;

    if (candOk) {
        candTrust = winverifytrust_file(candPath);
        candSig = classify_trust(candTrust);
        extract_signer_subject(candPath, candSubject,
                               sizeof(candSubject) / sizeof(candSubject[0]),
                               &candSubjectOk);
        if (candSig == SIG_VALID && candSubjectOk)
            candMs = wcsistr(candSubject, L"Microsoft") ? 1 : 0;
        add_check(&checks, L"authenticode", candSig == SIG_VALID,
                  L"WinVerifyTrust=0x%08lX status=%ls",
                  (unsigned long)candTrust, sig_status_name(candSig));
        add_check(&checks, L"microsoft_signer",
                  candSig == SIG_VALID && candMs == 1,
                  L"subject=%ls; microsoftSigned=%ls",
                  candSubjectOk ? candSubject : L"<not extractable>",
                  candMs == 1 ? L"true" : (candMs == 0 ? L"false" : L"unknown"));
    } else {
        add_check(&checks, L"authenticode", 0, L"skipped: candidate PE parse failed");
        add_check(&checks, L"microsoft_signer", 0, L"skipped: candidate PE parse failed");
    }

    if (refOk) {
        refTrust = winverifytrust_file(refPath);
        refSig = classify_trust(refTrust);
        extract_signer_subject(refPath, refSubject,
                               sizeof(refSubject) / sizeof(refSubject[0]),
                               &refSubjectOk);
        if (refSig == SIG_VALID && refSubjectOk)
            refMs = wcsistr(refSubject, L"Microsoft") ? 1 : 0;
    }

    /* ---------------- decision -------------------------------------------- */
    const wchar_t *decision = L"unknown";
    wchar_t rationale[700] = L"";
    int sigGateUsed = !ignoreSignature;

    if (!refOk || !candOk) {
        decision = L"unknown";
        swprintf(rationale, 700, L"cannot read/parse PE: reference=%ls candidate=%ls",
                 refOk ? L"ok" : refWhy, candOk ? L"ok" : candWhy);
    } else if (ignoreSignature) {
        if (buildIdMatch) {
            decision = L"allow";
            swprintf(rationale, 700,
                     L"[diagnostic/buildId-only] build identity identical "
                     L"(%ls); signature check disabled. This is exactly the "
                     L"blind spot: same-build byte changes are invisible.",
                     candBuild.buildId);
        } else {
            decision = L"warn";
            swprintf(rationale, 700,
                     L"[diagnostic/buildId-only] build identity differs "
                     L"(ref %ls vs cand %ls); function-level check required.",
                     refBuild.buildId, candBuild.buildId);
        }
    } else if (candSig == SIG_INVALID) {
        decision = L"deny";
        swprintf(rationale, 700,
                 L"candidate Authenticode is invalid (WinVerifyTrust=0x%08lX): "
                 L"the file was modified after signing. build identity %ls.",
                 (unsigned long)candTrust,
                 buildIdMatch ? L"matches the reference" : L"differs from the reference");
    } else if (candSig == SIG_UNSIGNED) {
        decision = L"deny";
        swprintf(rationale, 700,
                 L"candidate carries no Authenticode signature; an in-box "
                 L"audiodg.exe must be Microsoft-signed.");
    } else if (candSig == SIG_UNKNOWN) {
        decision = L"unknown";
        swprintf(rationale, 700,
                 L"candidate signature could not be verified offline "
                 L"(WinVerifyTrust=0x%08lX); trust status unknown.",
                 (unsigned long)candTrust);
    } else if (candMs == 0) {
        decision = L"deny";
        swprintf(rationale, 700,
                 L"candidate is validly signed but the signer (%ls) is not "
                 L"Microsoft; not the pinned in-box audiodg.",
                 candSubjectOk ? candSubject : L"<unknown>");
    } else if (candMs != 1) {
        decision = L"unknown";
        swprintf(rationale, 700,
                 L"candidate signature is valid but the signer identity could "
                 L"not be extracted/classified; cannot confirm Microsoft.");
    } else if (buildIdMatch) {
        decision = L"allow";
        swprintf(rationale, 700,
                 L"build identity identical and Microsoft signature valid. "
                 L"NOTE: this proves build identity + whole-file signature "
                 L"only, not the target function body.");
    } else {
        decision = L"warn";
        swprintf(rationale, 700,
                 L"Microsoft signature valid but the build identity changed "
                 L"(ref %ls vs cand %ls): build changed, function-level "
                 L"validation or manual confirmation required.",
                 refBuild.buildId, candBuild.buildId);
    }

    add_check(&checks, L"signature_gate", sigGateUsed,
              L"%ls", sigGateUsed ? L"enabled (default policy)"
                                  : L"DISABLED via --ignore-signature (diagnostic only)");
    add_check(&checks, L"function_body", 0,
              L"NOT PROVEN: pe-build-identity performs no function-level "
              L"analysis; located=null, targetChanged=unknown. A same-buildId "
              L"candidate could still contain a patched target function if it "
              L"were re-signed (not reproducible offline).");

    QueryPerformanceCounter(&t1);
    double timingMs = (double)(t1.QuadPart - t0.QuadPart) * 1000.0 /
                      (double)freq.QuadPart;

    /* ---------------- JSON output ----------------------------------------- */
    StrBuf sb;
    sb_init(&sb);
    sb_puts(&sb, "{\n  \"method\": ");
    sb_put_wjson(&sb, NSP_METHOD);
    sb_puts(&sb, ",\n  \"reference\": ");
    sb_put_wjson(&sb, refPath);
    sb_puts(&sb, ",\n  \"candidate\": ");
    sb_put_wjson(&sb, candPath);

    sb_puts(&sb, ",\n  \"build\": ");
#define EMIT_BUILD(b)                                                            \
    do {                                                                         \
        sb_puts(&sb, "{");                                                       \
        sb_puts(&sb, "\"fileVersion\": ");                                       \
        if ((b).hasFileVersion) sb_put_wjson(&sb, (b).fileVersion);              \
        else sb_puts(&sb, "null");                                               \
        sb_printf(&sb, ", \"timeDateStamp\": %lu, \"sizeOfImage\": %lu, "        \
                       "\"checksum\": %lu",                                      \
                  (unsigned long)(b).timeDateStamp,                              \
                  (unsigned long)(b).sizeOfImage,                                \
                  (unsigned long)(b).checksum);                                  \
        sb_printf(&sb, ", \"magic\": %lu, \"machine\": %lu, \"imageBase\": %llu", \
                  (unsigned long)(b).magic, (unsigned long)(b).machine,          \
                  (unsigned long long)(b).imageBase);                            \
        if ((b).parsed) {                                                        \
            sb_puts(&sb, ", \"buildId\": ");                                     \
            sb_put_wjson(&sb, (b).buildId);                                      \
        } else {                                                                 \
            sb_puts(&sb, ", \"buildId\": null");                                 \
        }                                                                        \
        sb_puts(&sb, "}");                                                       \
    } while (0)
    EMIT_BUILD(candBuild);
    sb_puts(&sb, ",\n  \"referenceBuild\": ");
    EMIT_BUILD(refBuild);
#undef EMIT_BUILD

    sb_puts(&sb, ",\n  \"buildIdMatch\": ");
    sb_puts(&sb, (refOk && candOk && buildIdMatch) ? "true" : "false");

    sb_puts(&sb, ",\n  \"located\": null");

    sb_puts(&sb, ",\n  \"decision\": ");
    sb_put_wjson(&sb, decision);

    sb_puts(&sb, ",\n  \"targetChanged\": null");

    sb_puts(&sb, ",\n  \"signature\": {");
    sb_puts(&sb, "\"candidateStatus\": ");
    sb_put_wjson(&sb, sig_status_name(candSig));
    sb_printf(&sb, ", \"candidateWinVerifyTrust\": \"0x%08lX\"", (unsigned long)candTrust);
    sb_puts(&sb, ", \"candidateSignerSubject\": ");
    sb_put_wjson(&sb, candSubjectOk ? candSubject : NULL);
    sb_puts(&sb, ", \"candidateMicrosoftSigned\": ");
    sb_puts(&sb, candMs == 1 ? "true" : (candMs == 0 ? "false" : "null"));
    sb_puts(&sb, ", \"referenceStatus\": ");
    sb_put_wjson(&sb, sig_status_name(refSig));
    sb_printf(&sb, ", \"referenceWinVerifyTrust\": \"0x%08lX\"", (unsigned long)refTrust);
    sb_puts(&sb, ", \"referenceSignerSubject\": ");
    sb_put_wjson(&sb, refSubjectOk ? refSubject : NULL);
    sb_puts(&sb, ", \"referenceMicrosoftSigned\": ");
    sb_puts(&sb, refMs == 1 ? "true" : (refMs == 0 ? "false" : "null"));
    sb_puts(&sb, ", \"gateEnabled\": ");
    sb_puts(&sb, sigGateUsed ? "true" : "false");
    sb_puts(&sb, "}");

    sb_puts(&sb, ",\n  \"checks\": [");
    for (int i = 0; i < checks.count; i++) {
        Check *c = &checks.items[i];
        if (i) sb_puts(&sb, ",");
        sb_puts(&sb, "\n    {\"name\": ");
        sb_put_wjson(&sb, c->name);
        sb_puts(&sb, ", \"ok\": ");
        sb_puts(&sb, c->ok ? "true" : "false");
        sb_puts(&sb, ", \"detail\": ");
        sb_put_wjson(&sb, c->detail);
        sb_puts(&sb, "}");
    }
    sb_puts(&sb, "\n  ]");

    sb_puts(&sb, ",\n  \"rationale\": ");
    sb_put_wjson(&sb, rationale);

    sb_printf(&sb, ",\n  \"timingMs\": %.3f\n}\n", timingMs);

    fputs(sb.data, stdout);
    fflush(stdout);
    free(sb.data);
    return 0;
}
