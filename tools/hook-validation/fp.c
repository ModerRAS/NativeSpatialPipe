#include "fp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>
#include <bcrypt.h>

int fp_sha256(const void *data, size_t len, uint8_t out[32]) {
  BCRYPT_ALG_HANDLE alg = NULL;
  BCRYPT_HASH_HANDLE hash = NULL;
  NTSTATUS st;
  DWORD objLen = 0, resultLen = 0, hashLen = 0, hashObjLen = 0;
  uint8_t *hashObj = NULL;
  int rc = -1;
  st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
  if (!BCRYPT_SUCCESS(st)) return -1;
  if (!BCRYPT_SUCCESS(BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &resultLen, 0))) goto done;
  if (!BCRYPT_SUCCESS(BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &resultLen, 0))) goto done;
  if (hashLen != 32) goto done;
  hashObjLen = objLen;
  hashObj = (uint8_t *)malloc(hashObjLen);
  if (!hashObj) goto done;
  if (!BCRYPT_SUCCESS(BCryptCreateHash(alg, &hash, hashObj, hashObjLen, NULL, 0, 0))) goto done;
  if (len && !BCRYPT_SUCCESS(BCryptHashData(hash, (PUCHAR)data, (ULONG)len, 0))) goto done;
  if (!BCRYPT_SUCCESS(BCryptFinishHash(hash, out, 32, 0))) goto done;
  rc = 0;
done:
  if (hash) BCryptDestroyHash(hash);
  if (alg) BCryptCloseAlgorithmProvider(alg, 0);
  free(hashObj);
  return rc;
}

void fp_hex(const uint8_t *data, size_t len, char *out) {
  size_t i;
  static const char *digits = "0123456789abcdef";
  for (i = 0; i < len; i++) {
    out[i * 2] = digits[data[i] >> 4];
    out[i * 2 + 1] = digits[data[i] & 15];
  }
  out[len * 2] = 0;
}

/* Bytes that drift between builds of the same function: rel32 (call/jmp/jcc) and
 * RIP-relative disp32 operands. They are wildcarded in the generated AOBs so the
 * pattern survives a rebuild that moves callees/data around. */
static void mark_unstable(const uint8_t *body, uint32_t n, uint8_t *mask) {
  uint32_t i;
  for (i = 0; i < n; i++) {
    uint32_t start = 0;
    int have = 0;
    uint8_t b = body[i];
    if (b == 0xe8 || b == 0xe9) { start = i + 1; have = 1; }
    else if (b == 0x0f && i + 1 < n && body[i + 1] >= 0x80 && body[i + 1] <= 0x8f) { start = i + 2; have = 1; }
    else if (b == 0x48 && i + 2 < n && (body[i + 1] == 0x8d || body[i + 1] == 0x8b) &&
             (body[i + 2] & 0xc7) == 0x05) { start = i + 3; have = 1; }
    else if ((b == 0xf6 || b == 0xf7) && i + 1 < n && body[i + 1] == 0x05) { start = i + 2; have = 1; }
    if (have) {
      uint32_t j;
      for (j = start; j < start + 4 && j < n; j++) mask[j] = 1;
    }
  }
}

int fp_generate_aobs(const PeImage *img, uint32_t rva, uint32_t size, Aob *out, int maxAobs) {
  uint8_t *body = NULL, *mask = NULL;
  uint32_t off = 0, i;
  int band, produced = 0;
  const uint32_t win = FP_AOB_LEN;
  if (!img || size < win * 2 || size > 0x10000) return -1;
  if (pe_rva_off(img, rva, size, &off) != 0) return -1;
  body = img->data + off;
  mask = (uint8_t *)calloc(size, 1);
  if (!mask) return -1;
  mark_unstable(body, size, mask);
  for (i = 0; i < size; i++)
    if (pe_reloc_byte(img, rva + i)) mask[i] = 1;

  for (band = 0; band < maxAobs; band++) {
    uint32_t span = (size - win + 1) / (uint32_t)maxAobs;
    uint32_t lo = (uint32_t)band * span;
    uint32_t hi = (band == maxAobs - 1) ? (size - win + 1) : lo + span;
    uint32_t bestOff = 0, bestMasked = 0xffffffff, bestDistinct = 0;
    int have = 0;
    for (off = lo; off < hi; off++) {
      uint32_t masked = 0, distinct = 0, j, k;
      for (j = 0; j < win; j++) if (mask[off + j]) masked++;
      if (masked > 6) continue;
      for (j = 0; j < win; j++) {
        int seen = 0;
        for (k = 0; k < j; k++) if (body[off + k] == body[off + j]) { seen = 1; break; }
        if (!seen) distinct++;
      }
      if (!have || masked < bestMasked || (masked == bestMasked && distinct > bestDistinct)) {
        have = 1;
        bestOff = off;
        bestMasked = masked;
        bestDistinct = distinct;
      }
    }
    if (!have) break;
    out[produced].offset = bestOff;
    out[produced].len = (uint16_t)win;
    for (i = 0; i < win; i++) {
      out[produced].pat[i] = body[bestOff + i];
      out[produced].wild[i] = mask[bestOff + i] ? 1 : 0;
    }
    produced++;
  }
  free(mask);
  return produced > 0 ? produced : -1;
}

int fp_aob_match(const Aob *aob, const uint8_t *body, uint32_t len, int tolerance, AobMatch *out) {
  uint32_t pos, i;
  memset(out, 0, sizeof(*out));
  if (!aob || aob->len == 0 || len < aob->len) return -1;
  for (pos = 0; pos + aob->len <= len; pos++) {
    int mism = 0;
    for (i = 0; i < aob->len; i++) {
      if (aob->wild[i]) continue;
      if (body[pos + i] != aob->pat[i]) {
        mism++;
        if (mism > tolerance) break;
      }
    }
    if (mism == 0) {
      out->exact++;
      if (out->bestMismatch != 0) { out->bestMismatch = 0; out->bestPos = pos; }
      else if (out->bestPos == 0 && out->exact == 1) out->bestPos = pos;
    } else if (mism <= tolerance) {
      out->tolerant++;
      if (out->bestMismatch == 0 || mism < out->bestMismatch) { out->bestMismatch = mism; out->bestPos = pos; }
    }
  }
  if (out->exact) out->bestMismatch = 0;
  return out->exact + out->tolerant;
}

void fp_similarity(const PeImage *refImg, uint32_t refRva, uint32_t refSize,
                   const uint8_t *candBody, uint32_t candLen, Similarity *out) {
  uint32_t refOff = 0, i, n;
  const uint8_t *refBody;
  int runStart = -1;
  memset(out, 0, sizeof(*out));
  if (!refImg || pe_rva_off(refImg, refRva, refSize, &refOff) != 0) return;
  refBody = refImg->data + refOff;
  n = refSize < candLen ? refSize : candLen;
  for (i = 0; i < n; i++) {
    int masked = pe_reloc_byte(refImg, refRva + i);
    int different;
    if (masked) { out->skipped++; different = 0; }
    else {
      out->compared++;
      different = refBody[i] != candBody[i];
    }
    if (different) {
      out->diffBytes++;
      if (runStart < 0) runStart = (int)i;
    } else {
      if (runStart >= 0) {
        int runLen = (int)i - runStart;
        out->diffRuns++;
        if (runLen == 1) { out->isolatedRuns++; if (!out->firstIsolated) out->firstIsolated = (uint32_t)runStart; }
        runStart = -1;
      }
    }
  }
  if (runStart >= 0) {
    int runLen = (int)n - runStart;
    out->diffRuns++;
    if (runLen == 1) { out->isolatedRuns++; if (!out->firstIsolated) out->firstIsolated = (uint32_t)runStart; }
  }
  out->ratio = out->compared ? 1.0 - (double)out->diffBytes / (double)out->compared : 0.0;
}

int fp_normalized_sha256(const PeImage *img, uint32_t rva, uint32_t size, uint8_t out[32]) {
  uint32_t off = 0, i;
  uint8_t *copy;
  int rc;
  if (!img || pe_rva_off(img, rva, size, &off) != 0) return -1;
  copy = (uint8_t *)malloc(size ? size : 1);
  if (!copy) return -1;
  memcpy(copy, img->data + off, size);
  for (i = 0; i < size; i++)
    if (pe_reloc_byte(img, rva + i)) copy[i] = 0;
  rc = fp_sha256(copy, size, out);
  free(copy);
  return rc;
}