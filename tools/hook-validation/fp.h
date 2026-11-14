/* Cross-build fingerprint core: AOB selection, tolerant AOB matching, normalized hash,
 * aligned similarity and "isolated diff run" mutation heuristic. */
#ifndef NSP_HOOK_VALIDATION_FP_H
#define NSP_HOOK_VALIDATION_FP_H

#include "pe.h"

#define AOB_MAX_LEN 64
#define AOB_MAX_COUNT 8
#define FP_REF_AOBS 5
#define FP_AOB_LEN 32

typedef struct Aob {
  uint32_t offset;             /* RVA offset inside the function (informational) */
  uint16_t len;                /* token count, 24..48 */
  uint8_t pat[AOB_MAX_LEN];
  uint8_t wild[AOB_MAX_LEN];   /* 1 = '??' wildcard */
} Aob;

typedef struct AobMatch {
  int exact;                   /* positions matching all literal bytes */
  int tolerant;                    /* positions matching with <= tolerance literal mismatches */
  int bestMismatch;
  uint32_t bestPos;
} AobMatch;

typedef struct Similarity {
  double ratio;                /* 1 - diffBytes / comparedBytes, reloc bytes skipped */
  uint32_t compared;
  uint32_t diffBytes;
  uint32_t skipped;            /* relocation bytes skipped */
  int diffRuns;                /* maximal runs of differing bytes */
  int isolatedRuns;            /* runs whose length is exactly 1 */
  uint32_t firstIsolated;
} Similarity;

int fp_sha256(const void *data, size_t len, uint8_t out[32]);
void fp_hex(const uint8_t *data, size_t len, char *out);

int fp_generate_aobs(const PeImage *img, uint32_t rva, uint32_t size, Aob *out, int maxAobs);
int fp_aob_match(const Aob *aob, const uint8_t *body, uint32_t len, int tolerance, AobMatch *out);
void fp_similarity(const PeImage *refImg, uint32_t refRva, uint32_t refSize,
                   const uint8_t *candBody, uint32_t candLen, Similarity *out);
int fp_normalized_sha256(const PeImage *img, uint32_t rva, uint32_t size, uint8_t out[32]);

#endif