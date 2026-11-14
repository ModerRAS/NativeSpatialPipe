/* nsp-hook-validate: cross-build function fingerprint validator for the audiodg hook target.
 *
 * CLI: nsp-hook-validate --method crossbuild-fingerprint --reference <ref.exe>
 *                       --candidate <cand.exe> --json [--db builds.json]
 *      nsp-hook-validate --method crossbuild-fingerprint --reference <ref.exe>
 *                       --candidate <cand.exe> --emit-entry --json
 *
 * The validator never trusts a whole-file hash: it locates the hooked function inside
 * the candidate through .pdata, AOB patterns and aligned similarity, then compares the
 * relocation-normalized SHA-256 with the per-build fingerprint database. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>

#include "fp.h"
#include "json.h"
#include "pe.h"

#define MAX_DB_BUILDS 16
#define MAX_JSON_PATH 1024

typedef struct BuildEntry {
  char buildId[64];
  uint32_t timeDateStamp;
  uint32_t sizeOfImage;
  uint32_t checkSum;
  uint32_t rva;
  uint32_t size;
  char hashHex[65];
  uint8_t hash[32];
  Aob aobs[AOB_MAX_COUNT];
  int naobs;
} BuildEntry;

typedef struct Db {
  BuildEntry builds[MAX_DB_BUILDS];
  int count;
  int refIdx;
} Db;

typedef struct Located {
  int found;
  uint32_t rva;
  uint32_t size;
  double confidence;
  double similarity;
  int exactHits;
  int nearHits;
  int totalAobs;
  Similarity sim;
  uint32_t secondBest;
  double secondSimilarity;
} Located;

static char g_error[512];

static void json_escape(const char *in, char *out, size_t outlen) {
  size_t o = 0;
  const unsigned char *p = (const unsigned char *)in;
  while (*p && o + 2 < outlen) {
    unsigned char c = *p++;
    switch (c) {
      case '"': out[o++] = '\\'; out[o++] = '"'; break;
      case '\\': out[o++] = '\\'; out[o++] = '\\'; break;
      case '\n': out[o++] = '\\'; out[o++] = 'n'; break;
      case '\r': out[o++] = '\\'; out[o++] = 'r'; break;
      case '\t': out[o++] = '\\'; out[o++] = 't'; break;
      default:
        if (c < 0x20) { o += (size_t)snprintf(out + o, outlen - o, "\\u%04x", c); }
        else out[o++] = (char)c;
    }
  }
  out[o] = 0;
}

static int parse_pattern(const char *pattern, Aob *aob) {
  const char *p = pattern;
  int n = 0;
  memset(aob, 0, sizeof(*aob));
  while (*p && n < AOB_MAX_LEN) {
    while (*p == ' ') p++;
    if (!*p) break;
    if (p[0] == '?' && p[1] == '?') {
      aob->wild[n] = 1;
      p += 2;
    } else {
      unsigned int value = 0;
      if (sscanf(p, "%2x", &value) != 1) return -1;
      aob->pat[n] = (uint8_t)value;
      p += 2;
    }
    n++;
  }
  aob->len = (uint16_t)n;
  return n >= 8 ? 0 : -1;
}

static char *read_text_file(const wchar_t *path, size_t *outLen) {
  FILE *f = _wfopen(path, L"rb");
  long n;
  char *buf;
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  n = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (n <= 0 || n > (16 << 20)) { fclose(f); return NULL; }
  buf = (char *)malloc((size_t)n + 1);
  if (!buf) { fclose(f); return NULL; }
  if (fread(buf, 1, (size_t)n, f) != (size_t)n) { free(buf); fclose(f); return NULL; }
  fclose(f);
  buf[n] = 0;
  if (outLen) *outLen = (size_t)n;
  return buf;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t outLen) {
  size_t i;
  if (!hex || strlen(hex) < outLen * 2) return -1;
  for (i = 0; i < outLen; i++) {
    unsigned int v = 0;
    if (sscanf(hex + i * 2, "%2x", &v) != 1) return -1;
    out[i] = (uint8_t)v;
  }
  return 0;
}

static int db_load(const wchar_t *path, Db *db) {
  char *text = read_text_file(path, NULL);
  char err[256];
  Jv *root = NULL;
  const Jv *builds, *refId;
  int i, n;
  memset(db, 0, sizeof(*db));
  db->refIdx = 0;
  if (!text) { snprintf(g_error, sizeof(g_error), "cannot read db %ls", path); return -1; }
  root = json_parse(text, err, sizeof(err));
  free(text);
  if (!root) { snprintf(g_error, sizeof(g_error), "db json: %s", err); return -1; }
  builds = json_get(root, "builds");
  if (!builds || builds->type != JV_ARR) { snprintf(g_error, sizeof(g_error), "db: missing builds[]"); json_free(root); return -1; }
  n = json_len(builds);
  if (n <= 0 || n > MAX_DB_BUILDS) { snprintf(g_error, sizeof(g_error), "db: bad build count"); json_free(root); return -1; }
  for (i = 0; i < n; i++) {
    const Jv *item = json_at(builds, i);
    BuildEntry *e = &db->builds[db->count];
    const Jv *aobs;
    int a;
    if (!item || item->type != JV_OBJ) continue;
    snprintf(e->buildId, sizeof(e->buildId), "%s", json_str(json_get(item, "buildId")) ? json_str(json_get(item, "buildId")) : "");
    e->timeDateStamp = (uint32_t)json_int(json_get(item, "timeDateStamp"));
    e->sizeOfImage = (uint32_t)json_int(json_get(item, "sizeOfImage"));
    e->checkSum = (uint32_t)json_int(json_get(item, "checkSum"));
    e->rva = (uint32_t)json_int(json_get(item, "rva"));
    e->size = (uint32_t)json_int(json_get(item, "size"));
    if (hex_to_bytes(json_str(json_get(item, "sha256")), e->hash, 32) != 0) {
      snprintf(g_error, sizeof(g_error), "db: build %d bad sha256", i);
      json_free(root);
      return -1;
    }
    fp_hex(e->hash, 32, e->hashHex);
    aobs = json_get(item, "aobs");
    for (a = 0; a < json_len(aobs) && a < AOB_MAX_COUNT; a++) {
      const Jv *x = json_at(aobs, a);
      Aob *aob = &e->aobs[e->naobs];
      if (parse_pattern(json_str(json_get(x, "pattern")), aob) != 0) {
        snprintf(g_error, sizeof(g_error), "db: build %d bad aob", i);
        json_free(root);
        return -1;
      }
      aob->offset = (uint32_t)json_int(json_get(x, "offset"));
      e->naobs++;
    }
    db->count++;
  }
  refId = json_get(root, "referenceBuildId");
  if (refId && json_str(refId)) {
    for (i = 0; i < db->count; i++)
      if (strcmp(db->builds[i].buildId, json_str(refId)) == 0) db->refIdx = i;
  }
  json_free(root);
  if (db->count == 0) { snprintf(g_error, sizeof(g_error), "db: no builds"); return -1; }
  return 0;
}

static int build_index(const Db *db, const char *buildId) {
  int i;
  for (i = 0; i < db->count; i++)
    if (buildId && buildId[0] && strcmp(db->builds[i].buildId, buildId) == 0) return i;
  return -1;
}

/* Locate the hooked function in the candidate: scan every .pdata function, score by
 * AOB hits of the reference build, then by aligned byte similarity. */
static int locate(const PeImage *refImg, const BuildEntry *refEntry, const PeImage *cand, Located *out) {
  uint32_t f, refOff = 0;
  uint32_t bestScore = 0;
  int haveBest = 0;
  uint32_t secondSim = 0;
  double secondSimVal = 0.0;
  memset(out, 0, sizeof(*out));
  if (pe_rva_off(refImg, refEntry->rva, refEntry->size, &refOff) != 0) return -1;
  for (f = 0; f < cand->pdataCount; f++) {
    uint32_t rva = cand->pdata[f].begin;
    uint32_t size = cand->pdata[f].end - cand->pdata[f].begin;
    uint32_t off = 0;
    int a, exact = 0, tolerant = 0;
    uint32_t score;
    Similarity sim;
    if (size < 64 || size > 8192) continue;
    if (pe_rva_off(cand, rva, size, &off) != 0) continue;
    for (a = 0; a < refEntry->naobs; a++) {
      AobMatch m;
      if (fp_aob_match(&refEntry->aobs[a], cand->data + off, size, 2, &m) <= 0) continue;
      if (m.exact) exact++;
      else if (m.tolerant) tolerant++;
    }
    if (!exact && !tolerant) continue;
    score = (uint32_t)(exact * 3 + tolerant);
    fp_similarity(refImg, refEntry->rva, refEntry->size, cand->data + off, size, &sim);
    if (!haveBest || score > bestScore || (score == bestScore && sim.ratio > out->similarity)) {
      if (haveBest) { secondSim = out->rva; secondSimVal = out->similarity; }
      haveBest = 1;
      bestScore = score;
      out->found = 1;
      out->rva = rva;
      out->size = size;
      out->exactHits = exact;
      out->nearHits = tolerant;
      out->totalAobs = refEntry->naobs;
      out->similarity = sim.ratio;
      out->sim = sim;
    } else if (sim.ratio > secondSimVal) {
      secondSim = rva;
      secondSimVal = sim.ratio;
    }
    (void)refOff;
  }
  out->secondBest = secondSim;
  out->secondSimilarity = secondSimVal;
  if (out->found) {
    double ratio = out->totalAobs ? (double)out->exactHits / (double)out->totalAobs : 0.0;
    out->confidence = ratio > out->similarity ? ratio : out->similarity;
    /* Ambiguity guard: a decisive match must be clearly better than the runner-up. */
    if (out->confidence < 0.85 || (out->secondSimilarity > 0.5 && out->similarity - out->secondSimilarity < 0.10)) {
      out->found = 0;
      out->confidence = 0.0;
    }
  }
  return 0;
}

static void print_aob_pattern(const Aob *aob, char *out, size_t outlen) {
  size_t o = 0;
  int i;
  for (i = 0; i < aob->len && o + 4 < outlen; i++) {
    if (aob->wild[i]) o += (size_t)snprintf(out + o, outlen - o, "%s??", i ? " " : "");
    else o += (size_t)snprintf(out + o, outlen - o, "%s%02x", i ? " " : "", aob->pat[i]);
  }
  out[o] = 0;
}

int wmain(int argc, wchar_t **argv) {
  const wchar_t *reference = NULL, *candidate = NULL, *dbPath = L"tools/hook-validation/builds.json";
  const wchar_t *method = L"crossbuild-fingerprint";
  int wantJson = 0, emitEntry = 0, i;
  PeImage refImg, candImg;
  Db db;
  BuildEntry generated;
  Located located;
  char version[64];
  uint8_t candHash[32];
  char candHashHex[65];
  int buildKnown = 0, knownIdx = -1, hashMatches = 0;
  const char *decision = "deny";
  int targetChanged = -1; /* -1 = null */
  char checks[16][512];
  int nChecks = 0;
  LARGE_INTEGER freq, t0, t1;
  double timingMs;
  char refEsc[MAX_JSON_PATH * 2], candEsc[MAX_JSON_PATH * 2];
  int rc = 0;

  for (i = 1; i < argc; i++) {
    const wchar_t *a = argv[i];
    if (!wcscmp(a, L"--method") && i + 1 < argc) method = argv[++i];
    else if (!wcscmp(a, L"--reference") && i + 1 < argc) reference = argv[++i];
    else if (!wcscmp(a, L"--candidate") && i + 1 < argc) candidate = argv[++i];
    else if (!wcscmp(a, L"--db") && i + 1 < argc) dbPath = argv[++i];
    else if (!wcscmp(a, L"--json")) wantJson = 1;
    else if (!wcscmp(a, L"--emit-entry")) emitEntry = 1;
    else if (!wcscmp(a, L"--help") || !wcscmp(a, L"-h")) {
      fputs("usage: nsp-hook-validate --method crossbuild-fingerprint --reference <ref.exe> "
            "--candidate <cand.exe> [--db builds.json] [--emit-entry] [--json]\n", stderr);
      return 2;
    } else {
      fprintf(stderr, "unknown argument: %ls\n", a);
      return 2;
    }
  }
  if (!reference || !candidate) {
    fputs("usage: nsp-hook-validate --method crossbuild-fingerprint --reference <ref.exe> "
          "--candidate <cand.exe> [--db builds.json] [--json]\n", stderr);
    return 2;
  }
  if (wcscmp(method, L"crossbuild-fingerprint") != 0) {
    fprintf(stderr, "unsupported --method %ls (only crossbuild-fingerprint)\n", method);
    return 2;
  }
  if (pe_load(reference, &refImg) != 0) { fprintf(stderr, "cannot parse reference %ls\n", reference); return 3; }
  if (pe_load(candidate, &candImg) != 0) { pe_free(&refImg); fprintf(stderr, "cannot parse candidate %ls\n", candidate); return 3; }
  if (db_load(dbPath, &db) != 0) {
    fprintf(stderr, "%s\n", g_error);
    pe_free(&refImg);
    pe_free(&candImg);
    return 3;
  }
  if (db.builds[db.refIdx].naobs < 1) {
    /* Bootstrapping aid: derive the reference AOB set from the reference image. */
    int generatedAobs = fp_generate_aobs(&refImg, db.builds[db.refIdx].rva, db.builds[db.refIdx].size,
                                         db.builds[db.refIdx].aobs, FP_REF_AOBS);
    if (generatedAobs < 1) {
      fprintf(stderr, "db reference build has no aobs and generation failed\n");
      pe_free(&refImg);
      pe_free(&candImg);
      return 3;
    }
    db.builds[db.refIdx].naobs = generatedAobs;
  }

  QueryPerformanceFrequency(&freq);
  QueryPerformanceCounter(&t0);

  /* Fingerprint of the reference function (used by --emit-entry). */
  memset(&generated, 0, sizeof(generated));
  generated.rva = db.builds[db.refIdx].rva;
  generated.size = db.builds[db.refIdx].size;

  locate(&refImg, &db.builds[db.refIdx], &candImg, &located);

  pe_file_version(candidate, &candImg, version, sizeof(version));
  if (fp_normalized_sha256(&candImg, located.found ? located.rva : 0, located.found ? located.size : 0, candHash) != 0)
    memset(candHash, 0, sizeof(candHash));
  fp_hex(candHash, 32, candHashHex);

  knownIdx = build_index(&db, version);
  buildKnown = knownIdx >= 0;
  if (buildKnown) {
    hashMatches = located.found && memcmp(candHash, db.builds[knownIdx].hash, 32) == 0;
  }

  /* --- evidence checks --------------------------------------------------- */
  snprintf(checks[nChecks], sizeof(checks[0]), "{\"name\":\"pe\",\"ok\":true,\"detail\":\"sections=%u .text=0x%x/0x%x .pdata=%u functions relocBytes=%s\"}",
           candImg.sectionCount,
           pe_section(&candImg, ".text") ? pe_section(&candImg, ".text")->va : 0,
           pe_section(&candImg, ".text") ? pe_section(&candImg, ".text")->vsize : 0,
           candImg.pdataCount, candImg.relocMap ? (pe_reloc_byte(&candImg, located.found ? located.rva : 0) ? "yes" : "none-in-target") : "absent");
  nChecks++;
  if (located.found)
    snprintf(checks[nChecks], sizeof(checks[0]),
             "{\"name\":\"pdata-locate\",\"ok\":true,\"detail\":\"rva=0x%x size=%u similarity=%.4f confidence=%.4f secondBestSim=%.4f\"}",
             located.rva, located.size, located.similarity, located.confidence, located.secondSimilarity);
  else
    snprintf(checks[nChecks], sizeof(checks[0]),
             "{\"name\":\"pdata-locate\",\"ok\":false,\"detail\":\"no .pdata function matched the reference AOB set (pdataFunctions=%u)\"}",
             candImg.pdataCount);
  nChecks++;
  snprintf(checks[nChecks], sizeof(checks[0]),
           "{\"name\":\"aob\",\"ok\":%s,\"detail\":\"%d/%d exact, %d/%d tolerant (patternLen=32, wildcarded rel32/disp32)\"}",
           (located.exactHits == located.totalAobs) ? "true" : "false",
           located.exactHits, located.totalAobs, located.exactHits + located.nearHits, located.totalAobs);
  nChecks++;
  snprintf(checks[nChecks], sizeof(checks[0]),
           "{\"name\":\"similarity\",\"ok\":%s,\"detail\":\"aligned=%.4f compared=%u diffBytes=%u diffRuns=%d isolatedRuns=%d skippedReloc=%u\"}",
           located.similarity >= 0.85 ? "true" : "false", located.similarity, located.sim.compared,
           located.sim.diffBytes, located.sim.diffRuns, located.sim.isolatedRuns, located.sim.skipped);
  nChecks++;
  snprintf(checks[nChecks], sizeof(checks[0]),
           "{\"name\":\"normalized-hash\",\"ok\":%s,\"detail\":\"sha256=%s db=%s match=%s\"}",
           buildKnown && hashMatches ? "true" : "false", candHashHex,
           buildKnown ? db.builds[knownIdx].hashHex : "n/a", buildKnown ? (hashMatches ? "true" : "false") : "n/a");
  nChecks++;
  snprintf(checks[nChecks], sizeof(checks[0]),
           "{\"name\":\"build-identity\",\"ok\":true,\"detail\":\"buildId=%s known=%s tds=%u sizeOfImage=%u checkSum=%u\"}",
           version, buildKnown ? "true" : "false", candImg.timeDateStamp, candImg.sizeOfImage, candImg.checkSum);
  nChecks++;
  snprintf(checks[nChecks], sizeof(checks[0]),
           "{\"name\":\"mutation-heuristic\",\"ok\":%s,\"detail\":\"isolated1ByteRuns=%d firstAt=%d; aobMisses=%d\"}",
           (located.sim.isolatedRuns == 0 && located.exactHits == located.totalAobs) ? "true" : "false",
           located.sim.isolatedRuns, (int)located.sim.firstIsolated,
           located.totalAobs - located.exactHits);
  nChecks++;

  /* --- decision ---------------------------------------------------------- */
  if (!located.found) {
    decision = "deny";
    targetChanged = -1;
  } else if (buildKnown) {
    decision = hashMatches ? "allow" : "deny";
    targetChanged = hashMatches ? 0 : 1;
  } else {
    int suspicious = located.sim.isolatedRuns > 0 || located.exactHits < located.totalAobs;
    if (suspicious) {
      decision = "deny";
      targetChanged = 1;
    } else if (located.similarity >= 0.98) {
      decision = "warn";
      targetChanged = -1;
    } else if (located.similarity >= 0.85) {
      decision = "warn";
      targetChanged = -1;
    } else if (located.similarity >= 0.50) {
      decision = "unknown";
      targetChanged = -1;
    } else {
      decision = "deny";
      targetChanged = -1;
    }
  }
  snprintf(checks[nChecks], sizeof(checks[0]),
           "{\"name\":\"policy\",\"ok\":true,\"detail\":\"%s\"}",
           buildKnown ? (hashMatches ? "known build + normalized hash match -> allow"
                                     : "known build + normalized hash mismatch -> deny (target changed)")
                      : (targetChanged == 1 ? "unknown build + modification evidence -> deny, targetChanged"
                                            : "unknown build, no modification evidence -> confirm/add to db"));
  nChecks++;

  QueryPerformanceCounter(&t1);
  timingMs = 1000.0 * (double)(t1.QuadPart - t0.QuadPart) / (double)freq.QuadPart;
  json_escape(reference ? "reference" : "", refEsc, sizeof(refEsc));
  (void)refEsc;
  json_escape(candidate ? "candidate" : "", candEsc, sizeof(candEsc));

  if (emitEntry) {
    char pat[AOB_MAX_LEN * 4];
    int a, k;
    printf("{\"buildId\":\"%s\",\"timeDateStamp\":%u,\"sizeOfImage\":%u,\"checkSum\":%u,\"rva\":%u,\"size\":%u,\"sha256\":\"%s\",\"aobs\":[",
           version, candImg.timeDateStamp, candImg.sizeOfImage, candImg.checkSum,
           located.found ? located.rva : 0, located.found ? located.size : 0, candHashHex);
    if (located.found) {
      BuildEntry gen;
      memset(&gen, 0, sizeof(gen));
      gen.rva = located.rva;
      gen.size = located.size;
      k = fp_generate_aobs(&candImg, located.rva, located.size, gen.aobs, FP_REF_AOBS);
      for (a = 0; a < k; a++) {
        print_aob_pattern(&gen.aobs[a], pat, sizeof(pat));
        printf("%s{\"offset\":%u,\"pattern\":\"%s\"}", a ? "," : "", gen.aobs[a].offset, pat);
      }
    }
    printf("]}\n");
    pe_free(&refImg);
    pe_free(&candImg);
    return 0;
  }

  if (wantJson) {
    char refPath[MAX_JSON_PATH * 2], candPath[MAX_JSON_PATH * 2];
    char refU[MAX_JSON_PATH] = "?", candU[MAX_JSON_PATH] = "?";
    WideCharToMultiByte(CP_UTF8, 0, reference, -1, refU, sizeof(refU), NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, candidate, -1, candU, sizeof(candU), NULL, NULL);
    json_escape(refU, refPath, sizeof(refPath));
    json_escape(candU, candPath, sizeof(candPath));
    printf("{\"method\":\"crossbuild-fingerprint\",\"reference\":\"%s\",\"candidate\":\"%s\",", refPath, candPath);
    printf("\"build\":{\"fileVersion\":\"%s\",\"timeDateStamp\":%u,\"sizeOfImage\":%u,\"checkSum\":%u},",
           version, candImg.timeDateStamp, candImg.sizeOfImage, candImg.checkSum);
    if (located.found)
      printf("\"located\":{\"rva\":%u,\"size\":%u,\"confidence\":%.4f},", located.rva, located.size, located.confidence);
    else
      printf("\"located\":null,");
    printf("\"decision\":\"%s\",", decision);
    if (targetChanged < 0) printf("\"targetChanged\":null,");
    else printf("\"targetChanged\":%s,", targetChanged ? "true" : "false");
    printf("\"buildKnown\":%s,\"similarity\":%.4f,\"dbBuildCount\":%d,\"checks\":[",
           buildKnown ? "true" : "false", located.similarity, db.count);
    for (i = 0; i < nChecks; i++) printf("%s%s", i ? "," : "", checks[i]);
    printf("],\"timingMs\":%.2f}\n", timingMs);
  } else {
    printf("method=crossbuild-fingerprint build=%s decision=%s targetChanged=%s rva=%s size=%u sim=%.4f conf=%.4f timing=%.2fms\n",
           version, decision, targetChanged < 0 ? "null" : (targetChanged ? "true" : "false"),
           located.found ? "located" : "none", located.size, located.similarity, located.confidence, timingMs);
    if (located.found) printf("locatedRva=0x%x\n", located.rva);
  }
  pe_free(&refImg);
  pe_free(&candImg);
  return rc;
}