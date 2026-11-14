/* Minimal JSON reader for tools/hook-validation/builds.json (no third-party code). */
#ifndef NSP_HOOK_VALIDATION_JSON_H
#define NSP_HOOK_VALIDATION_JSON_H

#include <stddef.h>

typedef enum { JV_NULL, JV_BOOL, JV_NUM, JV_STR, JV_ARR, JV_OBJ } JvType;

typedef struct Jv {
  JvType type;
  double num;
  int boolean;
  char *str;
  struct Jv **items;
  char **keys;
  int count;
} Jv;

Jv *json_parse(const char *text, char *err, size_t errlen);
void json_free(Jv *v);
const Jv *json_get(const Jv *obj, const char *key);
const char *json_str(const Jv *v);
double json_num(const Jv *v);
int json_int(const Jv *v);
int json_len(const Jv *v);
const Jv *json_at(const Jv *arr, int index);

#endif
