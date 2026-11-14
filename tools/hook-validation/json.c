#include "json.h"

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  const char *p;
  const char *end;
  char *err;
  size_t errlen;
  int depth;
  int failed;
} Ctx;

static void fail(Ctx *c, const char *msg) {
  if (!c->failed && c->err && c->errlen) snprintf(c->err, c->errlen, "%s", msg);
  c->failed = 1;
}

static void skip_ws(Ctx *c) {
  while (c->p < c->end && (*c->p == ' ' || *c->p == '\t' || *c->p == '\n' || *c->p == '\r')) c->p++;
}

static Jv *new_jv(JvType t) {
  Jv *v = (Jv *)calloc(1, sizeof(Jv));
  if (v) v->type = t;
  return v;
}

static char *parse_string_raw(Ctx *c) {
  size_t cap = 32, len = 0;
  char *out = (char *)malloc(cap);
  if (!out) { fail(c, "oom"); return NULL; }
  if (c->p >= c->end || *c->p != '"') { free(out); fail(c, "expected string"); return NULL; }
  c->p++;
  while (c->p < c->end) {
    unsigned char ch = (unsigned char)*c->p++;
    if (ch == '"') { out[len] = 0; return out; }
    if (ch == '\\') {
      char esc;
      if (c->p >= c->end) break;
      esc = *c->p++;
      switch (esc) {
        case '"': ch = '"'; break;
        case '\\': ch = '\\'; break;
        case '/': ch = '/'; break;
        case 'b': ch = '\b'; break;
        case 'f': ch = '\f'; break;
        case 'n': ch = '\n'; break;
        case 'r': ch = '\r'; break;
        case 't': ch = '\t'; break;
        default: free(out); fail(c, "bad escape"); return NULL;
      }
    }
    if (len + 2 > cap) {
      char *grown;
      cap *= 2;
      grown = (char *)realloc(out, cap);
      if (!grown) { free(out); fail(c, "oom"); return NULL; }
      out = grown;
    }
    out[len++] = (char)ch;
  }
  free(out);
  fail(c, "unterminated string");
  return NULL;
}

static int push_item(Jv *parent, char *key, Jv *child) {
  Jv **items = (Jv **)realloc(parent->items, sizeof(Jv *) * (size_t)(parent->count + 1));
  if (!items) return -1;
  parent->items = items;
  if (parent->type == JV_OBJ) {
    char **keys = (char **)realloc(parent->keys, sizeof(char *) * (size_t)(parent->count + 1));
    if (!keys) return -1;
    parent->keys = keys;
    parent->keys[parent->count] = key;
  } else {
    free(key);
  }
  parent->items[parent->count] = child;
  parent->count++;
  return 0;
}

static Jv *parse_value(Ctx *c);

static Jv *parse_array(Ctx *c) {
  Jv *arr = new_jv(JV_ARR);
  if (!arr) { fail(c, "oom"); return NULL; }
  c->p++; /* [ */
  skip_ws(c);
  if (c->p < c->end && *c->p == ']') { c->p++; return arr; }
  for (;;) {
    Jv *v = parse_value(c);
    if (c->failed || !v) { json_free(arr); return NULL; }
    if (push_item(arr, NULL, v) != 0) { json_free(v); json_free(arr); fail(c, "oom"); return NULL; }
    skip_ws(c);
    if (c->p < c->end && *c->p == ',') { c->p++; continue; }
    if (c->p < c->end && *c->p == ']') { c->p++; return arr; }
    json_free(arr);
    fail(c, "expected , or ]");
    return NULL;
  }
}

static Jv *parse_object(Ctx *c) {
  Jv *obj = new_jv(JV_OBJ);
  if (!obj) { fail(c, "oom"); return NULL; }
  c->p++; /* { */
  skip_ws(c);
  if (c->p < c->end && *c->p == '}') { c->p++; return obj; }
  for (;;) {
    char *key;
    Jv *v;
    skip_ws(c);
    key = parse_string_raw(c);
    if (!key) { json_free(obj); return NULL; }
    skip_ws(c);
    if (c->p >= c->end || *c->p != ':') { free(key); json_free(obj); fail(c, "expected :"); return NULL; }
    c->p++;
    v = parse_value(c);
    if (!v) { free(key); json_free(obj); return NULL; }
    if (push_item(obj, key, v) != 0) { free(key); json_free(v); json_free(obj); fail(c, "oom"); return NULL; }
    skip_ws(c);
    if (c->p < c->end && *c->p == ',') { c->p++; continue; }
    if (c->p < c->end && *c->p == '}') { c->p++; return obj; }
    json_free(obj);
    fail(c, "expected , or }");
    return NULL;
  }
}

static Jv *parse_value(Ctx *c) {
  skip_ws(c);
  if (c->p >= c->end) { fail(c, "unexpected end"); return NULL; }
  if (c->depth++ > 64) { fail(c, "nesting too deep"); return NULL; }
  if (*c->p == '{') { Jv *v = parse_object(c); c->depth--; return v; }
  if (*c->p == '[') { Jv *v = parse_array(c); c->depth--; return v; }
  if (*c->p == '"') {
    Jv *v = new_jv(JV_STR);
    if (!v) { fail(c, "oom"); return NULL; }
    v->str = parse_string_raw(c);
    if (!v->str) { free(v); return NULL; }
    c->depth--;
    return v;
  }
  if (!strncmp(c->p, "true", 4)) { Jv *v = new_jv(JV_BOOL); v->boolean = 1; c->p += 4; c->depth--; return v; }
  if (!strncmp(c->p, "false", 5)) { Jv *v = new_jv(JV_BOOL); c->p += 5; c->depth--; return v; }
  if (!strncmp(c->p, "null", 4)) { Jv *v = new_jv(JV_NULL); c->p += 4; c->depth--; return v; }
  {
    char *endp = NULL;
    double d = strtod(c->p, &endp);
    Jv *v;
    if (!endp || endp == c->p || endp > c->end) { fail(c, "bad number"); return NULL; }
    v = new_jv(JV_NUM);
    if (!v) { fail(c, "oom"); return NULL; }
    v->num = d;
    c->p = endp;
    c->depth--;
    return v;
  }
}

Jv *json_parse(const char *text, char *err, size_t errlen) {
  Ctx c;
  Jv *v;
  c.p = text;
  c.end = text + strlen(text);
  c.err = err;
  c.errlen = errlen;
  c.depth = 0;
  c.failed = 0;
  if (err && errlen) err[0] = 0;
  v = parse_value(&c);
  if (c.failed) { json_free(v); return NULL; }
  skip_ws(&c);
  if (c.p != c.end) { json_free(v); fail(&c, "trailing data"); return NULL; }
  return v;
}

void json_free(Jv *v) {
  int i;
  if (!v) return;
  for (i = 0; i < v->count; i++) json_free(v->items[i]);
  if (v->keys) {
    for (i = 0; i < v->count; i++) free(v->keys[i]);
    free(v->keys);
  }
  free(v->items);
  free(v->str);
  free(v);
}

const Jv *json_get(const Jv *obj, const char *key) {
  int i;
  if (!obj || obj->type != JV_OBJ) return NULL;
  for (i = 0; i < obj->count; i++)
    if (obj->keys[i] && strcmp(obj->keys[i], key) == 0) return obj->items[i];
  return NULL;
}

const char *json_str(const Jv *v) { return v && v->type == JV_STR ? v->str : NULL; }
double json_num(const Jv *v) { return v && v->type == JV_NUM ? v->num : 0.0; }
int json_int(const Jv *v) { return v && v->type == JV_NUM ? (int)v->num : 0; }
int json_len(const Jv *v) { return v && (v->type == JV_ARR || v->type == JV_OBJ) ? v->count : 0; }
const Jv *json_at(const Jv *arr, int index) {
  if (!arr || index < 0 || index >= arr->count) return NULL;
  return arr->items[index];
}
