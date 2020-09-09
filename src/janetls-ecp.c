/*
 * Copyright (c) 2020 Levi Schuck
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "janetls.h"
#include "janetls-ecp.h"

static int ecp_group_gc_fn(void * data, size_t len);
static int ecp_group_gcmark(void * data, size_t len);
static int ecp_group_get_fn(void * data, Janet key, Janet * out);

static int ecp_point_gc_fn(void * data, size_t len);
static int ecp_point_gcmark(void * data, size_t len);
static int ecp_point_get_fn(void * data, Janet key, Janet * out);

static int ecp_keypair_gc_fn(void * data, size_t len);
static int ecp_keypair_gcmark(void * data, size_t len);
static int ecp_keypair_get_fn(void * data, Janet key, Janet * out);

// TODO functions

JanetAbstractType janetls_ecp_group_object_type = {
  "janetls/ecp/group",
  ecp_group_gc_fn,
  ecp_group_gcmark,
  ecp_group_get_fn,
  JANET_ATEND_GET
};

JanetAbstractType janetls_ecp_point_object_type = {
  "janetls/ecp/point",
  ecp_point_gc_fn,
  ecp_point_gcmark,
  ecp_point_get_fn,
  JANET_ATEND_GET
};

JanetAbstractType janetls_ecp_keypair_object_type = {
  "janetls/ecp/keypair",
  ecp_keypair_gc_fn,
  ecp_keypair_gcmark,
  ecp_keypair_get_fn,
  JANET_ATEND_GET
};

static JanetMethod ecp_group_methods[] = {
  {NULL, NULL}
};

static JanetMethod ecp_point_methods[] = {
  {NULL, NULL}
};

static JanetMethod ecp_keypair_methods[] = {
  {NULL, NULL}
};


static const JanetReg cfuns[] =
{
  {NULL, NULL, NULL}
};

void submod_ecp(JanetTable * env)
{
  janet_cfuns(env, "janetls", cfuns);
}

static int ecp_group_get_fn(void *data, Janet key, Janet * out)
{
  (void)data;

  if (!janet_checktype(key, JANET_KEYWORD))
  {
    janet_panicf("expected keyword, got %p", key);
  }

  return janet_getmethod(janet_unwrap_keyword(key), ecp_group_methods, out);
}

static int ecp_group_gc_fn(void * data, size_t len)
{
  janetls_ecp_group_object * group = (janetls_ecp_group_object *)data;
  mbedtls_ecp_group_free(&group->group);
  return 0;
}

static int ecp_group_gcmark(void *data, size_t len)
{
  (void)len;
  (void)data;

  return 0;
}

static int ecp_point_get_fn(void *data, Janet key, Janet * out)
{
  (void)data;

  if (!janet_checktype(key, JANET_KEYWORD))
  {
    janet_panicf("expected keyword, got %p", key);
  }

  return janet_getmethod(janet_unwrap_keyword(key), ecp_point_methods, out);
}

static int ecp_point_gc_fn(void * data, size_t len)
{
  janetls_ecp_point_object * point = (janetls_ecp_point_object *)data;
  mbedtls_ecp_point_free(&point->point);
  return 0;
}

static int ecp_point_gcmark(void *data, size_t len)
{
  (void)len;
  janetls_ecp_point_object * point = (janetls_ecp_point_object *)data;

  if (point->group != NULL)
  {
    janet_mark(janet_wrap_abstract(point->group));
  }

  if (point->x != NULL)
  {
    janet_mark(janet_wrap_abstract(point->x));
  }

  if (point->y != NULL)
  {
    janet_mark(janet_wrap_abstract(point->y));
  }

  return 0;
}

janetls_ecp_group_object * janetls_new_ecp_group_object()
{
  janetls_ecp_group_object * group = janet_abstract(&janetls_ecp_group_object_type, sizeof(janetls_ecp_group_object));
  memset(group, 0, sizeof(janetls_ecp_group_object));
  mbedtls_ecp_group_init(&group->group);
  return group;
}

janetls_ecp_point_object * janetls_new_ecp_point_object()
{
  janetls_ecp_point_object * point = janet_abstract(&janetls_ecp_point_object_type, sizeof(janetls_ecp_point_object));
  memset(point, 0, sizeof(janetls_ecp_point_object));
  mbedtls_ecp_point_init(&point->point);
  return point;
}

janetls_ecp_keypair_object * janetls_new_ecp_keypair_object()
{
  janetls_ecp_keypair_object * keypair = janet_abstract(&janetls_ecp_keypair_object_type, sizeof(janetls_ecp_keypair_object));
  memset(keypair, 0, sizeof(janetls_ecp_keypair_object));
  mbedtls_ecp_keypair_init(&keypair->keypair);
  return keypair;
}
