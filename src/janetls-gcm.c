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
#include "janetls-random.h"
#include "janetls-gcm.h"
#include "mbedtls/platform_util.h"

// Abstract Object functions
static int gcm_gc_fn(void * data, size_t len);
static int gcm_gcmark(void * data, size_t len);
static int gcm_get_fn(void * data, Janet key, Janet * out);

static JanetAbstractType gcm_object_type = {
  "janetls/gcm",
  gcm_gc_fn,
  gcm_gcmark,
  gcm_get_fn,
  JANET_ATEND_GET
};

static JanetMethod gcm_methods[] = {
  {NULL, NULL},
};

static const JanetReg cfuns[] =
{
  {NULL, NULL, NULL}
};

void submod_gcm(JanetTable * env)
{
  janet_cfuns(env, "janetls", cfuns);
  janet_register_abstract_type(janetls_gcm_object_type());
}

janetls_gcm_object * janetls_new_gcm()
{
  janetls_gcm_object * gcm = janet_abstract(&gcm_object_type, sizeof(janetls_gcm_object));
  memset(gcm, 0, sizeof(janetls_gcm_object));
  mbedtls_gcm_init(&gcm->ctx);
  return gcm;
}

JanetAbstractType * janetls_gcm_object_type()
{
  return &gcm_object_type;
}

static int gcm_gc_fn(void * data, size_t len)
{
  janetls_gcm_object * gcm = (janetls_gcm_object *)data;
  mbedtls_gcm_free(&gcm->ctx);
  // Ensure the key does not remain in memory
  mbedtls_platform_zeroize(data, len);
  return 0;
}

static int gcm_gcmark(void * data, size_t len)
{
  (void)data;
  (void)len;
  return 0;
}

static int gcm_get_fn(void *data, Janet key, Janet * out)
{
  (void)data;

  if (!janet_checktype(key, JANET_KEYWORD))
  {
    janet_panicf("expected keyword, got %p", key);
  }

  return janet_getmethod(janet_unwrap_keyword(key), gcm_methods, out);
}
