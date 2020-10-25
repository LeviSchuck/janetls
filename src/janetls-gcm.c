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

// Janet functions
static Janet gcm_encrypt(int32_t argc, Janet * argv);
static Janet gcm_decrypt(int32_t argc, Janet * argv);
static Janet gcm_update(int32_t argc, Janet * argv);
static Janet gcm_finish(int32_t argc, Janet * argv);
static Janet gcm_key(int32_t argc, Janet * argv);
static Janet gcm_iv(int32_t argc, Janet * argv);
static Janet gcm_tag(int32_t argc, Janet * argv);
static Janet gcm_ad(int32_t argc, Janet * argv);

static JanetAbstractType gcm_object_type = {
  "janetls/gcm",
  gcm_gc_fn,
  gcm_gcmark,
  gcm_get_fn,
  JANET_ATEND_GET
};

static JanetMethod gcm_methods[] = {
  {"update", gcm_update},
  {"finish", gcm_finish},
  {"key", gcm_key},
  {"iv", gcm_iv},
  {"tag", gcm_tag},
  {"ad", gcm_ad},
  {NULL, NULL},
};

static const JanetReg cfuns[] =
{
  {"encrypt", gcm_encrypt, ""},
  {"decrypt", gcm_decrypt, ""},
  {"update", gcm_update, ""},
  {"finish", gcm_finish, ""},
  {"key", gcm_key, ""},
  {"iv", gcm_iv, ""},
  {"tag", gcm_tag, ""},
  {"ad", gcm_ad, ""},
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
  gcm->ad = janet_wrap_nil();
  gcm->iv = janet_wrap_nil();
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
  janetls_gcm_object * gcm = (janetls_gcm_object *)data;
  (void)len;

  janet_mark(gcm->ad);
  janet_mark(gcm->iv);

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

int janetls_setup_gcm(
  janetls_gcm_object * gcm_object,
  const uint8_t * key,
  size_t key_length,
  const uint8_t * iv,
  size_t iv_length,
  janetls_cipher_operation operation,
  const uint8_t * ad,
  size_t ad_length
  )
{
  int ret = 0;
  end:
  return ret;
}

int janetls_gcm_update(
  janetls_gcm_object * gcm_object,
  const uint8_t * data,
  size_t length,
  Janet * output)
{
  int ret = 0;
  end:
  return ret;
}

int janetls_gcm_finish(
  janetls_gcm_object * gcm_object,
  Janet * output)
{
  int ret = 0;
  end:
  return ret;
}

static Janet gcm_encrypt(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  return janet_wrap_nil();
}

static Janet gcm_decrypt(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  return janet_wrap_nil();
}

static Janet gcm_update(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  return janet_wrap_nil();
}

static Janet gcm_finish(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  return janet_wrap_nil();
}

static Janet gcm_key(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  return janet_wrap_nil();
}

static Janet gcm_iv(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  return janet_wrap_nil();
}

static Janet gcm_tag(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  return janet_wrap_nil();
}

static Janet gcm_ad(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  return janet_wrap_nil();
}
