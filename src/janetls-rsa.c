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
#include "janetls-rsa.h"

option_list_entry pkcs1_padding_versions[] = {
  {MBEDTLS_RSA_PKCS_V15, "pkcs1-v1.5", 0},
  {MBEDTLS_RSA_PKCS_V21, "pkcs1-v2.1", 0},
  {MBEDTLS_RSA_PKCS_V21, "oeap", OPTION_LIST_HIDDEN},
  {MBEDTLS_RSA_PKCS_V21, "pss", OPTION_LIST_HIDDEN},
};

#define PKCS1_PADDING_VERSIONS_COUNT (sizeof(pkcs1_padding_versions) / sizeof(option_list_entry))

static int rsa_gc_fn(void * data, size_t len);
static int rsa_get_fn(void * data, Janet key, Janet * out);

JanetAbstractType rsa_object_type = {
  "janetls/rsa",
  rsa_gc_fn,
  NULL,
  rsa_get_fn,
  JANET_ATEND_GET
};

static JanetMethod rsa_methods[] = {
  {NULL, NULL}
};

static int rsa_get_fn(void *data, Janet key, Janet * out)
{
  (void)data;

  if (!janet_checktype(key, JANET_KEYWORD))
  {
    janet_panicf("expected keyword, got %p", key);
  }

  return janet_getmethod(janet_unwrap_keyword(key), rsa_methods, out);
}

static int rsa_gc_fn(void * data, size_t len)
{
  rsa_object * rsa = (rsa_object *)data;
  mbedtls_rsa_free(&rsa->ctx);
  return 0;
}

rsa_object * new_rsa()
{
  rsa_object * rsa = janet_abstract(&rsa_object_type, sizeof(rsa_object));
  // By default PKCS#1 v1.5 encoded
  // The last parameter is the hash algorithm used for v2.1.
  // Since we are initializing to v1.5, that parameter is not used.
  mbedtls_rsa_init(&rsa->ctx, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
  return rsa;
}

int rsa_set_pkcs_v15(rsa_object * rsa)
{
  mbedtls_rsa_set_padding(&rsa->ctx, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
  // in case return codes are used later
  return 0;
}

int rsa_set_pkcs_v21(rsa_object * rsa, mbedtls_md_type_t md)
{
  mbedtls_rsa_set_padding(&rsa->ctx, MBEDTLS_RSA_PKCS_V21, md);
  // in case return codes are used later
  return 0;
}

static const JanetReg cfuns[] =
{
  {NULL, NULL, NULL}
};

void submod_rsa(JanetTable *env)
{
  janet_cfuns(env, "janetls", cfuns);
}


