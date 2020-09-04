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

option_list_entry pkcs1_versions[] = {
  {rsa_pkcs1_version_v15, "pkcs1-v1.5", 0},
  {rsa_pkcs1_version_v21, "pkcs1-v2.1", 0},
  {rsa_pkcs1_version_v15, "pkcs1-v1_5", OPTION_LIST_HIDDEN},
  {rsa_pkcs1_version_v21, "pkcs1-v2_1", OPTION_LIST_HIDDEN},
  {rsa_pkcs1_version_v15, "v1.5", OPTION_LIST_HIDDEN},
  {rsa_pkcs1_version_v21, "v2.1", OPTION_LIST_HIDDEN},
  {rsa_pkcs1_version_v15, "v1_5", OPTION_LIST_HIDDEN},
  {rsa_pkcs1_version_v21, "v2_1", OPTION_LIST_HIDDEN},
  {rsa_pkcs1_version_v15, "ssa", OPTION_LIST_HIDDEN},
  {rsa_pkcs1_version_v21, "rsaes", OPTION_LIST_HIDDEN},
  {rsa_pkcs1_version_v21, "oeap", OPTION_LIST_HIDDEN},
  {rsa_pkcs1_version_v21, "pss", OPTION_LIST_HIDDEN},
};

#define PKCS1_VERSIONS_COUNT (sizeof(pkcs1_versions) / sizeof(option_list_entry))

static int rsa_gc_fn(void * data, size_t len);
static int rsa_gcmark(void * data, size_t len);
static int rsa_get_fn(void * data, Janet key, Janet * out);
Janet rsa_is_private(int32_t argc, Janet * argv);
Janet rsa_is_public(int32_t argc, Janet * argv);
Janet rsa_sign(int32_t argc, Janet * argv);
Janet rsa_verify(int32_t argc, Janet * argv);
Janet rsa_encrypt(int32_t argc, Janet * argv);
Janet rsa_decrypt(int32_t argc, Janet * argv);
Janet rsa_get_version(int32_t argc, Janet * argv);
Janet rsa_get_mgf(int32_t argc, Janet * argv);
Janet rsa_get_digest(int32_t argc, Janet * argv);
Janet rsa_get_sizebits(int32_t argc, Janet * argv);
Janet rsa_get_sizebytes(int32_t argc, Janet * argv);
Janet rsa_export_public(int32_t argc, Janet * argv);
Janet rsa_export_private(int32_t argc, Janet * argv);
Janet rsa_import(int32_t argc, Janet * argv);
Janet rsa_generate(int32_t argc, Janet * argv);

int rsa_set_pkcs_v15(rsa_object * rsa);
int rsa_set_pkcs_v21(rsa_object * rsa, mbedtls_md_type_t md);

JanetAbstractType rsa_object_type = {
  "janetls/rsa",
  rsa_gc_fn,
  rsa_gcmark,
  rsa_get_fn,
  JANET_ATEND_GET
};

static JanetMethod rsa_methods[] = {
  {"private?", rsa_is_private},
  {"public?", rsa_is_public},
  {"get-version", rsa_get_version},
  {"get-mgf", rsa_get_mgf},
  {"get-digest", rsa_get_digest},
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

static int rsa_gcmark(void *data, size_t len)
{
  (void)len;
  rsa_object * rsa = (rsa_object *)data;

  if (rsa->random != NULL)
  {
    janet_mark(janet_wrap_abstract(rsa->random));
  }

  return 0;
}

rsa_object * new_rsa()
{
  rsa_object * rsa = janet_abstract(&rsa_object_type, sizeof(rsa_object));
  // By default PKCS#1 v1.5 encoded
  // The last parameter is the hash algorithm used for v2.1.
  // Since we are initializing to v1.5, that parameter is not used.
  mbedtls_rsa_init(&rsa->ctx, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
  // Lazy random
  rsa->random = NULL;
  rsa->type = rsa_key_type_public;
  rsa->version = rsa_pkcs1_version_v15;
  rsa->digest = MBEDTLS_MD_NONE;
  return rsa;
}

int rsa_set_pkcs_v15(rsa_object * rsa)
{
  mbedtls_rsa_set_padding(&rsa->ctx, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
  rsa->version = rsa_pkcs1_version_v15;
  // in case return codes are used later
  return 0;
}

int rsa_set_pkcs_v21(rsa_object * rsa, mbedtls_md_type_t md)
{
  mbedtls_rsa_set_padding(&rsa->ctx, MBEDTLS_RSA_PKCS_V21, md);
  rsa->version = rsa_pkcs1_version_v21;
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


Janet rsa_is_private(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);

  return janet_wrap_nil();
}

Janet rsa_is_public(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  return janet_wrap_nil();
}

Janet rsa_sign(int32_t argc, Janet * argv)
{
  janet_arity(argc, 2, 3);
  // RSA object
  // Data to hash
  // Hash function

  return janet_wrap_nil();
}

Janet rsa_verify(int32_t argc, Janet * argv)
{
  janet_arity(argc, 3, 4);
  // RSA object
  // Data to hash
  // Signature
  // Hash function
  return janet_wrap_nil();
}

Janet rsa_encrypt(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 2);
  // RSA object
  // Data to encrypt
  return janet_wrap_nil();
}

Janet rsa_decrypt(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 2);
  // RSA object
  // Data to decrypt
  return janet_wrap_nil();
}

Janet rsa_get_version(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  return janet_wrap_nil();
}

Janet rsa_get_mgf(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  return janet_wrap_nil();
}

Janet rsa_get_digest(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  return janet_wrap_nil();
}

Janet rsa_get_sizebits(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  return janet_wrap_nil();
}

Janet rsa_get_sizebytes(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  return janet_wrap_nil();
}

Janet rsa_export_public(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  return janet_wrap_nil();
}

Janet rsa_export_private(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  return janet_wrap_nil();
}

Janet rsa_import(int32_t argc, Janet * argv)
{
  // Maybe take one table/struct
  // for the RSA params
  // And other details, such as version, mgf, hash
  // Public params
  // N
  // E
  // Private params
  // D
  // P
  // Q
  // Derivable private params
  // DP
  // DQ
  // QP
  // Other options
  // version from pkcs1_versions
  // mask generation function from md supported_algorithms
  // default hash function from md supported_algorithms
  // randomness source
  janet_fixarity(argc, 1);

  if (!janet_checktype(argv[0], JANET_TABLE)
    && !janet_checktype(argv[0], JANET_STRUCT))
  {
    janet_panic("Expected a struct or table");
  }

  rsa_object * rsa = new_rsa();

  const JanetKV * kv = NULL;
  const JanetKV * kvs = NULL;
  int32_t len;
  int32_t cap = 0;
  janet_dictionary_view(argv[0], &kvs, &len, &cap);
  while ((kv = janet_dictionary_next(kvs, cap, kv)))
  {
    if (janet_is_byte_typed(kv->key))
    {
      JanetByteView key = janet_to_bytes(kv->key);
      if (janet_byte_cstrcmp_insensitive(key, "type") == 0)
      {
        // public, private
      }
      else if (janet_byte_cstrcmp_insensitive(key, "version") == 0)
      {

      }
      else if (janet_byte_cstrcmp_insensitive(key, "rng") == 0
        || janet_byte_cstrcmp_insensitive(key, "random") == 0)
      {
        
      }
      else if (janet_byte_cstrcmp_insensitive(key, "mgf") == 0
        || janet_byte_cstrcmp_insensitive(key, "mgf1") == 0
        || janet_byte_cstrcmp_insensitive(key, "mask-generation-function") == 0
        || janet_byte_cstrcmp_insensitive(key, "mask") == 0)
      {
        
      }
      else if (janet_byte_cstrcmp_insensitive(key, "hash") == 0
        || janet_byte_cstrcmp_insensitive(key, "digest") == 0)
      {
        
      }
      else if (janet_byte_cstrcmp_insensitive(key, "n") == 0)
      {

      }
      else if (janet_byte_cstrcmp_insensitive(key, "e") == 0)
      {

      }
      else if (janet_byte_cstrcmp_insensitive(key, "p") == 0)
      {

      }
      else if (janet_byte_cstrcmp_insensitive(key, "q") == 0)
      {

      }
      else if (janet_byte_cstrcmp_insensitive(key, "d") == 0)
      {

      }
      else if (janet_byte_cstrcmp_insensitive(key, "dp") == 0)
      {

      }
      else if (janet_byte_cstrcmp_insensitive(key, "dq") == 0)
      {

      }
      else if (janet_byte_cstrcmp_insensitive(key, "qp") == 0)
      {

      }
    }
    else
    {
      janet_panicf("Expected a keyword key in the struct or table, but got %p", kv->key);
    }
  }

  if (rsa->random == NULL)
  {
    // TODO procure a random source
  }

  // TODO validate the key
  return janet_wrap_nil();
}

Janet rsa_generate(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);

  if (!janet_checktype(argv[0], JANET_TABLE)
    && !janet_checktype(argv[0], JANET_STRUCT))
  {
    janet_panic("Expected a struct or table");
  }

  rsa_object * rsa = new_rsa();

  const JanetKV * kv = NULL;
  const JanetKV * kvs = NULL;
  int32_t len;
  int32_t cap = 0;
  unsigned int nbits = 0;
  int exponent = 0;
  janet_dictionary_view(argv[0], &kvs, &len, &cap);
  while ((kv = janet_dictionary_next(kvs, cap, kv)))
  {
    if (janet_is_byte_typed(kv->key))
    {
      JanetByteView key = janet_to_bytes(kv->key);
      if (janet_byte_cstrcmp_insensitive(key, "type") == 0)
      {
        // public, private
      }
      else if (janet_byte_cstrcmp_insensitive(key, "version") == 0)
      {
        // check pkcs1_versions
      }
      else if (janet_byte_cstrcmp_insensitive(key, "rng") == 0
        || janet_byte_cstrcmp_insensitive(key, "random") == 0)
      {
        // verify it is random, copy reference to rsa->random
      }
      else if (janet_byte_cstrcmp_insensitive(key, "mgf") == 0
        || janet_byte_cstrcmp_insensitive(key, "mgf1") == 0
        || janet_byte_cstrcmp_insensitive(key, "mask-generation-function") == 0
        || janet_byte_cstrcmp_insensitive(key, "mask") == 0)
      {
        // mbedtls_md_type_t symbol_to_alg(Janet keyword);
      }
      else if (janet_byte_cstrcmp_insensitive(key, "hash") == 0
        || janet_byte_cstrcmp_insensitive(key, "digest") == 0)
      {
        // mbedtls_md_type_t symbol_to_alg(Janet keyword);
      }
      else if (janet_byte_cstrcmp_insensitive(key, "bits") == 0)
      {

      }
      else if (janet_byte_cstrcmp_insensitive(key, "bytes") == 0)
      {
        // get bytes, set bits = bytes * 8
      }
      else if (janet_byte_cstrcmp_insensitive(key, "e") == 0
        || janet_byte_cstrcmp_insensitive(key, "exponent") == 0)
      {

      }
    }
    else
    {
      janet_panicf("Expected a keyword key in the struct or table, but got %p", kv->key);
    }
  }

  if (nbits < 128)
  {
    janet_panicf(":bits must be set to a value >= 128, or :bytes >= 16");
  }

  if ((nbits & 1) == 1)
  {
    janet_panicf(":bits may not be an odd number");
  }

  if (exponent <= 1 || ((exponent & 1) == 0))
  {
    janet_panicf(":e needs to be > 1 and be odd");
  }

  if (rsa->random == NULL)
  {
    // TODO procure a random source
  }


  return janet_wrap_nil();
}
