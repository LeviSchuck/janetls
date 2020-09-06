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
#include "mbedtls/md.h"


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

static int rsa_set_pkcs_v15(rsa_object * rsa);
static int rsa_set_pkcs_v21(rsa_object * rsa, janetls_md_algorithm md);
static int read_integer(Janet key, Janet value);
static void assert_verify_sign_size(rsa_object * rsa, janetls_md_algorithm alg, JanetByteView bytes);

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
  {"version", rsa_get_version},
  {"mgf", rsa_get_mgf},
  {"digest", rsa_get_digest},
  {"encrypt", rsa_encrypt},
  {"decrypt", rsa_decrypt},
  {"verify", rsa_verify},
  {"sign", rsa_sign},
  {"bits", rsa_get_sizebits},
  {"bytes", rsa_get_sizebytes},
  {"export-public", rsa_export_public},
  {"export-private", rsa_export_private},
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
  rsa->type = janetls_pk_key_type_public;
  rsa->version = janetls_rsa_pkcs1_version_v15;
  rsa->digest = janetls_md_algorithm_none;
  rsa->mgf1 = janetls_md_algorithm_none;
  return rsa;
}

int rsa_set_pkcs_v15(rsa_object * rsa)
{
  mbedtls_rsa_set_padding(&rsa->ctx, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
  rsa->version = janetls_rsa_pkcs1_version_v15;
  rsa->mgf1 = janetls_md_algorithm_none;
  // in case return codes are used later
  return 0;
}

int rsa_set_pkcs_v21(rsa_object * rsa, janetls_md_algorithm md)
{
  mbedtls_rsa_set_padding(&rsa->ctx, MBEDTLS_RSA_PKCS_V21, (mbedtls_md_type_t)md);
  rsa->version = janetls_rsa_pkcs1_version_v21;
  rsa->mgf1 = md;

  // in case return codes are used later
  return 0;
}

static const JanetReg cfuns[] =
{
  {"rsa/private?", rsa_is_private, ""},
  {"rsa/public?", rsa_is_public, ""},
  {"rsa/sign", rsa_sign, ""},
  {"rsa/verify", rsa_verify, ""},
  {"rsa/encrypt", rsa_encrypt, ""},
  {"rsa/decrypt", rsa_decrypt, ""},
  {"rsa/get-version", rsa_get_version, ""},
  {"rsa/get-mgf", rsa_get_mgf, ""},
  {"rsa/get-digest", rsa_get_digest, ""},
  {"rsa/get-size-bits", rsa_get_sizebits, ""},
  {"rsa/get-size-bytes", rsa_get_sizebytes, ""},
  {"rsa/export-private", rsa_export_private, ""},
  {"rsa/export-public", rsa_export_public, ""},
  {"rsa/import", rsa_import, ""},
  {"rsa/generate", rsa_generate, ""},
  {NULL, NULL, NULL}
};

void submod_rsa(JanetTable * env)
{
  janet_cfuns(env, "janetls", cfuns);
}


Janet rsa_is_private(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  return janet_wrap_boolean(rsa->type == janetls_pk_key_type_private);
}

Janet rsa_is_public(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  return janet_wrap_boolean(rsa->type == janetls_pk_key_type_public);
}

Janet rsa_sign(int32_t argc, Janet * argv)
{
  janet_arity(argc, 2, 3);
  rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  if (!janet_is_byte_typed(argv[1]))
  {
    janet_panicf("Expected a string or buffer to sign, but got %p", argv[1]);
  }
  janetls_md_algorithm alg = rsa->digest;
  if (argc > 2)
  {
    check_result(janetls_search_md_supported_algorithms(argv[2], &alg));
  }
  else if (alg == janetls_md_algorithm_none)
  {
    janet_panicf("This RSA object has no default digest, "
        "see janetls/md/algorithms for an expected value");
  }
  JanetByteView bytes = janet_to_bytes(argv[1]);
  assert_verify_sign_size(rsa, alg, bytes);
  uint8_t * signature = janet_smalloc(rsa->ctx.len);

  int ret = mbedtls_rsa_pkcs1_sign(
    &rsa->ctx,
    rsa->random ? janetls_random_rng : NULL,
    rsa->random,
    MBEDTLS_RSA_PRIVATE,
    (mbedtls_md_type_t)alg,
    bytes.len,
    bytes.bytes,
    signature
    );
  if (ret != 0)
  {
    janet_sfree(signature);
  }
  check_result(ret);

  Janet result = janet_wrap_string(janet_string(signature, rsa->ctx.len));
  // janet_string copies the bytes, it's time to free it now.
  janet_sfree(signature);

  return result;
}

Janet rsa_verify(int32_t argc, Janet * argv)
{
  janet_arity(argc, 3, 4);
  rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  if (!janet_is_byte_typed(argv[1]))
  {
    janet_panicf("Expected a string or buffer to sign, but got %p", argv[1]);
  }
  if (!janet_is_byte_typed(argv[2]))
  {
    janet_panicf("Expected a string or buffer to sign, but got %p", argv[1]);
  }
  janetls_md_algorithm alg = rsa->digest;
  if (argc > 3)
  {
    check_result(janetls_search_md_supported_algorithms(argv[3], &alg));
  }
  else if (alg == janetls_md_algorithm_none)
  {
    janet_panicf("This RSA object has no default digest, "
        "see janetls/md/algorithms for an expected value");
  }
  JanetByteView bytes = janet_to_bytes(argv[1]);

  assert_verify_sign_size(rsa, alg, bytes);

  JanetByteView signature = janet_to_bytes(argv[2]);

  if (signature.len != (int32_t) rsa->ctx.len)
  {
    janet_panicf("The signature provided is not the same length as "
      "this rsa key, this key expects %d, but the signature is %d bytes.",
      rsa->ctx.len, signature.len);
  }

  int ret = mbedtls_rsa_pkcs1_verify(
    &rsa->ctx,
    janetls_random_rng,
    rsa->random,
    MBEDTLS_RSA_PUBLIC,
    (mbedtls_md_type_t)alg,
    bytes.len,
    bytes.bytes,
    signature.bytes
    );

  // Don't indicate why it failed.
  // Also simplifies verify checks, no need to try catch.
  return janet_wrap_boolean(ret == 0);
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
  return janetls_search_rsa_pkcs1_version_to_janet(rsa->version);
}

Janet rsa_get_mgf(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  return janetls_search_md_supported_algorithms_to_janet(rsa->mgf1);
}

Janet rsa_get_digest(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  return janetls_search_md_supported_algorithms_to_janet(rsa->digest);
}

Janet rsa_get_sizebits(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  return janet_wrap_number(rsa->ctx.len * 8);
}

Janet rsa_get_sizebytes(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  return janet_wrap_number(rsa->ctx.len);
}

Janet rsa_export_public(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  (void)rsa;
  return janet_wrap_nil();
}

Janet rsa_export_private(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  (void)rsa;
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
  janet_arity(argc, 0, 1);

  if (argc > 0)
  {
    if (!janet_checktype(argv[0], JANET_TABLE)
      && !janet_checktype(argv[0], JANET_STRUCT))
    {
      janet_panic("Expected a struct or table");
    }
  }
  rsa_object * rsa = new_rsa();
  random_object * random = NULL;
  (void)random; // todo remove when used
  // The type will always be private
  janetls_rsa_pkcs1_version version = janetls_rsa_pkcs1_version_v15;
  janetls_md_algorithm mgf1 = janetls_md_algorithm_none;
  // RS256 is a common JWT algorithm combo.
  janetls_md_algorithm digest = janetls_md_algorithm_sha256;
  // also most common
  unsigned int nbits = 2048;
  // most common
  int exponent = 0x100001;

  const JanetKV * kv = NULL;
  const JanetKV * kvs = NULL;
  int32_t len;
  int32_t cap = 0;
  if (argc > 0)
  {
    janet_dictionary_view(argv[0], &kvs, &len, &cap);
  }
  while ((kv = janet_dictionary_next(kvs, cap, kv)))
  {
    if (janet_is_byte_typed(kv->key))
    {
      JanetByteView key = janet_to_bytes(kv->key);
      if (janet_byte_cstrcmp_insensitive(key, "version") == 0)
      {
        // check pkcs1_versions
        if (janetls_search_rsa_pkcs1_version(kv->value, &version) != 0)
        {
          janet_panicf("Expected :pkcs1-v1.5 or :pkcs1-v2.1 for :version, but got %p", kv->value);
        }
      }
      else if (janet_byte_cstrcmp_insensitive(key, "rng") == 0
        || janet_byte_cstrcmp_insensitive(key, "random") == 0)
      {
        // verify it is random, copy reference to rsa->random
        void * value_random = janet_checkabstract(kv->value, &random_object_type);
        if (value_random == NULL)
        {
          janet_panicf("Expected a janetls/random but got %p", kv->value);
        }
        random = (random_object *) value_random;
        rsa->random = value_random;
      }
      else if (janet_byte_cstrcmp_insensitive(key, "mgf") == 0
        || janet_byte_cstrcmp_insensitive(key, "mgf1") == 0
        || janet_byte_cstrcmp_insensitive(key, "mask-generation-function") == 0
        || janet_byte_cstrcmp_insensitive(key, "mask") == 0)
      {
        if (janetls_search_md_supported_algorithms(kv->value, &mgf1) != 0)
        {
          janet_panicf("Given algorithm %p is not expected for %p, please review "
            "janetls/md/algorithms for supported values", kv->key, kv->value);
        }
      }
      else if (janet_byte_cstrcmp_insensitive(key, "hash") == 0
        || janet_byte_cstrcmp_insensitive(key, "digest") == 0)
      {
        if (janetls_search_md_supported_algorithms(kv->value, &digest) != 0)
        {
          janet_panicf("Given algorithm %p is not expected for %p, please review "
            "janetls/md/algorithms for supported values", kv->key, kv->value);
        }
      }
      else if (janet_byte_cstrcmp_insensitive(key, "bits") == 0)
      {
        nbits = read_integer(kv->key, kv->value);
      }
      else if (janet_byte_cstrcmp_insensitive(key, "bytes") == 0)
      {
        nbits = read_integer(kv->key, kv->value) * 8;
      }
      else if (janet_byte_cstrcmp_insensitive(key, "e") == 0
        || janet_byte_cstrcmp_insensitive(key, "exponent") == 0)
      {
        exponent = read_integer(kv->key, kv->value);
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

  if (random == NULL)
  {
    random = janetls_new_random();
  }

  // Random will assist the concept of "blinding" in v1.5
  // It is necessary in v2.1
  rsa->random = random;

  rsa->digest = digest;
  // This is a new key made on this machine
  // it will have private components
  rsa->type = janetls_pk_key_type_private;
  switch (version)
  {
    case janetls_rsa_pkcs1_version_v15:
    {
      rsa_set_pkcs_v15(rsa);
      break;
    }
    case janetls_rsa_pkcs1_version_v21:
    {
      rsa_set_pkcs_v21(rsa, mgf1);
      break;
    }
    default:
    {
      janet_panic("Internal error, the rsa version was corrupted");
      break;
    }
  }
  // Finally generate the rsa key
  check_result(mbedtls_rsa_gen_key(&rsa->ctx, janetls_random_rng, random, nbits, exponent));

  return janet_wrap_abstract(rsa);
}

int read_integer(Janet key, Janet value)
{
  if (janet_checktype(value, JANET_NUMBER))
  {
    double number = janet_unwrap_number(value);
    int result = number;
    if (number != result)
    {
      janet_panicf("Expected a whole number for %p, but got %p", key, value);
    }
    return result;
  }
  else
  {
    janet_panicf("Expected a number for %p, but got %p", key, value);
  }
  // unreachable
  return -1;
}

static void assert_verify_sign_size(rsa_object * rsa, janetls_md_algorithm alg, JanetByteView bytes)
{
  // None has been passed explicitly by this point.
  // refer to https://www.foo.be/docs/opensst/ref/pkcs/pkcs-1/pkcs-1v2-1d1.pdf
  // section 9.1.2.1 for v1.5

  int minPadding = 10;
  if (rsa->version == janetls_rsa_pkcs1_version_v21)
  {
    // refer to section 9.1.1.1
    const mbedtls_md_info_t * info = mbedtls_md_info_from_type((mbedtls_md_type_t)rsa->mgf1);
    if (info == NULL)
    {
      janet_panicf("Expected a mask generation function, but no algorithm is present");
    }
    int hash_size = mbedtls_md_get_size(info);
    minPadding = hash_size + 1;
  }
  if (alg == janetls_md_algorithm_none
    // safe PKCS#1 v1.5 requires at least 10 bytes to prefix
    && bytes.len > (int32_t) (rsa->ctx.len - minPadding)
    // Let's not sign anything shorter than an MD5.
    && bytes.len < 16)
  {
    // It is possible to sign an existing body,
    // if it is within safe bounds for padding.
    janet_panicf("When directly signing content, which is generally unsafe, "
      "the size was outside of acceptable bounds. The size observed is %d",
      bytes.len);
  }
}