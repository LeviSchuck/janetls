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
#include "janetls-bignum.h"
#include "janetls-md.h"
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
static bignum_object * bignum_from_kv(const JanetKV * kv);

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
  rsa->information_class = janetls_pk_information_class_private;
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
  return janet_wrap_boolean(rsa->information_class == janetls_pk_information_class_private);
}

Janet rsa_is_public(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  return janet_wrap_boolean(rsa->information_class == janetls_pk_information_class_public);
}

Janet rsa_sign(int32_t argc, Janet * argv)
{
  janet_arity(argc, 2, 3);
  rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  if (rsa->information_class == janetls_pk_information_class_public)
  {
    janet_panicf("Public keys cannot :sign data, only :verify");
  }
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
  // TODO refactor the hashing block below
  JanetByteView bytes;
  if (alg == janetls_md_algorithm_none)
  {
    janet_smalloc(MBEDTLS_MD_MAX_SIZE);
    bytes = janet_to_bytes(argv[1]);
    if (bytes.len > MBEDTLS_MD_MAX_SIZE)
    {
      janet_panicf("When using :none which is not recommended, the size of "
        "the hash (%d) must be <= to %d", bytes.len, MBEDTLS_MD_MAX_SIZE);
    }
  }
  else
  {
    Janet result;
    check_result(janetls_md_digest(&result, alg, argv[1]));
    bytes = janet_to_bytes(result);
  }

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
  int ret = 0;
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

  JanetByteView bytes;
  if (alg == janetls_md_algorithm_none)
  {
    janet_smalloc(MBEDTLS_MD_MAX_SIZE);
    bytes = janet_to_bytes(argv[1]);
    if (bytes.len > MBEDTLS_MD_MAX_SIZE)
    {
      janet_panicf("When using :none which is not recommended, the size of "
        "the hash (%d) must be <= to %d", bytes.len, MBEDTLS_MD_MAX_SIZE);
    }
  }
  else
  {
    Janet result;
    check_result(janetls_md_digest(&result, alg, argv[1]));
    bytes = janet_to_bytes(result);
  }

  assert_verify_sign_size(rsa, alg, bytes);

  JanetByteView signature = janet_to_bytes(argv[2]);

  if (signature.len != (int32_t) rsa->ctx.len)
  {
    janet_panicf("The signature provided is not the same length as "
      "this rsa key, this key expects %d, but the signature is %d bytes.",
      rsa->ctx.len, signature.len);
  }

  ret = mbedtls_rsa_pkcs1_verify(
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
  rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  if (!janet_is_byte_typed(argv[1]))
  {
    janet_panicf("Expected a string or buffer to sign, but got %p", argv[1]);
  }
  JanetByteView plaintext = janet_to_bytes(argv[1]);
  // TODO ensure that the plaintext is under a certain length which can be
  // padded safely and correctly
  uint8_t * ciphertext = janet_smalloc(rsa->ctx.len);

  int ret = mbedtls_rsa_pkcs1_encrypt(
    &rsa->ctx,
    rsa->random ? janetls_random_rng : NULL,
    rsa->random,
    MBEDTLS_RSA_PRIVATE,
    plaintext.len,
    plaintext.bytes,
    ciphertext
    );
  if (ret != 0)
  {
    janet_sfree(ciphertext);
  }
  check_result(ret);

  Janet result = janet_wrap_string(janet_string(ciphertext, rsa->ctx.len));
  // janet_string copies the bytes, it's time to free it now.
  janet_sfree(ciphertext);

  return result;
}

Janet rsa_decrypt(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 2);
  rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  if (!janet_is_byte_typed(argv[1]))
  {
    janet_panicf("Expected a string or buffer to sign, but got %p", argv[1]);
  }
  JanetByteView ciphertext = janet_to_bytes(argv[1]);

  if (ciphertext.len != (int32_t)rsa->ctx.len)
  {
    janet_panicf("Ciphertext does not match RSA key size of %d bytes", rsa->ctx.len);
  }
  // TODO ensure that the ciphertext is under a certain length which can be
  // padded safely and correctly
  uint8_t * plaintext = janet_smalloc(rsa->ctx.len);

  size_t output_size = 0;

  int ret = mbedtls_rsa_pkcs1_decrypt(
    &rsa->ctx,
    rsa->random ? janetls_random_rng : NULL,
    rsa->random,
    MBEDTLS_RSA_PUBLIC,
    &output_size,
    ciphertext.bytes,
    plaintext,
    rsa->ctx.len
    );
  if (ret != 0)
  {
    janet_sfree(plaintext);
    return janet_wrap_nil();
  }

  Janet result = janet_wrap_string(janet_string(plaintext, output_size));
  // janet_string copies the bytes, it's time to free it now.
  janet_sfree(plaintext);

  return result;
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

  JanetTable * table = janet_table(11);

  janet_table_put(table, janet_ckeywordv("type"), janetls_search_pk_key_type_to_janet(janetls_pk_key_type_rsa));
  janet_table_put(table, janet_ckeywordv("information-class"), janetls_search_pk_information_class_to_janet(janetls_pk_information_class_public));
  janet_table_put(table, janet_ckeywordv("version"), janetls_search_rsa_pkcs1_version_to_janet(rsa->version));
  janet_table_put(table, janet_ckeywordv("digest"), janetls_search_md_supported_algorithms_to_janet(rsa->digest));

  if (rsa->random != NULL)
  {
    janet_table_put(table, janet_ckeywordv("random"), janet_wrap_abstract(rsa->random));
  }

  if (rsa->version == janetls_rsa_pkcs1_version_v21)
  {
    // the mask generation function is only relevant in PKCS#1 v2.1
    janet_table_put(table, janet_ckeywordv("mask"), janetls_search_md_supported_algorithms_to_janet(rsa->mgf1));
  }

  // The RSA modulus: n
  bignum_object * n = new_bignum();
  check_result(mbedtls_mpi_copy(&n->mpi, &rsa->ctx.N));
  janet_table_put(table, janet_ckeywordv("n"), janet_wrap_abstract(n));

  // The RSA exponent: e
  bignum_object * e = new_bignum();
  check_result(mbedtls_mpi_copy(&e->mpi, &rsa->ctx.E));
  janet_table_put(table, janet_ckeywordv("e"), janet_wrap_abstract(e));

  return janet_wrap_struct(janet_table_to_struct(table));
}

Janet rsa_export_private(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);

  JanetTable * table = janet_table(7);

  janet_table_put(table, janet_ckeywordv("type"), janetls_search_pk_key_type_to_janet(janetls_pk_key_type_rsa));
  janet_table_put(table, janet_ckeywordv("information-class"), janetls_search_pk_information_class_to_janet(janetls_pk_information_class_private));
  janet_table_put(table, janet_ckeywordv("version"), janetls_search_rsa_pkcs1_version_to_janet(rsa->version));
  janet_table_put(table, janet_ckeywordv("digest"), janetls_search_md_supported_algorithms_to_janet(rsa->digest));

  if (rsa->random != NULL)
  {
    janet_table_put(table, janet_ckeywordv("random"), janet_wrap_abstract(rsa->random));
  }

  if (rsa->version == janetls_rsa_pkcs1_version_v21)
  {
    // the mask generation function is only relevant in PKCS#1 v2.1
    janet_table_put(table, janet_ckeywordv("mask"), janetls_search_md_supported_algorithms_to_janet(rsa->mgf1));
  }

  // Public components
  // The RSA modulus: n
  bignum_object * n = new_bignum();
  check_result(mbedtls_mpi_copy(&n->mpi, &rsa->ctx.N));
  janet_table_put(table, janet_ckeywordv("n"), janet_wrap_abstract(n));

  // The RSA exponent: e
  bignum_object * e = new_bignum();
  check_result(mbedtls_mpi_copy(&e->mpi, &rsa->ctx.E));
  janet_table_put(table, janet_ckeywordv("e"), janet_wrap_abstract(e));

  // Private components
  // The RSA exponent: p
  bignum_object * p = new_bignum();
  check_result(mbedtls_mpi_copy(&p->mpi, &rsa->ctx.P));
  janet_table_put(table, janet_ckeywordv("p"), janet_wrap_abstract(p));

  // The RSA exponent: q
  bignum_object * q = new_bignum();
  check_result(mbedtls_mpi_copy(&q->mpi, &rsa->ctx.Q));
  janet_table_put(table, janet_ckeywordv("q"), janet_wrap_abstract(q));

  // The RSA exponent: d
  bignum_object * d = new_bignum();
  check_result(mbedtls_mpi_copy(&d->mpi, &rsa->ctx.D));
  janet_table_put(table, janet_ckeywordv("d"), janet_wrap_abstract(d));

  return janet_wrap_struct(janet_table_to_struct(table));
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

  int no_private_components = 1;
  int explicit_information_class = 0;
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
        janetls_pk_key_type type;
        if (janetls_search_pk_key_type(kv->value, &type) != 0)
        {
          janet_panicf("Expected :rsa for :type, but got %p", kv->value);
        }
        if (type != janetls_pk_key_type_rsa)
        {
          janet_panicf("Expected :rsa for :type, but got %p", kv->value);
        }
      }
      else if (janet_byte_cstrcmp_insensitive(key, "information-class") == 0)
      {
        // public, private
        if (janetls_search_pk_information_class(kv->value, &rsa->information_class) != 0)
        {
          janet_panicf("Expected :public or :private for :information-class, but got %p", kv->value);
        }
        explicit_information_class = 1;
      }
      else if (janet_byte_cstrcmp_insensitive(key, "version") == 0)
      {
        janetls_rsa_pkcs1_version version = janetls_rsa_pkcs1_version_v15;
        if (janetls_search_rsa_pkcs1_version(kv->value, &version) != 0)
        {
          janet_panicf("Expected :pkcs1-v1.5 or :pkcs1-v2.1 for :version, but got %p", kv->value);
        }
        rsa->version = version;
      }
      else if (janet_byte_cstrcmp_insensitive(key, "rng") == 0
        || janet_byte_cstrcmp_insensitive(key, "random") == 0)
      {
        random_object * random = janet_checkabstract(kv->value, &random_object_type);
        if (random == NULL)
        {
          janet_panicf("Expected a janetls/random object but got %p", kv->value);
        }
        rsa->random = random;
      }
      else if (janet_byte_cstrcmp_insensitive(key, "mgf") == 0
        || janet_byte_cstrcmp_insensitive(key, "mgf1") == 0
        || janet_byte_cstrcmp_insensitive(key, "mask-generation-function") == 0
        || janet_byte_cstrcmp_insensitive(key, "mask") == 0)
      {
        janetls_md_algorithm mgf1 = janetls_md_algorithm_none;
        if (janetls_search_md_supported_algorithms(kv->value, &mgf1) != 0)
        {
          janet_panicf("Expected a value from janetls/md/algorithms for %p, but got %p", kv->key, kv->value);
        }
        rsa->mgf1 = mgf1;
      }
      else if (janet_byte_cstrcmp_insensitive(key, "hash") == 0
        || janet_byte_cstrcmp_insensitive(key, "digest") == 0)
      {
        janetls_md_algorithm digest = janetls_md_algorithm_none;
        if (janetls_search_md_supported_algorithms(kv->value, &digest) != 0)
        {
          janet_panicf("Expected a value from janetls/md/algorithms for %p, but got %p", kv->key, kv->value);
        }
        rsa->digest = digest;
      }
      else if (janet_byte_cstrcmp_insensitive(key, "n") == 0)
      {
        bignum_object * num = bignum_from_kv(kv);
        check_result(mbedtls_rsa_import(&rsa->ctx, &num->mpi, NULL, NULL, NULL, NULL));
      }
      else if (janet_byte_cstrcmp_insensitive(key, "e") == 0)
      {
        bignum_object * num = bignum_from_kv(kv);
        check_result(mbedtls_rsa_import(&rsa->ctx, NULL, NULL, NULL, NULL, &num->mpi));
      }
      else if (janet_byte_cstrcmp_insensitive(key, "p") == 0)
      {
        bignum_object * num = bignum_from_kv(kv);
        check_result(mbedtls_rsa_import(&rsa->ctx, NULL, &num->mpi, NULL, NULL, NULL));
        no_private_components = 0;
      }
      else if (janet_byte_cstrcmp_insensitive(key, "q") == 0)
      {
        bignum_object * num = bignum_from_kv(kv);
        check_result(mbedtls_rsa_import(&rsa->ctx, NULL, NULL, &num->mpi, NULL, NULL));
        no_private_components = 0;
      }
      else if (janet_byte_cstrcmp_insensitive(key, "d") == 0)
      {
        bignum_object * num = bignum_from_kv(kv);
        check_result(mbedtls_rsa_import(&rsa->ctx, NULL, NULL, NULL, &num->mpi, NULL));
        no_private_components = 0;
      }
      // other parameters dq, dp, qp are not importable in mbedtls
      // These are derived in the rsa complete function
    }
    else
    {
      janet_panicf("Expected a keyword key in the struct or table, but got %p", kv->key);
    }
  }

  if (rsa->version == janetls_rsa_pkcs1_version_v15)
  {
    rsa_set_pkcs_v15(rsa);
  }
  else if (rsa->version == janetls_rsa_pkcs1_version_v21)
  {
    rsa_set_pkcs_v21(rsa, rsa->mgf1);
  }

  if (rsa->information_class == janetls_pk_information_class_private
    && no_private_components)
  {
    if (explicit_information_class)
    {
      janet_panic("The imported key was specified as :private but lacked "
        "rsa private components, it should have the :information-class as "
        ":public");
    }
    else
    {
      rsa->information_class = janetls_pk_information_class_public;
    }
  }

  // Validate the key
  check_result(mbedtls_rsa_complete(&rsa->ctx));

  if (rsa->random == NULL)
  {
    rsa->random = janetls_new_random();
  }

  return janet_wrap_abstract(rsa);
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
  int exponent = 0x10001;

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
    // Random will assist the concept of "blinding" in v1.5
    // It is necessary in v2.1
    rsa->random = random;
  }

  rsa->digest = digest;
  // This is a new key made on this machine
  // it will have private components
  rsa->information_class = janetls_pk_information_class_private;
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

static bignum_object * bignum_from_kv(const JanetKV * kv)
{
  Janet bignum = unknown_to_bignum_opt(kv->value, 0, 10);
  if (janet_checktype(bignum, JANET_NIL))
  {
    janet_panicf("Expected a bignum for %p, but got %p", kv->key, kv->value);
  }
  return janet_unwrap_abstract(bignum);
}