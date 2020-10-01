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
static Janet rsa_is_private(int32_t argc, Janet * argv);
static Janet rsa_is_public(int32_t argc, Janet * argv);
static Janet rsa_information_class(int32_t argc, Janet * argv);
static Janet rsa_type(int32_t argc, Janet * argv);
static Janet rsa_sign(int32_t argc, Janet * argv);
static Janet rsa_verify(int32_t argc, Janet * argv);
static Janet rsa_encrypt(int32_t argc, Janet * argv);
static Janet rsa_decrypt(int32_t argc, Janet * argv);
static Janet rsa_get_version(int32_t argc, Janet * argv);
static Janet rsa_get_mgf(int32_t argc, Janet * argv);
static Janet rsa_get_digest(int32_t argc, Janet * argv);
static Janet rsa_get_sizebits(int32_t argc, Janet * argv);
static Janet rsa_get_sizebytes(int32_t argc, Janet * argv);
static Janet rsa_export_public(int32_t argc, Janet * argv);
static Janet rsa_export_private(int32_t argc, Janet * argv);
static Janet rsa_import(int32_t argc, Janet * argv);
static Janet rsa_generate(int32_t argc, Janet * argv);

static int rsa_set_pkcs_v15(janetls_rsa_object * rsa);
static int rsa_set_pkcs_v21(janetls_rsa_object * rsa, janetls_md_algorithm md);
static int read_integer(Janet key, Janet value);
static void assert_verify_sign_size(janetls_rsa_object * rsa, janetls_md_algorithm alg, JanetByteView bytes);
static janetls_bignum_object * bignum_from_kv(const JanetKV * kv);
static JanetByteView signature_bytes(Janet data, janetls_md_algorithm alg);

static JanetAbstractType rsa_object_type = {
  "janetls/rsa",
  rsa_gc_fn,
  rsa_gcmark,
  rsa_get_fn,
  JANET_ATEND_GET
};

static JanetMethod rsa_methods[] = {
  {"private?", rsa_is_private},
  {"public?", rsa_is_public},
  {"information-class", rsa_information_class},
  {"type", rsa_type},
  {"version", rsa_get_version},
  {"mask", rsa_get_mgf},
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

static int rsa_get_fn(void * data, Janet key, Janet * out)
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
  janetls_rsa_object * rsa = (janetls_rsa_object *)data;
  mbedtls_rsa_free(&rsa->ctx);
  return 0;
}

static int rsa_gcmark(void *data, size_t len)
{
  (void)len;
  janetls_rsa_object * rsa = (janetls_rsa_object *)data;

  if (rsa->random != NULL)
  {
    janet_mark(janet_wrap_abstract(rsa->random));
  }

  return 0;
}

janetls_rsa_object * new_rsa()
{
  janetls_rsa_object * rsa = janet_abstract(&rsa_object_type, sizeof(janetls_rsa_object));
  memset(rsa, 0, sizeof(janetls_rsa_object));
  // By default PKCS#1 v1.5 encoded
  // The last parameter is the hash algorithm used for v2.1.
  // Since we are initializing to v1.5, that parameter is not used.
  mbedtls_rsa_init(&rsa->ctx, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
  rsa->version = janetls_rsa_pkcs1_version_v15;
  return rsa;
}

JanetAbstractType * janetls_rsa_object_type()
{
  return &rsa_object_type;
}

int rsa_set_pkcs_v15(janetls_rsa_object * rsa)
{
  mbedtls_rsa_set_padding(&rsa->ctx, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
  rsa->version = janetls_rsa_pkcs1_version_v15;
  rsa->mgf1 = janetls_md_algorithm_none;
  // in case return codes are used later
  return 0;
}

int rsa_set_pkcs_v21(janetls_rsa_object * rsa, janetls_md_algorithm md)
{
  mbedtls_rsa_set_padding(&rsa->ctx, MBEDTLS_RSA_PKCS_V21, (mbedtls_md_type_t)md);
  rsa->version = janetls_rsa_pkcs1_version_v21;
  rsa->mgf1 = md;

  // in case return codes are used later
  return 0;
}

static const JanetReg cfuns[] =
{
  {"rsa/private?", rsa_is_private, "(janetls/rsa/private? rsa)\n\n"
    "Returns true when the key is a private information class.\n"
    "When true, it can perform both public and private operations."
    },
  {"rsa/public?", rsa_is_public, "(janetls/rsa/public? rsa)\n\n"
    "Returns true when the key is a private information class.\n"
    "When true, it can perform only public operations, "
    "such as verify, and encrypt."
    },
  {"rsa/information-class", rsa_information_class, "(janetls/rsa/information-class rsa)\n\n"
    "Returns :public or :private depending on the components this key has."
    },
  {"rsa/sign", rsa_sign, "(janetls/rsa/sign rsa data &opt alg)\n\n"
    "A Private key operation, sign the input data with the given key.\n"
    "When an algorithm is provided, it overrides the default algorithm on "
    "this key for signatures. It's probably best to set the algorithm "
    "on key import or generation instead.\n"
    "A binary string is returned, this is the signature to provide to "
    "a verifier."
    },
  {"rsa/verify", rsa_verify, "(janetls/rsa/verify rsa data sig &opt alg)\n\n"
    "A Public key operation, verify the input data with the given key "
    "with the binary signature.\n"
    "When an algorithm is provided, it overrides the default algorithm on "
    "this key for signatures. It's probably best to set the algorithm "
    "on key import or generation instead.\n"
    "Usually a false return when the data has been modified, or the signature "
    "was made with another key (or is just noise).\n"
    "A true or false is returned."
    },
  {"rsa/encrypt", rsa_encrypt, "(janetls/rsa/verify rsa data)\n\n"
    "A Public key operation, encrypt the input plaintext with the given key.\n"
    "This should only be used to encrypt small portions of data, such as "
    "a symmetric key. (A common use case.)\n"
    "If the data is too large, a panic will happen.\n"
    "This function handles all padding, blinding, masking, etc. as part of "
    "the given key.\n"
    "The result is a binary string of the ciphertext."
    },
  {"rsa/decrypt", rsa_decrypt, "(janetls/rsa/verify rsa data)\n\n"
    "A Private key operation, decrypt the ciphertext with the given key.\n"
    "The result is a binary string of the decrypted content when successful.\n"
    "Otherwise, nil will be returned."
    },
  {"rsa/version", rsa_get_version, "(janetls/rsa/version rsa)\n\n"
    "Also accessible via (:version rsa)\n"
    "Gets whether this is PKCS#1 v1.5 or v2.1, with the values as listed in "
    "janetls/rsa/versions."
    },
  {"rsa/versions", janetls_search_rsa_pkcs1_version_set, "(janetls/rsa/versions)\n\n"
    "Enumerates PKCS#1 versions supported.\n"
    "pkcs1-v1.5 is used for most RSA signatures in the wild, it can be used "
    "for encryption as well but is less advised due to many attacks"
    "discovered.\n"
    "pkcs1-v2.1 is most is used for PSS signatures and OAEP encryption."
    },
  {"rsa/mask", rsa_get_mgf, "(janetls/rsa/mask rsa)\n\n"
    "Gets the digest algorithm used for masking in PKCS#1 v2.1 signatures "
    "and encryption.\n"
    "Algorithms are as listed in janetls/md/algorithms."
    },
  {"rsa/digest", rsa_get_digest, "(janetls/rsa/digest rsa)\n\n"
    "Gets the digest algorithm used for hashing in signatures"
    "Algorithms are as listed in janetls/md/algorithms."
    },
  {"rsa/bits", rsa_get_sizebits, "(janetls/rsa/bits rsa)\n\n"
    "Returns the bit count of the modulus in this key, for example: 2048 bit "
    "keys return 2048 here."
    },
  {"rsa/bytes", rsa_get_sizebytes, "(janetls/rsa/bytes rsa)\n\n"
    "Returns the bit count of the modulus in this key, for example: 2048 bit "
    "keys return 256 here."
    },
  {"rsa/export-private", rsa_export_private, "(janetls/rsa/export-private rsa)\n\n"
    "Returns a struct with all the options to import this private key, review "
    "the documentation on janetls/rsa/import for full details."
    "Will panic if a public key is provided.\n"
    },
  {"rsa/export-public", rsa_export_public, ""
    "Returns a struct with all the options to import this key as a public key, "
    " review the documentation on janetls/rsa/import for full details."
    },
  {"rsa/import", rsa_import, "(janetls/rsa/import opts)\n\n"
    "Create an rsa object with the parameters in this opts struct or table.\n"
    "The following options are involved: \n"
    ":information-class - :public or :private, this will be deduced if "
    "omitted by whether private components were provided.\n"
    ":version - refer to janetls/rsa/versions for options\n"
    ":digest - Which hash function to use for signatures, by default SHA-256\n"
    ":mask - Which hash function to use for masking, by default SHA-256 in "
    "PKCS#1 v2.1\n"
    ":n - The modulus as a bignum.\n"
    ":e - The exponent, by default 65537.\n"
    ":d - Private exponent, a private component.\n"
    ":p - Prime1, a private component.\n"
    ":q - Prime2 a private component.\n"
    "Note that other parameters (dp, dq, qp) are not accepted, and are "
    "derived. Other primes are not accepted.\n"
    ":type - This will always be :rsa, for later generic key classification.\n"
    },
  {"rsa/generate", rsa_generate, "(janetls/rsa/generate opts)\n\n"
    "A subset of the options used in janetls/rsa/import are used here, for "
    "details, review the documentation on janetls/rsa/import.\n"
    "The options supported are: :version, :mask, :digest, :e.\n"
    "Additional options not in janetls/rsa/import are: :bits and :bytes."
    ":bits - By default 2048, should be even.\n"
    ":bytes - Replaces :bits, multiplied by 8. "
    "So :bytes 256 will be equivalent to :bits 2048.\n"
    "The generated key will always be of the private information class."
    },
  {NULL, NULL, NULL}
};

void submod_rsa(JanetTable * env)
{
  janet_cfuns(env, "janetls", cfuns);
  janet_register_abstract_type(&rsa_object_type);
}


static Janet rsa_is_private(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  return janet_wrap_boolean(rsa->information_class == janetls_pk_information_class_private);
}

static Janet rsa_is_public(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  return janet_wrap_boolean(rsa->information_class == janetls_pk_information_class_public);
}

static Janet rsa_information_class(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  return janetls_search_pk_information_class_to_janet(rsa->information_class);
}

static Janet rsa_type(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  (void)argv;
  return janet_ckeywordv("rsa");
}

static Janet rsa_sign(int32_t argc, Janet * argv)
{
  janet_arity(argc, 2, 3);
  janetls_rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
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
  JanetByteView bytes = signature_bytes(argv[1], alg);

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

static Janet rsa_verify(int32_t argc, Janet * argv)
{
  int ret = 0;
  janet_arity(argc, 3, 4);
  janetls_rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
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

  JanetByteView bytes = signature_bytes(argv[1], alg);

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
    rsa->random ? janetls_random_rng : NULL,
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

static Janet rsa_encrypt(int32_t argc, Janet * argv)
{
  // refer to https://www.foo.be/docs/opensst/ref/pkcs/pkcs-1/pkcs-1v2-1d1.pdf
  // for sizes
  janet_fixarity(argc, 2);
  janetls_rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  if (!janet_is_byte_typed(argv[1]))
  {
    janet_panicf("Expected a string or buffer to sign, but got %p", argv[1]);
  }
  JanetByteView plaintext = janet_to_bytes(argv[1]);
  // v1.5 as described in section 7.2.1
  int32_t max_size = rsa->ctx.len - 11;

  if (rsa->version == janetls_rsa_pkcs1_version_v21)
  {
    const mbedtls_md_info_t * info = mbedtls_md_info_from_type((mbedtls_md_type_t)rsa->mgf1);
    if (info == NULL)
    {
      janet_panicf("Expected a mask generation function, but no algorithm "
        "is present");
    }
    int32_t hash_size = mbedtls_md_get_size(info);

    // v2.1 as described in section 7.1.1
    max_size = rsa->ctx.len - 2 - (2 * hash_size);
  }

  if (plaintext.len > max_size)
  {
    janet_panicf("The max size a plaintext can be with this key is %d bytes, "
      "but the message is %d bytes", max_size, plaintext.len);
  }
  uint8_t * ciphertext = janet_smalloc(rsa->ctx.len);

  int ret = mbedtls_rsa_pkcs1_encrypt(
    &rsa->ctx,
    rsa->random ? janetls_random_rng : NULL,
    rsa->random,
    MBEDTLS_RSA_PUBLIC,
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

static Janet rsa_decrypt(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 2);
  janetls_rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  if (!janet_is_byte_typed(argv[1]))
  {
    janet_panicf("Expected a string or buffer to sign, but got %p", argv[1]);
  }
  JanetByteView ciphertext = janet_to_bytes(argv[1]);

  if (ciphertext.len != (int32_t)rsa->ctx.len)
  {
    janet_panicf("Ciphertext does not match RSA key size of %d bytes", rsa->ctx.len);
  }
  uint8_t * plaintext = janet_smalloc(rsa->ctx.len);

  size_t output_size = 0;

  int ret = mbedtls_rsa_pkcs1_decrypt(
    &rsa->ctx,
    rsa->random ? janetls_random_rng : NULL,
    rsa->random,
    MBEDTLS_RSA_PRIVATE,
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

static Janet rsa_get_version(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  return janetls_search_rsa_pkcs1_version_to_janet(rsa->version);
}

static Janet rsa_get_mgf(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  return janetls_search_md_supported_algorithms_to_janet(rsa->mgf1);
}

static Janet rsa_get_digest(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  return janetls_search_md_supported_algorithms_to_janet(rsa->digest);
}

static Janet rsa_get_sizebits(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  return janet_wrap_number(rsa->ctx.len * 8);
}

static Janet rsa_get_sizebytes(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);
  return janet_wrap_number(rsa->ctx.len);
}

static Janet rsa_export_public(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);

  JanetTable * table = janet_table(11);

  janet_table_put(table, janet_ckeywordv("type"), janetls_search_pk_key_type_to_janet(janetls_pk_key_type_rsa));
  janet_table_put(table, janet_ckeywordv("information-class"), janetls_search_pk_information_class_to_janet(janetls_pk_information_class_public));
  janet_table_put(table, janet_ckeywordv("version"), janetls_search_rsa_pkcs1_version_to_janet(rsa->version));
  janet_table_put(table, janet_ckeywordv("digest"), janetls_search_md_supported_algorithms_to_janet(rsa->digest));

  if (rsa->version == janetls_rsa_pkcs1_version_v21)
  {
    // the mask generation function is only relevant in PKCS#1 v2.1
    janet_table_put(table, janet_ckeywordv("mask"), janetls_search_md_supported_algorithms_to_janet(rsa->mgf1));
  }

  // The RSA modulus: n
  janetls_bignum_object * n = janetls_new_bignum();
  check_result(mbedtls_mpi_copy(&n->mpi, &rsa->ctx.N));
  janet_table_put(table, janet_ckeywordv("n"), janet_wrap_abstract(n));

  // The RSA exponent: e
  janetls_bignum_object * e = janetls_new_bignum();
  check_result(mbedtls_mpi_copy(&e->mpi, &rsa->ctx.E));
  janet_table_put(table, janet_ckeywordv("e"), janet_wrap_abstract(e));

  return janet_wrap_struct(janet_table_to_struct(table));
}

static Janet rsa_export_private(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_rsa_object * rsa = janet_getabstract(argv, 0, &rsa_object_type);

  if (rsa->information_class == janetls_pk_information_class_public)
  {
    janet_panic("Cannot export a private key from a public key");
  }

  JanetTable * table = janet_table(10);

  janet_table_put(table, janet_ckeywordv("type"), janetls_search_pk_key_type_to_janet(janetls_pk_key_type_rsa));
  janet_table_put(table, janet_ckeywordv("information-class"), janetls_search_pk_information_class_to_janet(janetls_pk_information_class_private));
  janet_table_put(table, janet_ckeywordv("version"), janetls_search_rsa_pkcs1_version_to_janet(rsa->version));
  janet_table_put(table, janet_ckeywordv("digest"), janetls_search_md_supported_algorithms_to_janet(rsa->digest));

  if (rsa->version == janetls_rsa_pkcs1_version_v21)
  {
    // the mask generation function is only relevant in PKCS#1 v2.1
    janet_table_put(table, janet_ckeywordv("mask"), janetls_search_md_supported_algorithms_to_janet(rsa->mgf1));
  }

  // Public components
  // The RSA modulus: n
  janetls_bignum_object * n = janetls_new_bignum();
  check_result(mbedtls_mpi_copy(&n->mpi, &rsa->ctx.N));
  janet_table_put(table, janet_ckeywordv("n"), janet_wrap_abstract(n));

  // The RSA exponent: e
  janetls_bignum_object * e = janetls_new_bignum();
  check_result(mbedtls_mpi_copy(&e->mpi, &rsa->ctx.E));
  janet_table_put(table, janet_ckeywordv("e"), janet_wrap_abstract(e));

  // Private components
  // The RSA exponent: p
  janetls_bignum_object * p = janetls_new_bignum();
  check_result(mbedtls_mpi_copy(&p->mpi, &rsa->ctx.P));
  janet_table_put(table, janet_ckeywordv("p"), janet_wrap_abstract(p));

  // The RSA exponent: q
  janetls_bignum_object * q = janetls_new_bignum();
  check_result(mbedtls_mpi_copy(&q->mpi, &rsa->ctx.Q));
  janet_table_put(table, janet_ckeywordv("q"), janet_wrap_abstract(q));

  // The RSA exponent: d
  janetls_bignum_object * d = janetls_new_bignum();
  check_result(mbedtls_mpi_copy(&d->mpi, &rsa->ctx.D));
  janet_table_put(table, janet_ckeywordv("d"), janet_wrap_abstract(d));

  // These aren't imported back, but they are part of the standard.
  // The RSA exponent: dp = d mod (p-1)
  janetls_bignum_object * dp = janetls_new_bignum();
  check_result(mbedtls_mpi_copy(&dp->mpi, &rsa->ctx.DP));
  janet_table_put(table, janet_ckeywordv("dp"), janet_wrap_abstract(dp));

  janetls_bignum_object * dq = janetls_new_bignum();
  check_result(mbedtls_mpi_copy(&dq->mpi, &rsa->ctx.DQ));
  janet_table_put(table, janet_ckeywordv("dq"), janet_wrap_abstract(dq));

  janetls_bignum_object * qp = janetls_new_bignum();
  check_result(mbedtls_mpi_copy(&qp->mpi, &rsa->ctx.QP));
  janet_table_put(table, janet_ckeywordv("qp"), janet_wrap_abstract(qp));

  return janet_wrap_struct(janet_table_to_struct(table));
}

static Janet rsa_import(int32_t argc, Janet * argv)
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
  janet_fixarity(argc, 1);

  if (!janet_checktype(argv[0], JANET_TABLE)
    && !janet_checktype(argv[0], JANET_STRUCT))
  {
    janet_panic("Expected a struct or table");
  }

  janetls_rsa_object * rsa = new_rsa();

  int no_private_components = 1;
  uint8_t imported_p = 0;
  uint8_t imported_q = 0;
  uint8_t imported_d = 0;
  int explicit_information_class = 0;
  int explicit_mgf1 = 0;
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
        if (mgf1 == janetls_md_algorithm_none)
        {
          janet_panicf("The mask generation function cannot be %p for %p", kv->value, kv->key);
        }
        rsa->mgf1 = mgf1;
        explicit_mgf1 = 1;
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
        janetls_bignum_object * num = bignum_from_kv(kv);
        check_result(mbedtls_rsa_import(&rsa->ctx, &num->mpi, NULL, NULL, NULL, NULL));
      }
      else if (janet_byte_cstrcmp_insensitive(key, "e") == 0)
      {
        janetls_bignum_object * num = bignum_from_kv(kv);
        check_result(mbedtls_rsa_import(&rsa->ctx, NULL, NULL, NULL, NULL, &num->mpi));
      }
      else if (janet_byte_cstrcmp_insensitive(key, "p") == 0)
      {
        janetls_bignum_object * num = bignum_from_kv(kv);
        check_result(mbedtls_rsa_import(&rsa->ctx, NULL, &num->mpi, NULL, NULL, NULL));
        no_private_components = 0;
        imported_p = 1;
      }
      else if (janet_byte_cstrcmp_insensitive(key, "q") == 0)
      {
        janetls_bignum_object * num = bignum_from_kv(kv);
        check_result(mbedtls_rsa_import(&rsa->ctx, NULL, NULL, &num->mpi, NULL, NULL));
        no_private_components = 0;
        imported_q = 1;
      }
      else if (janet_byte_cstrcmp_insensitive(key, "d") == 0)
      {
        janetls_bignum_object * num = bignum_from_kv(kv);
        check_result(mbedtls_rsa_import(&rsa->ctx, NULL, NULL, NULL, &num->mpi, NULL));
        no_private_components = 0;
        imported_d = 1;
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
    if (rsa->mgf1 == janetls_md_algorithm_none && !explicit_mgf1)
    {
      if (rsa->digest != janetls_md_algorithm_none)
      {
        // Common tactic: same as the digest
        rsa->mgf1 = rsa->digest;
      }
      else
      {
        // Otherwise a safe default
        rsa->mgf1 = janetls_md_algorithm_sha256;
      }
    }
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
  else if (rsa->information_class != janetls_pk_information_class_private
    && !no_private_components)
  {
    if (explicit_information_class)
    {
      janet_panic("The imported key was specified as :public but included "
        "rsa private components, it should have the :information-class as "
        ":private");
    }
    if (imported_p && imported_q && imported_d)
    {
      rsa->information_class = janetls_pk_information_class_private;
    }
    else
    {
      janet_panic("The imported key does not include a full set of rsa "
        "private components, it should have :p, :q, and :d set.");
    }
  }

  // Validate the key
  check_result(mbedtls_rsa_complete(&rsa->ctx));

  rsa->random = janetls_get_random();

  return janet_wrap_abstract(rsa);
}

static Janet rsa_generate(int32_t argc, Janet * argv)
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
  janetls_rsa_object * rsa = new_rsa();
  janetls_random_object * random = NULL;
  // The type will always be private
  janetls_rsa_pkcs1_version version = janetls_rsa_pkcs1_version_v15;
  janetls_md_algorithm mgf1 = janetls_md_algorithm_sha256;
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
        if (mgf1 == janetls_md_algorithm_none)
        {
          janet_panicf("The mask generation function cannot be %p for %p", kv->value, kv->key);
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


  random = janetls_get_random();
  // Random will assist the concept of "blinding" in v1.5
  // It is necessary in v2.1
  rsa->random = random;

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

static void assert_verify_sign_size(janetls_rsa_object * rsa, janetls_md_algorithm alg, JanetByteView bytes)
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

static janetls_bignum_object * bignum_from_kv(const JanetKV * kv)
{
  Janet bignum = unknown_to_bignum_opt(kv->value, 0, 10);
  if (janet_checktype(bignum, JANET_NIL))
  {
    janet_panicf("Expected a bignum for %p, but got %p", kv->key, kv->value);
  }
  return janet_unwrap_abstract(bignum);
}

static JanetByteView signature_bytes(Janet data, janetls_md_algorithm alg)
{
  JanetByteView bytes;
  if (alg == janetls_md_algorithm_none)
  {
    janet_smalloc(MBEDTLS_MD_MAX_SIZE);
    bytes = janet_to_bytes(data);
    if (bytes.len > MBEDTLS_MD_MAX_SIZE)
    {
      janet_panicf("When using :none which is not recommended, the size of "
        "the hash (%d) must be <= to %d", bytes.len, MBEDTLS_MD_MAX_SIZE);
    }
  }
  else
  {
    Janet result;
    check_result(janetls_md_digest(&result, alg, data));
    bytes = janet_to_bytes(result);
  }
  return bytes;
}
