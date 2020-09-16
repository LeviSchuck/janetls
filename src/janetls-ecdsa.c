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
#include "janetls-ecdsa.h"
#include "janetls-md.h"
#include "janetls-asn1.h"


static int ecdsa_gc_fn(void * data, size_t len);
static int ecdsa_gcmark(void * data, size_t len);
static int ecdsa_get_fn(void * data, Janet key, Janet * out);

static Janet ecdsa_is_private(int32_t argc, Janet * argv);
static Janet ecdsa_is_public(int32_t argc, Janet * argv);
static Janet ecdsa_sign(int32_t argc, Janet * argv);
static Janet ecdsa_verify(int32_t argc, Janet * argv);
static Janet ecdsa_export_public(int32_t argc, Janet * argv);
static Janet ecdsa_export_private(int32_t argc, Janet * argv);
static Janet ecdsa_get_digest(int32_t argc, Janet * argv);
static Janet ecdsa_get_sizebits(int32_t argc, Janet * argv);
static Janet ecdsa_get_sizebytes(int32_t argc, Janet * argv);
static Janet ecdsa_get_group(int32_t argc, Janet * argv);
static Janet ecdsa_import(int32_t argc, Janet * argv);
static Janet ecdsa_generate(int32_t argc, Janet * argv);

static janetls_ecp_curve_group janetls_ecdsa_default_digest(janetls_ecp_curve_group curve_group);
static int ecdsa_supports_curve(janetls_ecp_curve_group curve_group);
static JanetByteView signature_bytes(Janet data, janetls_md_algorithm alg);

JanetAbstractType ecdsa_object_type = {
  "janetls/ecdsa",
  ecdsa_gc_fn,
  ecdsa_gcmark,
  ecdsa_get_fn,
  JANET_ATEND_GET
};

static JanetMethod ecdsa_methods[] = {
  {"private?", ecdsa_is_private},
  {"public?", ecdsa_is_public},
  {"group", ecdsa_get_group},
  {"digest", ecdsa_get_digest},
  {"verify", ecdsa_verify},
  {"sign", ecdsa_sign},
  {"bits", ecdsa_get_sizebits},
  {"bytes", ecdsa_get_sizebytes},
  {"export-public", ecdsa_export_public},
  {"export-private", ecdsa_export_private},
  {NULL, NULL}
};

static const JanetReg cfuns[] =
{
  {"ecdsa/sign", ecdsa_sign, "(janetls/ecdsa/sign ecdsa data &opt alg)\n\n"
    "A Private key operation, sign the input data with the given key.\n"
    "When an algorithm is provided, it overrides the default algorithm on "
    "this key for signatures. It's probably best to set the algorithm "
    "on key import or generation instead.\n"
    "A binary string is returned, this is the signature to provide to "
    "a verifier. In the case of ECDSA, it comes in two parts, R,S which are "
    "two X coordinates in the curve group's prime field."
    },
  {"ecdsa/verify", ecdsa_verify, "(janetls/ecdsa/verify ecdsa alg data &opt sig)\n\n"
    "A Public key operation, verify the input data with the given public point "
    "with the binary signature.\n"
    "The algorithm must be a value in janetls/md/algorithms.\n"
    "Usually a false return when the data has been modified, or the signature "
    "was made with another key (or is just noise).\n"
    "A true or false is returned."
    },
  {"ecdsa/generate", ecdsa_generate, ""},
  {"ecdsa/import", ecdsa_import, ""},
  {"ecdsa/private?", ecdsa_is_private, ""},
  {"ecdsa/public?", ecdsa_is_public, ""},
  {"ecdsa/group", ecdsa_get_group, ""},
  {"ecdsa/digest", ecdsa_get_digest, ""},
  {"ecdsa/bits", ecdsa_get_sizebits, ""},
  {"ecdsa/bytes", ecdsa_get_sizebytes, ""},
  {"ecdsa/export-public", ecdsa_export_public, ""},
  {"ecdsa/export-private", ecdsa_export_private, ""},
  {NULL, NULL, NULL}
};

void submod_ecdsa(JanetTable * env)
{
  janet_cfuns(env, "janetls", cfuns);
}

janetls_ecdsa_object * janetls_new_ecdsa()
{
  janetls_ecdsa_object * ecdsa = janet_abstract(&ecdsa_object_type, sizeof(janetls_ecdsa_object));
  memset(ecdsa, 0, sizeof(janetls_ecdsa_object));
  return ecdsa;
}

JanetAbstractType * janetls_ecdsa_object_type()
{
  return &ecdsa_object_type;
}

static int ecdsa_get_fn(void * data, Janet key, Janet * out)
{
  (void)data;

  if (!janet_checktype(key, JANET_KEYWORD))
  {
    janet_panicf("expected keyword, got %p", key);
  }

  return janet_getmethod(janet_unwrap_keyword(key), ecdsa_methods, out);
}

static int ecdsa_gc_fn(void * data, size_t len)
{
  (void)len;
  (void)data;
  return 0;
}

static int ecdsa_gcmark(void *data, size_t len)
{
  (void)len;
  janetls_ecdsa_object * ecdsa = (janetls_ecdsa_object *)data;

  if (ecdsa->group != NULL)
  {
    janet_mark(janet_wrap_abstract(ecdsa->group));
  }
  if (ecdsa->public_coordinate != NULL)
  {
    janet_mark(janet_wrap_abstract(ecdsa->public_coordinate));
  }
  if (ecdsa->keypair != NULL)
  {
    janet_mark(janet_wrap_abstract(ecdsa->keypair));
  }
  if (ecdsa->random != NULL)
  {
    janet_mark(janet_wrap_abstract(ecdsa->random));
  }

  return 0;
}

static Janet ecdsa_is_private(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_ecdsa_object * ecdsa = janet_getabstract(argv, 0, &ecdsa_object_type);
  return janet_wrap_boolean(ecdsa->information_class == janetls_pk_information_class_private);
}

static Janet ecdsa_is_public(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_ecdsa_object * ecdsa = janet_getabstract(argv, 0, &ecdsa_object_type);
  return janet_wrap_boolean(ecdsa->information_class == janetls_pk_information_class_public);
}

static Janet ecdsa_sign(int32_t argc, Janet * argv)
{
  janet_arity(argc, 2, 3);
  janetls_ecdsa_object * ecdsa = janet_getabstract(argv, 0, &ecdsa_object_type);
  if (ecdsa->information_class == janetls_pk_information_class_public)
  {
    janet_panicf("Public keys cannot :sign data, only :verify");
  }
  if (!janet_is_byte_typed(argv[1]))
  {
    janet_panicf("Expected a string or buffer to sign, but got %p", argv[1]);
  }
  janetls_md_algorithm alg = ecdsa->digest;
  if (argc > 2)
  {
    check_result(janetls_search_md_supported_algorithms(argv[2], &alg));
  }
  else if (alg == janetls_md_algorithm_none)
  {
    janet_panicf("This ecdsa object has no default digest, "
        "see janetls/md/algorithms for an expected value");
  }
  JanetByteView bytes = signature_bytes(argv[1], alg);

  mbedtls_mpi r;
  mbedtls_mpi s;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);

  int ret = mbedtls_ecdsa_sign(
    &ecdsa->group->ecp_group,
    &r,
    &s,
    &ecdsa->keypair->keypair.d,
    bytes.bytes,
    bytes.len,
    janetls_random_rng,
    ecdsa->random ? ecdsa->random : janetls_get_random()
    );
  if (ret != 0)
  {
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    check_result(ret);
  }

  uint8_t signature[MBEDTLS_ECP_MAX_PT_LEN];
  int32_t curve_bytes = ((int32_t)(ecdsa->group->ecp_group.nbits) + 7) / 8;
  if (curve_bytes > MBEDTLS_ECP_MAX_PT_LEN)
  {
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    janet_panic("Internal error, the curve has a byte count greater than what is supported");
  }

  ret = mbedtls_mpi_write_binary(&r, signature, curve_bytes);
  if (ret != 0)
  {
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    check_result(ret);
  }
  ret = mbedtls_mpi_write_binary(&s, signature + curve_bytes, curve_bytes);
  if (ret != 0)
  {
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    check_result(ret);
  }

  Janet result = janet_wrap_string(janet_string(signature, curve_bytes * 2));

  // Now that the signature has been written, clear the intermediate bignums
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);

  return result;
}

static Janet ecdsa_verify(int32_t argc, Janet * argv)
{
  int ret = 0;
  janet_arity(argc, 3, 4);
  janetls_ecdsa_object * ecdsa = janet_getabstract(argv, 0, &ecdsa_object_type);
  if (!janet_is_byte_typed(argv[1]))
  {
    janet_panicf("Expected a string or buffer to sign, but got %p", argv[1]);
  }
  if (!janet_is_byte_typed(argv[2]))
  {
    janet_panicf("Expected a string or buffer to sign, but got %p", argv[1]);
  }
  janetls_md_algorithm alg = ecdsa->digest;
  if (argc > 3)
  {
    check_result(janetls_search_md_supported_algorithms(argv[3], &alg));
  }
  else if (alg == janetls_md_algorithm_none)
  {
    janet_panicf("This ECDSA object has no default digest, "
        "see janetls/md/algorithms for an expected value");
  }

  JanetByteView bytes = signature_bytes(argv[1], alg);

  int32_t curve_bytes = ((int32_t)(ecdsa->group->ecp_group.nbits) + 7) / 8;
  int32_t expected_length = curve_bytes * 2;

  JanetByteView signature = janet_to_bytes(argv[2]);
  mbedtls_mpi r;
  mbedtls_mpi s;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);

  if (signature.len == expected_length)
  {
    retcheck(mbedtls_mpi_read_binary(&r, signature.bytes, curve_bytes));
    retcheck(mbedtls_mpi_read_binary(&s, signature.bytes + curve_bytes, curve_bytes));
  }
  else if (signature.len > expected_length)
  {
    // This may be an ASN.1 signature, if it came from openssl.
    // There's no way to not do ASN.1 signatures from the command line.
    Janet decoded = janet_wrap_nil();
    int ret = janetls_asn1_decode(
      &decoded,
      argv[2],
      ASN1_FLAG_COLLAPSE_GUESSABLE_VALUES,
      janetls_encoding_base64_variant_standard
      );
    if (ret != 0) {
      janet_panicf("The signature provided is not the same length as "
        "this ecdsa key, this key expects %d bytes, but the signature is %d "
        "bytes. It can be more if it is an ASN.1 encoded sequence of R,S.",
        expected_length, signature.len);
    }
    int32_t tuple_length = 0;
    const Janet * tuple_values = NULL;
    int error = 0;
    if (janet_checktype(decoded, JANET_TUPLE))
    {
      tuple_values = janet_unwrap_tuple(decoded);
      tuple_length = janet_tuple_length(tuple_values);
    }
    if (tuple_length == 2)
    {
      janetls_bignum_object * r_object = janet_checkabstract(tuple_values[0], janetls_bignum_object_type());
      janetls_bignum_object * s_object = janet_checkabstract(tuple_values[1], janetls_bignum_object_type());
      if (r_object == NULL || s_object == NULL)
      {
        error = 1;
      }
      else
      {
        ret = mbedtls_mpi_copy(&r, &r_object->mpi);
        if (ret != 0)
        {
          error = 1;
        }
        ret = mbedtls_mpi_copy(&s, &s_object->mpi);
        if (ret != 0)
        {
          error = 1;
        }
      }
    }
    if (tuple_length != 2 || error)
    {
      janet_panicf("The signature provided is not the same length as "
        "this ecdsa key, it was recognized as an ASN.1 document but it did "
        "not have the expected format of SEQUENCE [R, S].");
    }
  }
  else
  {
    janet_panicf("The signature provided is not the same length as "
        "this ecdsa key, this key expects %d bytes, but the signature is %d "
        "bytes. It can be more if it is an ASN.1 encoded sequence of R,S.",
        expected_length, signature.len);
  }

  janetls_ecp_point_object * point = ecdsa->public_coordinate;
  if (point == NULL)
  {
    if (ecdsa->keypair == NULL)
    {
      janet_panic("Internal error, the keypair appears to be null, and there is no public coordinate");
    }
    point = janetls_ecp_keypair_get_public_coordinate(ecdsa->keypair);
  }

  ret = mbedtls_ecdsa_verify(
    &ecdsa->group->ecp_group,
    bytes.bytes,
    bytes.len,
    &point->point,
    &r,
    &s
    );
end:
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);

  // Don't indicate why it failed.
  // Also simplifies verify checks, no need to try catch.
  return janet_wrap_boolean(ret == 0);
}

static Janet ecdsa_export_public(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_ecdsa_object * ecdsa = janet_getabstract(argv, 0, &ecdsa_object_type);
  JanetTable * table = janet_table(7);

  janet_table_put(table, janet_ckeywordv("type"), janetls_search_pk_key_type_to_janet(janetls_pk_key_type_ec));
  janet_table_put(table, janet_ckeywordv("information-class"), janetls_search_pk_information_class_to_janet(janetls_pk_information_class_public));
  janet_table_put(table, janet_ckeywordv("digest"), janetls_search_md_supported_algorithms_to_janet(ecdsa->digest));
  janet_table_put(table, janet_ckeywordv("curve-group"), janetls_search_ecp_curve_group_to_janet(ecdsa->group->group));

  janetls_ecp_point_object * point = ecdsa->public_coordinate;
  if (point == NULL)
  {
    if (ecdsa->keypair == NULL)
    {
      janet_panic("Internal error, this ECDSA object lacks a public coordinate and a private keypair");
    }
    point = janetls_ecp_keypair_get_public_coordinate(ecdsa->keypair);
    ecdsa->public_coordinate = point;
  }

  // The ECC modulus: x
  janetls_bignum_object * x =  janetls_ecp_point_get_x(point);
  janet_table_put(table, janet_ckeywordv("x"), janet_wrap_abstract(x));

  // The ECC exponent: y
  janetls_bignum_object * y =  janetls_ecp_point_get_y(point);
  janet_table_put(table, janet_ckeywordv("y"), janet_wrap_abstract(y));

  // The public point encoded
  janet_table_put(table, janet_ckeywordv("p"), janetls_ecp_point_get_encoded(point, janetls_ecp_compression_uncompressed));

  return janet_wrap_struct(janet_table_to_struct(table));
}

static Janet ecdsa_export_private(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_ecdsa_object * ecdsa = janet_getabstract(argv, 0, &ecdsa_object_type);
  JanetTable * table = janet_table(8);

  janet_table_put(table, janet_ckeywordv("type"), janetls_search_pk_key_type_to_janet(janetls_pk_key_type_ec));
  janet_table_put(table, janet_ckeywordv("information-class"), janetls_search_pk_information_class_to_janet(janetls_pk_information_class_private));
  janet_table_put(table, janet_ckeywordv("digest"), janetls_search_md_supported_algorithms_to_janet(ecdsa->digest));
  janet_table_put(table, janet_ckeywordv("curve-group"), janetls_search_ecp_curve_group_to_janet(ecdsa->group->group));

  janetls_ecp_point_object * point = ecdsa->public_coordinate;
  if (point == NULL)
  {
    if (ecdsa->keypair == NULL)
    {
      janet_panic("Internal error, this ECDSA object lacks a public coordinate and a private keypair");
    }
    point = janetls_ecp_keypair_get_public_coordinate(ecdsa->keypair);
    ecdsa->public_coordinate = point;
  }
  // The ECC coordinate: x
  janetls_bignum_object * x = janetls_ecp_point_get_x(point);
  janet_table_put(table, janet_ckeywordv("x"), janet_wrap_abstract(x));

  // The ECC coordinate: y
  janetls_bignum_object * y =  janetls_ecp_point_get_y(point);
  janet_table_put(table, janet_ckeywordv("y"), janet_wrap_abstract(y));

  // The ECC secret: d
  janet_table_put(table, janet_ckeywordv("d"), ecdsa->keypair->secret);

  // The public point encoded
  janet_table_put(table, janet_ckeywordv("p"), janetls_ecp_point_get_encoded(point, janetls_ecp_compression_uncompressed));

  return janet_wrap_struct(janet_table_to_struct(table));
}

static Janet ecdsa_get_digest(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_ecdsa_object * ecdsa = janet_getabstract(argv, 0, &ecdsa_object_type);
  return janetls_search_md_supported_algorithms_to_janet(ecdsa->digest);
}

static Janet ecdsa_get_sizebits(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_ecdsa_object * ecdsa = janet_getabstract(argv, 0, &ecdsa_object_type);
  return janet_wrap_number(ecdsa->group->ecp_group.nbits);
}

static Janet ecdsa_get_sizebytes(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_ecdsa_object * ecdsa = janet_getabstract(argv, 0, &ecdsa_object_type);
  int bytes = ((int)(ecdsa->group->ecp_group.nbits) + 7) / 8;
  return janet_wrap_number(bytes);
}

static Janet ecdsa_get_group(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_ecdsa_object * ecdsa = janet_getabstract(argv, 0, &ecdsa_object_type);
  return janet_wrap_abstract(ecdsa->group);
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

static Janet ecdsa_import(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_ecdsa_object * ecdsa = janetls_new_ecdsa();
  if (janet_checktype(argv[0], JANET_ABSTRACT))
  {
    // check if an ecp point or ecp keypair
    janetls_ecp_point_object * point =
      janet_checkabstract(argv[0], janetls_ecp_point_object_type());
    if (point != NULL)
    {
      ecdsa->group = point->group;
      ecdsa->public_coordinate = point;
      ecdsa->information_class = janetls_pk_information_class_public;
      ecdsa->random = point->group->random;
      ecdsa->digest = janetls_ecdsa_default_digest(point->group->group);
      goto final_check;
    }
    janetls_ecp_keypair_object * keypair =
      janet_checkabstract(argv[0], janetls_ecp_keypair_object_type());
    if (keypair != NULL)
    {
      ecdsa->group = keypair->group;
      ecdsa->keypair = keypair;
      ecdsa->public_coordinate = keypair->public_coordinate;
      ecdsa->information_class = janetls_pk_information_class_private;
      ecdsa->random = keypair->group->random;
      ecdsa->digest = janetls_ecdsa_default_digest(keypair->group->group);
      goto final_check;
    }
    goto unrecognized_type;
  }
  else if(janet_checktype(argv[0], JANET_TABLE) || janet_checktype(argv[0], JANET_STRUCT))
  {
    janetls_bignum_object * x = NULL;
    janetls_bignum_object * y = NULL;
    Janet d = janet_wrap_nil();
    janetls_ecp_group_object * group = NULL;
    Janet p = janet_wrap_nil();
    int explicit_digest = 0;

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
            janet_panicf("Expected :ec for :type, but got %p", kv->value);
          }
          if (type != janetls_pk_key_type_ec)
          {
            janet_panicf("Expected :ec for :type, but got %p", kv->value);
          }
        }
        else if (janet_byte_cstrcmp_insensitive(key, "information-class") == 0)
        {
          // public, private
          if (janetls_search_pk_information_class(kv->value, &ecdsa->information_class) != 0)
          {
            janet_panicf("Expected :public or :private for :information-class, but got %p", kv->value);
          }
        }
        else if (janet_byte_cstrcmp_insensitive(key, "hash") == 0
          || janet_byte_cstrcmp_insensitive(key, "digest") == 0)
        {
          janetls_md_algorithm digest = janetls_md_algorithm_none;
          if (janetls_search_md_supported_algorithms(kv->value, &digest) != 0)
          {
            janet_panicf("Expected a value from janetls/md/algorithms for %p, but got %p", kv->key, kv->value);
          }
          ecdsa->digest = digest;
          explicit_digest = 1;
        }
        else if (janet_byte_cstrcmp_insensitive(key, "x") == 0)
        {
          x = bignum_from_kv(kv);
        }
        else if (janet_byte_cstrcmp_insensitive(key, "y") == 0)
        {
          y = bignum_from_kv(kv);
        }
        else if (janet_byte_cstrcmp_insensitive(key, "p") == 0
          || janet_byte_cstrcmp_insensitive(key, "point") == 0)
        {
          // validation comes later.
          p = kv->value;
        }
        else if (janet_byte_cstrcmp_insensitive(key, "d") == 0
          || janet_byte_cstrcmp_insensitive(key, "secret") == 0)
        {
          if (janet_checktype(kv->value, JANET_STRING))
          {
            d = kv->value;
          }
          else if (janet_checktype(kv->value, JANET_BUFFER))
          {
            // make an immutable copy
            JanetByteView bytes = janet_to_bytes(kv->value);
            d = janet_wrap_string(janet_string(bytes.bytes, bytes.len));
          }
          else
          {
            janet_panicf("Expected a string or buffer for %p, but got %p",
              kv->key, kv->value);
          }
        }
        else if (janet_byte_cstrcmp_insensitive(key, "curve-group") == 0
          || janet_byte_cstrcmp_insensitive(key, "curve") == 0
          || janet_byte_cstrcmp_insensitive(key, "group") == 0)
        {
          if (janet_is_byte_typed(kv->value))
          {
            janetls_ecp_curve_group curve_group = janetls_ecp_curve_group_none;
            if (janetls_search_ecp_curve_group(kv->value, &curve_group) != 0)
            {
              janet_panicf("Expected a value from janetls/ecp/curve-groups "
                "for %p, but got %p", kv->key, kv->value);
            }
            group = janetls_ecp_load_curve_group(curve_group);
          }
          else if ((group = janet_checkabstract(kv->value, janetls_ecp_group_object_type())))
          {
            // Nothing we're good!
          }
          else
          {
            janet_panicf("Expected a keyword or janetls/ecp/group for %p, "
            "but got %p", kv->key, kv->value);
          }
        }
      }
      else
      {
        janet_panicf("Expected a keyword key in the struct or table, but got %p", kv->key);
      }
    }
    if (group == NULL)
    {
      janet_panic("Cannot import an EC key without knowing the group type, "
        "this is specified in the :curve-group field");
    }
    int no_secret = janet_checktype(d, JANET_NIL);
    int has_p = !janet_checktype(p, JANET_NIL);
    if (no_secret && (x == NULL || y == NULL) && !has_p)
    {
      janet_panic("When importing a public EC key, both :x and :y must be present, or a :p for a point");
    }

    janetls_ecp_point_object * point = NULL;
    if (has_p)
    {
      point = janet_checkabstract(p, janetls_ecp_point_object_type());
      if (point == NULL && janet_is_byte_typed(p))
      {
        point = janetls_ecp_load_point_binary(group, p);
      }
      else
      {
        janet_panicf("The point :p is not an ecp/point object or a string or buffer, received %p", p);
      }
    }

    // Finally create the ecdsa stuff
    ecdsa->group = group;
    ecdsa->random = group->random;

    if (ecdsa->digest == janetls_md_algorithm_none && !explicit_digest)
    {
      ecdsa->digest = janetls_ecdsa_default_digest(group->group);
    }

    if (!no_secret)
    {
      ecdsa->keypair = janetls_ecp_load_keypair_object(group, d);
      ecdsa->public_coordinate = janetls_ecp_keypair_get_public_coordinate(ecdsa->keypair);
      ecdsa->information_class = janetls_pk_information_class_private;
    }
    else if (has_p && point)
    {
      ecdsa->public_coordinate = point;
      ecdsa->information_class = janetls_pk_information_class_public;
    }
    else if (x != NULL && y != NULL)
    {
      ecdsa->public_coordinate = janetls_ecp_load_point_object(group, x, y);
      ecdsa->information_class = janetls_pk_information_class_public;
    }
    else
    {
      janet_panic("Internal error: Validation failed for public coordinate");
    }
  }
  else
  {
unrecognized_type:
    janet_panicf("Expected a table or struct or janetls/ecp/point or "
    "janetls/ecp/keypair, but got %p", argv[0]);
  }
final_check:
  if (!ecdsa_supports_curve(ecdsa->group->group))
  {
    janet_panicf("The curve %p is not supported by ECDSA", janetls_search_ecp_curve_group_to_janet(ecdsa->group->group));
  }
  if (ecdsa->random == NULL)
  {
    ecdsa->random = janetls_get_random();
  }
  return janet_wrap_abstract(ecdsa);
}

static janetls_ecp_curve_group janetls_ecdsa_default_digest(janetls_ecp_curve_group curve_group)
{
  switch (curve_group)
  {
    case janetls_ecp_curve_group_secp192r1:
    case janetls_ecp_curve_group_secp192k1:
    case janetls_ecp_curve_group_secp224r1:
    case janetls_ecp_curve_group_secp224k1:
    case janetls_ecp_curve_group_secp256k1:
    case janetls_ecp_curve_group_secp256r1:
    case janetls_ecp_curve_group_bp256r1:
    {
      return janetls_md_algorithm_sha256;
      break;
    }
    case janetls_ecp_curve_group_secp384r1:
    case janetls_ecp_curve_group_bp384r1:
    {
      return janetls_md_algorithm_sha384;
      break;
    }
    case janetls_ecp_curve_group_secp521r1:
    case janetls_ecp_curve_group_bp512r1:
    {
      return janetls_md_algorithm_sha512;
      break;
    }
    default:
    {
      // "ECDSA" doesn't actually support montgomery curves..
      return janetls_md_algorithm_sha256;
    }
  }
}

static int ecdsa_supports_curve(janetls_ecp_curve_group curve_group)
{
  switch (curve_group)
  {
    case janetls_ecp_curve_group_secp192r1:
    case janetls_ecp_curve_group_secp192k1:
    case janetls_ecp_curve_group_secp224r1:
    case janetls_ecp_curve_group_secp224k1:
    case janetls_ecp_curve_group_secp256k1:
    case janetls_ecp_curve_group_secp256r1:
    case janetls_ecp_curve_group_bp256r1:
    case janetls_ecp_curve_group_secp384r1:
    case janetls_ecp_curve_group_bp384r1:
    case janetls_ecp_curve_group_secp521r1:
    case janetls_ecp_curve_group_bp512r1:
    {
      // no problem
      return 1;
    }
    default:
    {
      return 0;
    }
  }
}

static Janet ecdsa_generate(int32_t argc, Janet * argv)
{
  janet_arity(argc, 0, 2);
  janetls_ecp_group_object * group = NULL;
  if (argc == 0)
  {
    // default to NIST P-256
    group = janetls_ecp_load_curve_group(janetls_ecp_curve_group_secp256r1);
  }
  else if (janet_is_byte_typed(argv[0]))
  {
    janetls_ecp_curve_group curve_group;
    check_result(janetls_search_ecp_curve_group(argv[0], &curve_group));
    group = janetls_ecp_load_curve_group(curve_group);
  }
  else if ((group = janet_checkabstract(argv[0], janetls_ecp_group_object_type())))
  {
    // Nothing, it has loaded as desired
  }
  else
  {
    janet_panicf("Expected a group object or a curve group (as in "
    "janetls/ecp/curve-groups), but got %p", argv[0]);
  }

  janetls_ecp_keypair_object * keypair = janetls_ecp_generate_keypair_object(group);
  janetls_ecdsa_object * ecdsa = janetls_new_ecdsa();
  ecdsa->group = group;
  ecdsa->public_coordinate = keypair->public_coordinate;
  ecdsa->keypair = keypair;
  ecdsa->random = janetls_get_random();
  ecdsa->information_class = janetls_pk_information_class_private;

  if (argc > 1)
  {
    check_result(janetls_search_md_supported_algorithms(argv[1], &ecdsa->digest));
  }
  else
  {
    ecdsa->digest = janetls_ecdsa_default_digest(group->group);
  }

  if (!ecdsa_supports_curve(group->group))
  {
    janet_panicf("The curve %p is not supported by ECDSA", janetls_search_ecp_curve_group_to_janet(group->group));
  }

  return janet_wrap_abstract(ecdsa);
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
