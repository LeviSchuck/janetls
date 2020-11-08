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
#include "janetls-ecdsa.h"
#include <inttypes.h>

#define ECP_KEYPAIR_HAS_PUBLIC 1

static int ecp_group_gc_fn(void * data, size_t len);
static int ecp_group_gcmark(void * data, size_t len);
static int ecp_group_get_fn(void * data, Janet key, Janet * out);

static int ecp_point_gc_fn(void * data, size_t len);
static int ecp_point_gcmark(void * data, size_t len);
static int ecp_point_get_fn(void * data, Janet key, Janet * out);

static int ecp_keypair_gc_fn(void * data, size_t len);
static int ecp_keypair_gcmark(void * data, size_t len);
static int ecp_keypair_get_fn(void * data, Janet key, Janet * out);

static Janet ecp_group_from_key(int32_t argc, Janet * argv);
static Janet ecp_group_get_group(int32_t argc, Janet * argv);
static Janet ecp_group_get_curve_group(int32_t argc, Janet * argv);
static Janet ecp_group_get_generator(int32_t argc, Janet * argv);
static Janet ecp_group_get_zero(int32_t argc, Janet * argv);
static Janet ecp_group_compare(int32_t argc, Janet * argv);
static Janet ecp_group_generate_keypair(int32_t argc, Janet * argv);
static Janet ecp_point_get_x(int32_t argc, Janet * argv);
static Janet ecp_point_get_y(int32_t argc, Janet * argv);
static Janet ecp_point_is_zero(int32_t argc, Janet * argv);
static Janet ecp_point_export(int32_t argc, Janet * argv);
static Janet ecp_point_import(int32_t argc, Janet * argv);
static Janet ecp_point_compare(int32_t argc, Janet * argv);
static Janet ecp_keypair_get_point(int32_t argc, Janet * argv);
static Janet ecp_keypair_get_secret(int32_t argc, Janet * argv);
static Janet ecp_keypair_export(int32_t argc, Janet * argv);
static Janet ecp_keypair_import(int32_t argc, Janet * argv);
static Janet ecp_keypair_compare(int32_t argc, Janet * argv);

static janetls_random_object * random_from_group(janetls_ecp_group_object * group);

static int compare_group(Janet a, Janet b);
static int compare_point(Janet a, Janet b);
static int compare_keypair(Janet a, Janet b);


static void ecp_group_to_string_untyped(void * group, JanetBuffer * buffer);
static int ecp_group_compare_untyped(void * x, void * y);
static int32_t ecp_group_hash(void * p, size_t len);

static void ecp_point_to_string_untyped(void * group, JanetBuffer * buffer);
static int ecp_point_compare_untyped(void * x, void * y);
static int32_t ecp_point_hash(void * p, size_t len);

static void ecp_keypair_to_string_untyped(void * group, JanetBuffer * buffer);
static int ecp_keypair_compare_untyped(void * x, void * y);
static int32_t ecp_keypair_hash(void * p, size_t len);

static JanetAbstractType ecp_group_object_type = {
  "janetls/ecp/group",
  ecp_group_gc_fn,
  ecp_group_gcmark,
  ecp_group_get_fn,
  NULL,
  NULL,
  NULL,
  ecp_group_to_string_untyped,
  ecp_group_compare_untyped,
  ecp_group_hash,
  JANET_ATEND_HASH
};

static JanetAbstractType ecp_point_object_type = {
  "janetls/ecp/point",
  ecp_point_gc_fn,
  ecp_point_gcmark,
  ecp_point_get_fn,
  NULL,
  NULL,
  NULL,
  ecp_point_to_string_untyped,
  ecp_point_compare_untyped,
  ecp_point_hash,
  JANET_ATEND_HASH
};

static JanetAbstractType ecp_keypair_object_type = {
  "janetls/ecp/keypair",
  ecp_keypair_gc_fn,
  ecp_keypair_gcmark,
  ecp_keypair_get_fn,
  NULL,
  NULL,
  NULL,
  ecp_keypair_to_string_untyped,
  ecp_keypair_compare_untyped,
  ecp_keypair_hash,
  JANET_ATEND_HASH
};

static JanetMethod ecp_group_methods[] = {
  {"curve-group", ecp_group_get_curve_group},
  {"group", ecp_group_get_group},
  {"generator", ecp_group_get_generator},
  {"zero", ecp_group_get_zero},
  {"import-point", ecp_point_import},
  {"import-key", ecp_keypair_import},
  {"compare", ecp_group_compare},
  {"generate", ecp_group_generate_keypair},
  {NULL, NULL}
};

static JanetMethod ecp_point_methods[] = {
  {"group", ecp_group_get_group},
  {"x", ecp_point_get_x},
  {"y", ecp_point_get_y},
  {"zero?", ecp_point_is_zero},
  {"export", ecp_point_export},
  {"compare", ecp_point_compare},
  {NULL, NULL}
};

static JanetMethod ecp_keypair_methods[] = {
  {"group", ecp_group_get_group},
  {"export", ecp_keypair_export},
  {"point", ecp_keypair_get_point},
  {"secret", ecp_keypair_get_secret},
  {"compare", ecp_keypair_compare},
  {NULL, NULL}
};


static const JanetReg cfuns[] =
{
  {"ecp/curve-groups", janetls_search_ecp_curve_group_set, "(janetls/ecp/curve-groups)\n\n"
    "Enumerates supported curve groups"
    },
  {"ecp/load-curve-group", ecp_group_from_key, "(janetls/ecp/group curve-group)\n\n"
    "Load a standard group, curve-group should be a value found in "
    "janetls/ecp/curve-groups."
    },
  {"ecp/group", ecp_group_get_group, "(janetls/ecp/group multiple)\n\n"
    "Finds the janetls/ecp/group object from a keypair or point. When given "
    "a group, it returns itself."
    },
  {"ecp/curve-group", ecp_group_get_curve_group, "(janetls/ecp/curve-group multiple)\n\n"
    "Finds the curve group keyword (as in janetls/ecp/curve-groups) from a "
    "group, keypair, or point."
    },
  {"ecp/generator", ecp_group_get_generator, "(janetls/ecp/generator group)\n\n"
    "Returns the generator point for the curve group as a ecp/point."
    },
  {"ecp/zero", ecp_group_get_zero, "(janetls/ecp/zero group)\n\n"
    "Returns the zero point for the curve group as a ecp/point.\n"
    "Note that 'zero' is the identity point, but it may also be labeled "
    "infinity on the projective plane."
    },
  {"ecp/x", ecp_point_get_x, "(janetls/ecp/x multple)\n\n"
    "Get the X coordinate of the point or public point of a keypair, "
    "returns a bignum"
    },
  {"ecp/y", ecp_point_get_y, "(janetls/ecp/y multple)\n\n"
    "Get the Y coordinate of the point or public point of a keypair, "
    "returns a bignum"
    },
  {"ecp/zero?", ecp_point_is_zero, "(janetls/ecp/zero? point)\n\n"
    "returns a boolean of if this point is at zero, or is not invertable."
    },
  {"ecp/point", ecp_keypair_get_point, "(janetls/ecp/point keypair)\n\n"
    "returns a the public point in the keypair."
    },
  {"ecp/secret", ecp_keypair_get_secret, "(janetls/ecp/secret keypair)\n\n"
    "returns a the private secret in the keypair, which is a bignum."
    },
  {"ecp/compression", janetls_search_ecp_compression_set, "(janetls/ecp/compression)\n\n"
    "Enumerates supported compression options, for use when exporting."
    },
  {"ecp/export-point", ecp_point_export, "(janetls/ecp/export-point multiple &opt compression)\n\n"
    "Exports the point or public point from a keypair to binary. "
    "The exact format depends on the curve in use.\n"
    "By default, compression will be :uncompressed, options are enumerated in "
    "janetls/ecp/compression.\n"
    "Using compressed points is discouraged, they cannot be imported by this "
    "library, and are deprecated in RFC 8422 for TLS"
    },
  {"ecp/import-point", ecp_point_import, "(janetls/ecp/import group binary)\n\n"
    "Imports binary exported coordinate within the group curve.\n"
    "Essentially, this only imports the public component of a keypair."
    },
  {"ecp/export-keypair", ecp_keypair_export, "(janetls/ecp/export-keypair keypair)\n\n"
    "Exports the secret component keypair to binary. "
    "The exact format depends on the curve in use.\n"
    },
  {"ecp/import-keypair", ecp_keypair_import, "(janetls/ecp/import group binary)\n\n"
    "Imports the private component from a binary into a keypair.\n"
    "The public coordinate will be calculated during validation."
    },
  {"ecp/generate", ecp_group_generate_keypair, "(janetls/ecp/generate group)\n\n"
    "Generate a keypair within the group.\n"
    "It generates a secret which is compatible with the group, and then "
    "derives the public point for that secret against the group generator."
    },
  {NULL, NULL, NULL}
};

void submod_ecp(JanetTable * env)
{
  janet_cfuns(env, "janetls", cfuns);
  janet_register_abstract_type(&ecp_group_object_type);
  janet_register_abstract_type(&ecp_point_object_type);
  janet_register_abstract_type(&ecp_keypair_object_type);
}

JanetAbstractType * janetls_ecp_group_object_type()
{
  return &ecp_group_object_type;
}

JanetAbstractType * janetls_ecp_point_object_type()
{
  return &ecp_point_object_type;
}

JanetAbstractType * janetls_ecp_keypair_object_type()
{
  return &ecp_keypair_object_type;
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
  mbedtls_ecp_group_free(&group->ecp_group);
  return 0;
}

static int ecp_group_gcmark(void *data, size_t len)
{
  (void)len;
  janetls_ecp_group_object * group = (janetls_ecp_group_object *)data;
  if (group->random != NULL)
  {
    janet_mark(janet_wrap_abstract(group->random));
  }
  if (group->zero != NULL)
  {
    janet_mark(janet_wrap_abstract(group->zero));
  }

  if (group->generator != NULL)
  {
    janet_mark(janet_wrap_abstract(group->generator));
  }

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

static int ecp_keypair_get_fn(void *data, Janet key, Janet * out)
{
  (void)data;

  if (!janet_checktype(key, JANET_KEYWORD))
  {
    janet_panicf("expected keyword, got %p", key);
  }

  return janet_getmethod(janet_unwrap_keyword(key), ecp_keypair_methods, out);
}

static int ecp_keypair_gc_fn(void * data, size_t len)
{
  janetls_ecp_keypair_object * keypair = (janetls_ecp_keypair_object *)data;
  mbedtls_ecp_keypair_free(&keypair->keypair);
  return 0;
}

static int ecp_keypair_gcmark(void *data, size_t len)
{
  (void)len;
  janetls_ecp_keypair_object * keypair = (janetls_ecp_keypair_object *)data;

  if (keypair->group != NULL)
  {
    janet_mark(janet_wrap_abstract(keypair->group));
  }

  if (keypair->public_coordinate != NULL)
  {
    janet_mark(janet_wrap_abstract(keypair->public_coordinate));
  }

  janet_mark(keypair->secret);

  return 0;
}

janetls_ecp_group_object * janetls_new_ecp_group_object()
{
  janetls_ecp_group_object * group = janet_abstract(&ecp_group_object_type, sizeof(janetls_ecp_group_object));
  memset(group, 0, sizeof(janetls_ecp_group_object));
  mbedtls_ecp_group_init(&group->ecp_group);
  return group;
}

janetls_ecp_point_object * janetls_new_ecp_point_object()
{
  janetls_ecp_point_object * point = janet_abstract(&ecp_point_object_type, sizeof(janetls_ecp_point_object));
  memset(point, 0, sizeof(janetls_ecp_point_object));
  mbedtls_ecp_point_init(&point->point);
  return point;
}

janetls_ecp_keypair_object * janetls_new_ecp_keypair_object()
{
  janetls_ecp_keypair_object * keypair = janet_abstract(&ecp_keypair_object_type, sizeof(janetls_ecp_keypair_object));
  memset(keypair, 0, sizeof(janetls_ecp_keypair_object));
  mbedtls_ecp_keypair_init(&keypair->keypair);
  return keypair;
}

static Janet ecp_group_from_key(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_ecp_curve_group group;
  if (janetls_search_ecp_curve_group(argv[0], &group) != 0)
  {
    janet_panicf("Could not find a group for %p, see (janetls/ecp/curve-groups) for options", argv[0]);
  }
  return janet_wrap_abstract(janetls_ecp_load_curve_group(group));
}

static Janet ecp_group_get_group(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);

  return janet_wrap_abstract(group_from_janet(argv[0], 1));
}

static Janet ecp_group_get_curve_group(int32_t argc, Janet * argv)
{
  janetls_ecp_group_object * group = group_from_janet(argv[0], 1);
  return janetls_search_ecp_curve_group_to_janet(group->group);
}

static Janet ecp_group_get_generator(int32_t argc, Janet * argv)
{
  janetls_ecp_group_object * group = group_from_janet(argv[0], 1);

  if (group->generator == NULL)
  {
    janetls_ecp_point_object * point = janetls_new_ecp_point_object();
    check_result(mbedtls_ecp_copy(&point->point, &group->ecp_group.G));
    point->group = group;
    group->generator = point;
  }

  return janet_wrap_abstract(group->generator);
}

static Janet ecp_group_get_zero(int32_t argc, Janet * argv)
{
  Janet curve = ecp_group_get_group(argc, argv);
  janetls_ecp_group_object * group = janet_unwrap_abstract(curve);

  if (group->zero == NULL)
  {
    janetls_ecp_point_object * point = janetls_new_ecp_point_object();
    check_result(mbedtls_ecp_set_zero(&point->point));
    point->group = group;
    group->zero = point;
  }

  return janet_wrap_abstract(group->zero);
}

static Janet ecp_group_generate_keypair(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_ecp_group_object * group = group_from_janet(argv[0], 1);
  return janet_wrap_abstract(janetls_ecp_generate_keypair_object(group));
}

static Janet ecp_point_get_x(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_ecp_point_object * point = point_from_janet(argv[0], 1);
  return janet_wrap_abstract(janetls_ecp_point_get_x(point));
}

static Janet ecp_point_get_y(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_ecp_point_object * point = point_from_janet(argv[0], 1);
  return janet_wrap_abstract(janetls_ecp_point_get_y(point));
}

static Janet ecp_point_is_zero(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_ecp_point_object * point = point_from_janet(argv[0], 1);
  return janet_wrap_boolean(mbedtls_ecp_is_zero(&point->point));
}

static Janet ecp_point_export(int32_t argc, Janet * argv)
{
  janet_arity(argc, 1, 2);
  janetls_ecp_point_object * point = point_from_janet(argv[0], 1);
  janetls_ecp_compression compression = janetls_ecp_compression_uncompressed;
  if (argc > 1)
  {
    check_result(janetls_search_ecp_compression(argv[1], &compression));
  }
  return janetls_ecp_point_get_encoded(point, compression);
}

static Janet ecp_point_import(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 2);
  janetls_ecp_group_object * group = group_from_janet(argv[0], 1);
  return janet_wrap_abstract(janetls_ecp_load_point_binary(group, argv[1]));
}

static Janet ecp_keypair_get_point(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_ecp_keypair_object * keypair = janet_getabstract(argv, 0, &ecp_keypair_object_type);
  return janet_wrap_abstract(janetls_ecp_keypair_get_public_coordinate(keypair));
}

static Janet ecp_keypair_get_secret(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_ecp_keypair_object * keypair = janet_getabstract(argv, 0, &ecp_keypair_object_type);
  return keypair->secret;
}

static Janet ecp_keypair_export(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_ecp_keypair_object * keypair = janet_getabstract(argv, 0, &ecp_keypair_object_type);
  uint8_t output[MBEDTLS_ECP_MAX_BYTES];
  // compute bits to bytes of the curve
  size_t length = (keypair->group->ecp_group.nbits + 7) / 8;
  if (length > MBEDTLS_ECP_MAX_BYTES)
  {
    janet_panicf("The given curve has a larger bit size than is "
      "supported, the bit size appears to be %d", keypair->group->ecp_group.nbits);
  }
  check_result(mbedtls_ecp_write_key(
    &keypair->keypair,
    output,
    length
    ));
  return janet_wrap_string(janet_string(output, length));
}

#define CURVE25519_KEY_SIZE 32
#define CURVE25519_KEY_BITS (CURVE25519_KEY_SIZE * 8)
#define CURVE448_KEY_SIZE 56
#define CURVE448_KEY_BITS (CURVE448_KEY_SIZE * 8)

static void ecp_keypair_from_secret(
  janetls_ecp_keypair_object * keypair,
  janetls_ecp_group_object * group,
  Janet secret)
{
  if (!janet_is_byte_typed(secret))
  {
    janet_panicf("Expected a string or buffer but got %p", secret);
  }
  JanetByteView bytes = janet_to_bytes(secret);

  if (janet_checktype(secret, JANET_STRING))
  {
    keypair->secret = secret;
  }
  else
  {
    // Create an immutable copy
    keypair->secret = janet_wrap_string(janet_string(bytes.bytes, bytes.len));
  }

  // Unfortunately mbedtls does not expose just the right interface for this to
  // be convenient.
  // Below is an adaptation / inline of mbedtls_ecp_read_key

  if (group->group == janetls_ecp_curve_group_x25519)
  {
    if (bytes.len != CURVE25519_KEY_SIZE)
    {
      janet_panicf("The input key size should be %d, but %d bytes were given",
        CURVE25519_KEY_SIZE, bytes.len);
    }
    check_result(mbedtls_mpi_read_binary_le(&keypair->keypair.d, bytes.bytes, bytes.len));

    // Per RFC7748
    // k_list[0]  &= 248 (0b11111000)
    // k_list[31] &= 127 (0b01111111)
    // k_list[31] |= 64  (0b01000000)
    // Set the three least significant bits to 0
    check_result(mbedtls_mpi_set_bit(&keypair->keypair.d, 0, 0));
    check_result(mbedtls_mpi_set_bit(&keypair->keypair.d, 1, 0));
    check_result(mbedtls_mpi_set_bit(&keypair->keypair.d, 2, 0));
    // Set the most significant bit to 0
    check_result(mbedtls_mpi_set_bit(&keypair->keypair.d, CURVE25519_KEY_BITS - 1, 0));
    // Set the second most significant bit to 1
    check_result(mbedtls_mpi_set_bit(&keypair->keypair.d, CURVE25519_KEY_BITS - 2, 1));
  }
  else if (group->group == janetls_ecp_curve_group_x448)
  {
    // This code is a derivation of the curve25519 read_key code
    // It is NOT present in mbedtls, however the implementation is
    // researched and justified, review the annotated python? below
    if (bytes.len != CURVE448_KEY_SIZE)
    {
      janet_panicf("The input key size should be %d, but %d bytes were given",
        CURVE448_KEY_SIZE, bytes.len);
    }
    check_result(mbedtls_mpi_read_binary_le(&keypair->keypair.d, bytes.bytes, bytes.len));

    // Per RFC7748
    // https://tools.ietf.org/html/rfc7748#section-5
    // See page 8 for decode routine
    // k_list[0]  &= 252 (0b11111100)
    // k_list[55] |= 128 (0b10000000)
    // Set the two least significant bits to 0
    check_result(mbedtls_mpi_set_bit(&keypair->keypair.d, 0, 0));
    check_result(mbedtls_mpi_set_bit(&keypair->keypair.d, 1, 0));
    // Set the most significant bit to 1
    check_result(mbedtls_mpi_set_bit(&keypair->keypair.d, CURVE448_KEY_BITS - 1, 1));
  }
  else if (mbedtls_ecp_get_type(&group->ecp_group) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS)
  {
    check_result(mbedtls_mpi_read_binary(&keypair->keypair.d, bytes.bytes, bytes.len));
    check_result(mbedtls_ecp_check_privkey(&group->ecp_group, &keypair->keypair.d));
  }
  else
  {
    janet_panicf("Unfortunately the curve type %p is not supported",
      janetls_search_ecp_curve_group_to_janet(group->group));
  }
}

static Janet ecp_keypair_import(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 2);
  janetls_ecp_group_object * group = group_from_janet(argv[0], 1);
  janetls_ecp_keypair_object * keypair = janetls_new_ecp_keypair_object();
  keypair->group = group;

  // It also so happens that keypairs are also the "ctx" used in ecdsa,
  // without any sort of wrapping.
  // Keypairs maintain their own copy of the group.
  check_result(mbedtls_ecp_group_copy(&keypair->keypair.grp, &group->ecp_group));

  ecp_keypair_from_secret(keypair, group, argv[1]);

  return janet_wrap_abstract(keypair);
}

janetls_ecp_keypair_object * keypair_from_janet(Janet value, int panic)
{
  janetls_ecp_keypair_object * keypair = janet_checkabstract(value, &ecp_keypair_object_type);

  if (keypair == NULL)
  {
    janetls_ecdsa_object * ecdsa_object = janet_checkabstract(value, janetls_ecdsa_object_type());
    if (ecdsa_object != NULL)
    {
      keypair = ecdsa_object->keypair;
    }
  }

  if (keypair == NULL && panic)
  {
    janet_panicf("Expected a keypair or ecdsa object");
  }

  return keypair;
}

janetls_ecp_point_object * point_from_janet(Janet value, int panic)
{
  janetls_ecp_point_object * point = janet_checkabstract(value, &ecp_point_object_type);

  if (point == NULL)
  {
    janetls_ecp_keypair_object * keypair = janet_checkabstract(value, &ecp_keypair_object_type);
    if (keypair != NULL)
    {
      point = janetls_ecp_keypair_get_public_coordinate(keypair);
    }
  }
  if (point == NULL)
  {
    janetls_ecdsa_object * ecdsa_object = janet_checkabstract(value, janetls_ecdsa_object_type());
    janetls_ecp_keypair_object * keypair;
    if (ecdsa_object != NULL)
    {
      point = ecdsa_object->public_coordinate;
      keypair = ecdsa_object->keypair;
      // ECDSA objects can exist with a secret and not a public point set
      // Calculate it and attach it to the ecdsa object
      if (point == NULL && keypair != NULL)
      {
        point = janetls_ecp_keypair_get_public_coordinate(keypair);
        ecdsa_object->public_coordinate = point;
      }
    }
  }

  if (point == NULL && panic)
  {
    janet_panicf("Expected a point or keypair or ecdsa object");
  }

  return point;
}

janetls_ecp_group_object * group_from_janet(Janet value, int panic)
{
  janetls_ecp_group_object * group_object = janet_checkabstract(value, &ecp_group_object_type);
  if (group_object != NULL)
  {
    return group_object;
  }

  if (janet_is_byte_typed(value))
  {
    janetls_ecp_curve_group curve_group;
    if (janetls_search_ecp_curve_group(value, &curve_group) == 0)
    {
      return janetls_ecp_load_curve_group(curve_group);
    }
  }

  janetls_ecp_point_object * point_object = janet_checkabstract(value, &ecp_point_object_type);
  if (point_object != NULL && point_object->group != NULL)
  {
    return point_object->group;
  }

  janetls_ecp_keypair_object * keypair_object = janet_checkabstract(value, &ecp_keypair_object_type);
  if (keypair_object != NULL && keypair_object->group != NULL)
  {
    return keypair_object->group;
  }

  janetls_ecdsa_object * ecdsa_object = janet_checkabstract(value, janetls_ecdsa_object_type());
  if (ecdsa_object != NULL && ecdsa_object->group != NULL)
  {
    return ecdsa_object->group;
  }

  if (panic)
  {
    janet_panicf("Expected a group, point, or keypair but got %p", value);
  }

  return NULL;
}

static int compare_group(Janet a, Janet b)
{
  janetls_ecp_group_object * group1 = group_from_janet(a, 0);
  janetls_ecp_group_object * group2 = group_from_janet(b, 0);
  if (group1 == NULL)
  {
    return -1;
  }
  if (group2 == NULL)
  {
    return 1;
  }

  if (group1->group == group2->group)
  {
    return 0;
  }
  else if (group1->group > group2->group)
  {
    return 1;
  }

  return -1;
}

static int compare_point(Janet a, Janet b)
{
  janetls_ecp_point_object * point1 = point_from_janet(a, 0);
  janetls_ecp_point_object * point2 = point_from_janet(b, 0);
  if (point1 == NULL)
  {
    return -1;
  }
  if (point2 == NULL)
  {
    return 1;
  }
  int ret = mbedtls_ecp_point_cmp(&point1->point, &point2->point);
  if (ret == 0)
  {
    return 0;
  }

  // ECP point comparison is only ==, but janet compare expects ordering.
  // We can try to compare the X coordinate next, and then Y.

  ret = mbedtls_mpi_cmp_mpi(&point1->point.X, &point2->point.X);
  if (ret != 0)
  {
    return ret;
  }

  ret = mbedtls_mpi_cmp_mpi(&point1->point.Y, &point2->point.Y);
  if (ret != 0)
  {
    return ret;
  }

  // They must be equal
  return 0;
}

static int compare_keypair(Janet a, Janet b)
{
  janetls_ecp_keypair_object * keypair1 = janet_checkabstract(a, &ecp_keypair_object_type);
  janetls_ecp_keypair_object * keypair2 = janet_checkabstract(b, &ecp_keypair_object_type);

  if (keypair1 == NULL)
  {
    return -1;
  }

  if (keypair2 == NULL)
  {
    return 1;
  }

  // Compare the secret values
  return mbedtls_mpi_cmp_mpi(&keypair1->keypair.d, &keypair2->keypair.d);
}

static Janet ecp_group_compare(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 2);
  int ret = compare_group(argv[0], argv[1]);
  // Ensure that ordering is only applied if both are actually groups
  if (ret == 0
    && janet_checkabstract(argv[0], &ecp_group_object_type) != 0
    && janet_checkabstract(argv[1], &ecp_group_object_type) == 0
    )
  {
    ret = -1;
  }
  else if (ret == 0
    && janet_checkabstract(argv[0], &ecp_group_object_type) == 0
    && janet_checkabstract(argv[1], &ecp_group_object_type) != 0
    )
  {
    ret = 1;
  }
  return janet_wrap_number(ret);
}

static Janet ecp_point_compare(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 2);
  int ret = compare_group(argv[0], argv[1]);
  if (ret == 0)
  {
    ret = compare_point(argv[0], argv[1]);
  }
  // Ensure that ordering is only applied if both are actually groups
  if (ret == 0
    && janet_checkabstract(argv[0], &ecp_point_object_type) != 0
    && janet_checkabstract(argv[1], &ecp_point_object_type) == 0
    )
  {
    ret = -1;
  }
  else if (ret == 0
    && janet_checkabstract(argv[0], &ecp_point_object_type) == 0
    && janet_checkabstract(argv[1], &ecp_point_object_type) != 0
    )
  {
    ret = 1;
  }
  return janet_wrap_number(ret);
}

static Janet ecp_keypair_compare(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 2);

  int ret = compare_group(argv[0], argv[1]);
  // The groups must be the same for the secrets be be comparable.
  if (ret == 0)
  {
    ret = compare_keypair(argv[0], argv[1]);
  }
  return janet_wrap_number(ret);
}

static janetls_random_object * random_from_group(janetls_ecp_group_object * group)
{
  if (group->random == NULL)
  {
    group->random = janetls_get_random();
  }
  return group->random;
}

static void ecp_group_to_string_untyped(void * data, JanetBuffer * buffer)
{
  janetls_ecp_group_object * group = data;
  const char * text = janetls_search_ecp_curve_group_text(group->group);
  if (text == NULL)
  {
    text = "unknown";
  }
  janet_buffer_push_cstring(buffer, text);
  return;
}

static int ecp_group_compare_untyped(void * x, void * y)
{
  return compare_group(janet_wrap_abstract(x), janet_wrap_abstract(y));
}

static int32_t ecp_group_hash(void * data, size_t len)
{
  (void)len;
  janetls_ecp_group_object * group = data;
  if (group->hash != 0)
  {
    return group->hash;
  }
  // https://stackoverflow.com/a/12996028
  // Hash an int
  uint32_t hash = (uint32_t)(group->group);
  hash = ((hash >> 16) ^ hash) * 0x45d9f3b;
  hash = ((hash >> 16) ^ hash) * 0x45d9f3b;
  hash = (hash >> 16) ^ hash;
  group->hash = (int32_t)hash;
  return (int32_t)hash;
}

#define MAX_BIGINT_TO_STRING_SUPPORTED 512

static void mbedtls_ecp_point_to_janet_buffer(mbedtls_ecp_point * point, JanetBuffer * buffer)
{
  // 256 bit is only like 77 characters long
  // 255 (+1 for \0) characters should support (mathamatically 847 bits)
  // There are no standard curves with such lengths, so this should be a
  // safe stack-buffer size to use.
  uint8_t buf[MAX_BIGINT_TO_STRING_SUPPORTED];
  size_t length = 0;
  int ret = mbedtls_mpi_write_string(&point->X, 10, (char *)buf, MAX_BIGINT_TO_STRING_SUPPORTED, &length);
  if (ret == 0)
  {
    janet_buffer_push_bytes(buffer, buf, length);
  }
  else
  {
    janet_buffer_push_cstring(buffer, "ERROR-X");
  }
  janet_buffer_push_u8(buffer, ',');

  ret = mbedtls_mpi_write_string(&point->Y, 10, (char *)buf, MAX_BIGINT_TO_STRING_SUPPORTED, &length);
  if (ret == 0)
  {
    janet_buffer_push_bytes(buffer, buf, length);
  }
  else
  {
    janet_buffer_push_cstring(buffer, "ERROR-Y");
  }
}

static void ecp_point_to_string_untyped(void * data, JanetBuffer * buffer)
{
  janetls_ecp_point_object * point = data;

  ecp_group_to_string_untyped(point->group, buffer);
  janet_buffer_push_u8(buffer, ':');
  mbedtls_ecp_point_to_janet_buffer(&point->point, buffer);

  return;
}

static int ecp_point_compare_untyped(void * x, void * y)
{
  return compare_point(janet_wrap_abstract(x), janet_wrap_abstract(y));
}

static int32_t ecp_point_hash(void * data, size_t len)
{
  (void)len;
  janetls_ecp_point_object * point = data;
  if (point->hash != 0)
  {
    return point->hash;
  }

  int32_t hash = 0;
  uint8_t output[MBEDTLS_ECP_MAX_PT_LEN];
  size_t length = 0;
  int ret = mbedtls_ecp_point_write_binary(
    &point->group->ecp_group,
    &point->point,
    janetls_ecp_compression_uncompressed,
    &length,
    output,
    sizeof(output)
    );
  if (ret == 0)
  {
    hash = (int32_t)janetls_crc32(output, length);;
  }
  else
  {
    // This is unlikely..
    // Just hash the raw point structure.
    hash = (int32_t)janetls_crc32((const uint8_t *) &point->point, sizeof(mbedtls_ecp_point));
  }

  // But wait! We're not done yet!
  // We need to also account for the group
  hash = hash ^ ecp_group_hash(point->group, 0);

  point->hash = hash;

  return hash;
}

static void ecp_keypair_to_string_untyped(void * data, JanetBuffer * buffer)
{
  janetls_ecp_keypair_object * keypair = data;
  ecp_group_to_string_untyped(keypair->group, buffer);
  janet_buffer_push_u8(buffer, ':');
  mbedtls_ecp_point_to_janet_buffer(&keypair->keypair.Q, buffer);
  janet_buffer_push_cstring(buffer, ":secret-");
  // The secret is intentionally not revealed.. because it might be easy to
  // accidentally toss this into a function displayed to an adversary.

  uint32_t bits = (uint32_t)keypair->group->ecp_group.nbits;
  // The bit size is bounded and should not exceed 31 base-10 digits
  char bit_count[32];
  bit_count[0] = 0; // in case something goes wrong
  sprintf(bit_count, "%"PRIu32, bits);
  janet_buffer_push_cstring(buffer, bit_count);
  janet_buffer_push_cstring(buffer, "-bits");
  return;
}

static int ecp_keypair_compare_untyped(void * x, void * y)
{
  return compare_keypair(janet_wrap_abstract(x), janet_wrap_abstract(y));;
}

static int32_t ecp_keypair_hash(void * data, size_t len)
{
  (void)len;
  janetls_ecp_keypair_object * keypair = data;
  int32_t hash = keypair->hash;
  if (hash != 0)
  {
    return hash;
  }

  hash = (int32_t)janetls_bignum_hash_mpi(&keypair->keypair.d);
  // But wait! We're not done yet!
  // We need to also account for the group
  hash = hash ^ ecp_group_hash(keypair->group, 0);

  keypair->hash = hash;
  return hash;
}

janetls_bignum_object * janetls_ecp_point_get_x(janetls_ecp_point_object * point)
{
  // the x copy is lazily created in the janet gc context
  if (point->x == NULL)
  {
    // Populate x
    janetls_bignum_object * x = janetls_new_bignum();
    check_result(mbedtls_mpi_copy(&x->mpi, &point->point.X));
    point->x = x;
  }
  return point->x;
}
janetls_bignum_object * janetls_ecp_point_get_y(janetls_ecp_point_object * point)
{
  // the y copy is lazily created in the janet gc conteyt
  if (point->y == NULL)
  {
    // Populate y
    janetls_bignum_object * y = janetls_new_bignum();
    check_result(mbedtls_mpi_copy(&y->mpi, &point->point.Y));
    point->y = y;
  }
  return point->y;
}

Janet janetls_ecp_keypair_secret(janetls_ecp_keypair_object * keypair)
{
  return keypair->secret;
}

janetls_ecp_group_object * janetls_ecp_load_curve_group(janetls_ecp_curve_group curve_group)
{
  janetls_ecp_group_object * group = janetls_new_ecp_group_object();
  group->group = curve_group;
  check_result(mbedtls_ecp_group_load(&group->ecp_group, (mbedtls_ecp_group_id)curve_group));
  group->type = (janetls_ecp_curve_type)mbedtls_ecp_get_type(&group->ecp_group);
  return group;
}

janetls_ecp_keypair_object * janetls_ecp_generate_keypair_object(janetls_ecp_group_object * group)
{
  if (group == NULL || group->group == janetls_ecp_curve_group_none)
  {
    janet_panic("Cannot generate a keypair without a curve group");
  }

  janetls_random_object * random = random_from_group(group);
  janetls_ecp_keypair_object * keypair = janetls_new_ecp_keypair_object();
  uint8_t buf[MBEDTLS_ECP_MAX_BYTES];
  keypair->group = group;

  // It also so happens that keypairs are also the "ctx" used in ecdsa,
  // without any sort of wrapping.
  // Keypairs maintain their own copy of the group.
  check_result(mbedtls_ecp_group_copy(&keypair->keypair.grp, &group->ecp_group));
  check_result(mbedtls_ecp_gen_keypair(
    &group->ecp_group,
    &keypair->keypair.d,
    &keypair->keypair.Q,
    janetls_random_rng,
    random
    ));

  size_t length = (keypair->group->ecp_group.nbits + 7) / 8;
  if (length > MBEDTLS_ECP_MAX_BYTES)
  {
    janet_panicf("The given curve has a larger bit size than is "
      "supported, the bit size appears to be %d", keypair->group->ecp_group.nbits);
  }
  check_result(mbedtls_ecp_write_key(&keypair->keypair, buf, length));
  keypair->secret = janet_wrap_string(janet_string(buf, length));
  return keypair;
}

janetls_ecp_keypair_object * janetls_ecp_load_keypair_object(janetls_ecp_group_object * group, Janet secret)
{
  if (group == NULL || group->group == janetls_ecp_curve_group_none)
  {
    janet_panic("Cannot generate a keypair without a curve group");
  }

  janetls_ecp_keypair_object * keypair = janetls_new_ecp_keypair_object();
  keypair->group = group;

  // It also so happens that keypairs are also the "ctx" used in ecdsa,
  // without any sort of wrapping.
  // Keypairs maintain their own copy of the group.
  check_result(mbedtls_ecp_group_copy(&keypair->keypair.grp, &group->ecp_group));
  ecp_keypair_from_secret(keypair, group, secret);

  return keypair;
}

janetls_ecp_point_object * janetls_ecp_load_point_object(janetls_ecp_group_object * group, janetls_bignum_object * x, janetls_bignum_object * y)
{
  janetls_ecp_point_object * point = janetls_new_ecp_point_object();
  point->group = group;
  point->x = x;
  point->y = y;
  check_result(mbedtls_mpi_copy(&point->point.X, &x->mpi));
  check_result(mbedtls_mpi_copy(&point->point.Y, &y->mpi));
  // Don't forget to set this, it's a scaling factor used internally by mbedtls..
  check_result(mbedtls_mpi_lset(&point->point.Z, 1));
  return point;
}

janetls_ecp_point_object * janetls_ecp_keypair_get_public_coordinate(janetls_ecp_keypair_object * keypair)
{
  if (keypair->public_coordinate == NULL)
  {
    // time to copy from the inside
    janetls_ecp_point_object * point = janetls_new_ecp_point_object();
    janetls_ecp_group_object * group = keypair->group;
    point->group = group;

    if ((keypair->flags & ECP_KEYPAIR_HAS_PUBLIC) == 0)
    {
      // We need to calculate the public component before we can copy from it!
      // But before that.. we need a random generator.
      // Rely on the group having one, or make it have one.

      check_result(mbedtls_ecp_mul(
        &group->ecp_group,
        &keypair->keypair.Q,
        &keypair->keypair.d,
        &group->ecp_group.G,
        janetls_random_rng,
        random_from_group(group)
        ));

      keypair->flags |= ECP_KEYPAIR_HAS_PUBLIC;
    }

    check_result(mbedtls_ecp_copy(&point->point, &keypair->keypair.Q));
    keypair->public_coordinate = point;
  }
  return keypair->public_coordinate;
}

janetls_ecp_point_object * janetls_ecp_load_point_binary(janetls_ecp_group_object * group, Janet coordinate)
{
  if (!janet_is_byte_typed(coordinate))
  {
    janet_panicf("Expected a string or buffer but got %p", coordinate);
  }
  JanetByteView bytes = janet_to_bytes(coordinate);
  janetls_ecp_point_object * point = janetls_new_ecp_point_object();
  point->group = group;
  int ret = mbedtls_ecp_point_read_binary(
    &group->ecp_group,
    &point->point,
    bytes.bytes,
    bytes.len
    );
  if (ret == MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE
    && bytes.len > 0
    && (bytes.bytes[0] == 0x02 || bytes.bytes[0] == 0x03)
    )
  {
    // For some reason mbedtls supports writing compressed points but
    // does not support reading compressed points.
    // A future enhancement can resolve this by lifting the reading
    // into this function, detecting a compressed point, and
    // decoding it properly.
    // https://www.secg.org/sec1-v2.pdf
    // 02 and 03 as the first byte describe if the Y is positive or negative
    // mbedTLS will never support decompression, as it is not mandated
    // in the TLS specification.
    // Support for compressed format has been deprecated by RFC 8422 in the
    // context of TLS, which reflects a more general sentiment in the ECC
    // community to prefer uncompressed format. Also, implementing it correctly
    // for all supported curves would require substantial code, impacting our
    // footprint - and the present PR would require non-trivial rework (values
    // of P not congruent to 3 mod 4, unit tests) before if would be ready
    // for merge.
    // I could possibly detect this and use the following
    // https://github.com/mwarning/mbedtls_ecp_compression
    // (CC-Zero 1.0 licensed)
    // but it'd only work for some groups, not all, and that'd have to be
    // detected too.

    janet_panicf("The input is likely a compressed point, which is not "
      "supported at this time.");
  }
  check_result(ret);
  check_result(mbedtls_ecp_check_pubkey(&group->ecp_group, &point->point));
  return point;
}

Janet janetls_ecp_point_get_encoded(janetls_ecp_point_object * point, janetls_ecp_compression compression)
{
  uint8_t output[MBEDTLS_ECP_MAX_PT_LEN];
  size_t length = 0;
  check_result(mbedtls_ecp_point_write_binary(
    &point->group->ecp_group,
    &point->point,
    compression,
    &length,
    output,
    sizeof(output)
    ));
  return janet_wrap_string(janet_string(output, length));
}
