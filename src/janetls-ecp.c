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

static Janet ecp_group_from_key(int32_t argc, Janet * argv);
static Janet ecp_group_get_group(int32_t argc, Janet * argv);
static Janet ecp_group_get_curve_group(int32_t argc, Janet * argv);
static Janet ecp_group_get_generator(int32_t argc, Janet * argv);
static Janet ecp_group_get_zero(int32_t argc, Janet * argv);
static Janet ecp_group_compare(int32_t argc, Janet * argv);
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

static janetls_ecp_point_object * point_from_janet(Janet value, int panic);
static janetls_ecp_group_object * group_from_janet(Janet value, int panic);

static int compare_group(Janet a, Janet b);
static int compare_point(Janet a, Janet b);
static int compare_keypair(Janet a, Janet b);

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
  {"group", ecp_group_get_group},
  {"generator", ecp_group_get_generator},
  {"zero", ecp_group_get_zero},
  {"import-point", ecp_point_import},
  {"import-key", ecp_keypair_import},
  {"compare", ecp_group_compare},
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
    "janetls/ecp/groups."
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
  {"ecp/y", ecp_point_get_x, "(janetls/ecp/y multple)\n\n"
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
    "janetls/ecp/compression."
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
  mbedtls_ecp_group_free(&group->ecp_group);
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
  janetls_ecp_keypair_object * point = (janetls_ecp_keypair_object *)data;

  if (point->group != NULL)
  {
    janet_mark(janet_wrap_abstract(point->group));
  }

  if (point->secret != NULL)
  {
    janet_mark(janet_wrap_abstract(point->secret));
  }

  if (point->public_coordinate != NULL)
  {
    janet_mark(janet_wrap_abstract(point->public_coordinate));
  }

  return 0;
}

janetls_ecp_group_object * janetls_new_ecp_group_object()
{
  janetls_ecp_group_object * group = janet_abstract(&janetls_ecp_group_object_type, sizeof(janetls_ecp_group_object));
  memset(group, 0, sizeof(janetls_ecp_group_object));
  mbedtls_ecp_group_init(&group->ecp_group);
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

static Janet ecp_group_from_key(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_ecp_curve_group group;
  if (janetls_search_ecp_curve_group(argv[0], &group) != 0)
  {
    janet_panicf("Could not find a group for %p, see (janetls/ecp/groups) for options", argv[0]);
  }
  janetls_ecp_group_object * group_object = janetls_new_ecp_group_object();
  group_object->group = group;
  check_result(mbedtls_ecp_group_load(&group_object->ecp_group, (mbedtls_ecp_group_id)group));
  group_object->type = mbedtls_ecp_get_type(&group_object->ecp_group);
  return janet_wrap_abstract(group_object);
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
  Janet curve = ecp_group_get_group(argc, argv);
  janetls_ecp_group_object * group = janet_unwrap_abstract(curve);
  janetls_ecp_point_object * point = janetls_new_ecp_point_object();
  check_result(mbedtls_ecp_copy(&point->point, &group->ecp_group.G));
  point->group = group;
  return janet_wrap_abstract(point);
}

static Janet ecp_group_get_zero(int32_t argc, Janet * argv)
{
  Janet curve = ecp_group_get_group(argc, argv);
  janetls_ecp_group_object * group = janet_unwrap_abstract(curve);
  janetls_ecp_point_object * point = janetls_new_ecp_point_object();
  check_result(mbedtls_ecp_set_zero(&point->point));
  point->group = group;
  return janet_wrap_abstract(point);
}

static Janet ecp_point_get_x(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_ecp_point_object * point = point_from_janet(argv[0], 1);

  // the x copy is lazily created in the janet gc context
  if (point->x == NULL)
  {
    // Populate x
    bignum_object * x = new_bignum();
    check_result(mbedtls_mpi_copy(&x->mpi, &point->point.X));
    point->x = x;
  }
  return janet_wrap_abstract(point->x);
}

static Janet ecp_point_get_y(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_ecp_point_object * point = point_from_janet(argv[0], 1);

  // the y copy is lazily created in the janet gc context
  if (point->y == NULL)
  {
    // Populate y
    bignum_object * y = new_bignum();
    check_result(mbedtls_mpi_copy(&y->mpi, &point->point.Y));
    point->y = y;
  }
  return janet_wrap_abstract(point->y);
}

static Janet ecp_point_is_zero(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_ecp_point_object * point = point_from_janet(argv[0], 1);
  return janet_wrap_boolean(mbedtls_ecp_is_zero(&point->point));
}

static Janet ecp_point_export(int32_t argc, Janet * argv)
{
  return janet_wrap_nil();
}

static Janet ecp_point_import(int32_t argc, Janet * argv)
{
  return janet_wrap_nil();
}

static Janet ecp_keypair_get_point(int32_t argc, Janet * argv)
{
  return janet_wrap_nil();
}

static Janet ecp_keypair_get_secret(int32_t argc, Janet * argv)
{
  return janet_wrap_nil();
}

static Janet ecp_keypair_export(int32_t argc, Janet * argv)
{
  return janet_wrap_nil();
}

static Janet ecp_keypair_import(int32_t argc, Janet * argv)
{
  return janet_wrap_nil();
}

static janetls_ecp_point_object * point_from_janet(Janet value, int panic)
{
  janetls_ecp_point_object * point = janet_checkabstract(value, &janetls_ecp_point_object_type);
  if (point == NULL)
  {
    janetls_ecp_keypair_object * keypair = janet_checkabstract(value, &janetls_ecp_keypair_object_type);
    if (keypair != NULL)
    {
      point = keypair->public_coordinate;
    }
  }
  if (point == NULL && panic)
  {
    janet_panicf("Expected a point or keypair");
  }
  return point;
}

static janetls_ecp_group_object * group_from_janet(Janet value, int panic)
{
  janetls_ecp_group_object * group_object = janet_checkabstract(value, &janetls_ecp_group_object_type);
  if (group_object != NULL)
  {
    return group_object;
  }

  janetls_ecp_point_object * point_object = janet_checkabstract(value, &janetls_ecp_group_object_type);
  if (point_object != NULL && point_object->group != NULL)
  {
    return point_object->group;
  }

  janetls_ecp_keypair_object * keypair_object = janet_checkabstract(value, &janetls_ecp_group_object_type);
  if (keypair_object != NULL && keypair_object->group != NULL)
  {
    return keypair_object->group;
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
  janetls_ecp_keypair_object * keypair1 = janet_checkabstract(a, &janetls_ecp_keypair_object_type);
  janetls_ecp_keypair_object * keypair2 = janet_checkabstract(b, &janetls_ecp_keypair_object_type);

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
    && janet_checkabstract(argv[0], &janetls_ecp_group_object_type) != 0
    && janet_checkabstract(argv[1], &janetls_ecp_group_object_type) == 0
    )
  {
    ret = -1;
  }
  else if (ret == 0
    && janet_checkabstract(argv[0], &janetls_ecp_group_object_type) == 0
    && janet_checkabstract(argv[1], &janetls_ecp_group_object_type) != 0
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
    && janet_checkabstract(argv[0], &janetls_ecp_point_object_type) != 0
    && janet_checkabstract(argv[1], &janetls_ecp_point_object_type) == 0
    )
  {
    ret = -1;
  }
  else if (ret == 0
    && janet_checkabstract(argv[0], &janetls_ecp_point_object_type) == 0
    && janet_checkabstract(argv[1], &janetls_ecp_point_object_type) != 0
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
