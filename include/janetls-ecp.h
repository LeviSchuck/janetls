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

#ifndef JANETLS_ECP_H
#define JANETLS_ECP_H
#include <janet.h>
#include "mbedtls/ecp.h"
#include "janetls-options.h"
#include "janetls-bignum.h"
#include "janetls-random.h"

typedef struct janetls_ecp_group_object {
  mbedtls_ecp_group ecp_group;
  janetls_ecp_curve_type type;
  janetls_ecp_curve_group group;
  janetls_random_object * random;
  struct janetls_ecp_point_object * zero;
  struct janetls_ecp_point_object * generator;
  int32_t hash;
} janetls_ecp_group_object;

typedef struct janetls_ecp_point_object {
  mbedtls_ecp_point point;
  janetls_ecp_group_object * group;
  janetls_bignum_object * x;
  janetls_bignum_object * y;
  int32_t hash;
} janetls_ecp_point_object;

typedef struct janetls_ecp_keypair_object {
  mbedtls_ecp_keypair keypair;
  janetls_ecp_group_object * group;
  janetls_ecp_point_object * public_coordinate;
  Janet secret;
  int flags;
  int32_t hash;
} janetls_ecp_keypair_object;

janetls_ecp_group_object * janetls_new_ecp_group_object();
janetls_ecp_point_object * janetls_new_ecp_point_object();
janetls_ecp_keypair_object * janetls_new_ecp_keypair_object();

JanetAbstractType * janetls_ecp_group_object_type();
JanetAbstractType * janetls_ecp_point_object_type();
JanetAbstractType * janetls_ecp_keypair_object_type();

janetls_bignum_object * janetls_ecp_point_get_x(janetls_ecp_point_object * point);
janetls_bignum_object * janetls_ecp_point_get_y(janetls_ecp_point_object * point);
Janet janetls_ecp_point_get_encoded(janetls_ecp_point_object * point, janetls_ecp_compression compression);
janetls_ecp_point_object * janetls_ecp_keypair_get_public_coordinate(janetls_ecp_keypair_object * keypair);
Janet janetls_ecp_keypair_secret(janetls_ecp_keypair_object * keypair);

janetls_ecp_group_object * janetls_ecp_load_curve_group(janetls_ecp_curve_group curve_group);
janetls_ecp_keypair_object * janetls_ecp_generate_keypair_object(janetls_ecp_group_object * group);
janetls_ecp_keypair_object * janetls_ecp_load_keypair_object(janetls_ecp_group_object * group, Janet secret);
janetls_ecp_point_object * janetls_ecp_load_point_binary(janetls_ecp_group_object * group, Janet coordinate);
janetls_ecp_point_object * janetls_ecp_load_point_object(janetls_ecp_group_object * group, janetls_bignum_object * x, janetls_bignum_object * y);

janetls_ecp_keypair_object * keypair_from_janet(Janet value, int panic);
janetls_ecp_point_object * point_from_janet(Janet value, int panic);
janetls_ecp_group_object * group_from_janet(Janet value, int panic);

#endif
