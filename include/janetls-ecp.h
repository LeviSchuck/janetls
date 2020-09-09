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

typedef struct janetls_ecp_group_object {
  mbedtls_ecp_group group;
} janetls_ecp_group_object;

typedef struct janetls_ecp_point_object {
  mbedtls_ecp_point point;
  janetls_ecp_group_object * group;
  bignum_object * x;
  bignum_object * y;
} janetls_ecp_point_object;

typedef struct janetls_ecp_keypair_object {
  mbedtls_ecp_keypair keypair;
  janetls_ecp_group_object * group;
  bignum_object * secret;
  janetls_ecp_point_object * public_coordinate;
} janetls_ecp_keypair_object;

janetls_ecp_group_object * janetls_new_ecp_group_object();
janetls_ecp_point_object * janetls_new_ecp_point_object();
janetls_ecp_keypair_object * janetls_new_ecp_keypair_object();

#endif