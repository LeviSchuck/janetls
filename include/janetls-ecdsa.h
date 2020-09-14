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

#ifndef JANETLS_ECDSA_H
#define JANETLS_ECDSA_H
#include <janet.h>
#include "mbedtls/ecdsa.h"
#include "janetls-options.h"
#include "janetls-random.h"
#include "janetls-ecp.h"

typedef struct janetls_ecdsa_object {
  janetls_ecp_group_object * group;
  janetls_ecp_point_object * point;
  janetls_ecp_keypair_object * keypair;
  janetls_random_object * random;
  janetls_pk_information_class information_class;
  janetls_md_algorithm digest;
} janetls_ecdsa_object;

janetls_ecdsa_object * janetls_new_ecdsa();

JanetAbstractType * janetls_ecdsa_object_type();

#endif