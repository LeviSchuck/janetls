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

#ifndef JANETLS_BIGNUM_H
#define JANETLS_BIGNUM_H
#include "mbedtls/bignum.h"

typedef struct janetls_bignum_object {
  // Hint: MPI: Multi-Precision-Integer
  mbedtls_mpi mpi;
  uint8_t flags;
  int32_t hash;
} janetls_bignum_object;
janetls_bignum_object * janetls_new_bignum();
Janet unknown_to_bignum(Janet value);
Janet unknown_to_bignum_opt(Janet value, int panic, int radix);
int janetls_unknown_to_bignum(Janet * destination, Janet value, int radix);
int janetls_bignum_to_bytes(Janet * destination, Janet value);
int janetls_bignum_to_digits(Janet * destination, Janet value);
uint32_t janetls_bignum_hash_mpi(mbedtls_mpi * mpi);
JanetAbstractType * janetls_bignum_object_type();
#endif
