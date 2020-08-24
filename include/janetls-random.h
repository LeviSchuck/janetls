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

#ifndef JANETLS_RANDOM_H
#define JANETLS_RANDOM_H
#include <janet.h>
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
extern JanetAbstractType random_object_type;
typedef struct random_object {
  // Access to the outside world, like /dev/random or via syscall
  mbedtls_entropy_context entropy;
  // Hint: DRBG: Deterministic Random Bit Generator
  mbedtls_ctr_drbg_context drbg;
  uint8_t flags;
} random_object;

// This will wrap around random_object for use elsewhere
int janetls_random_rng(void *, unsigned char *, size_t);
random_object * get_or_gen_random_object(int argc, Janet * argv, int offset);

#endif