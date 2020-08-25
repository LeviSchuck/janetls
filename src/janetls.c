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
#include "mbedtls/bignum.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"

JANET_MODULE_ENTRY(JanetTable *env)
{
  submod_md(env);
  submod_util(env);
  submod_bignum(env);
  submod_random(env);
  submod_byteslice(env);
  submod_asn1(env);
}

void check_result(int mbedtls_result)
{
  if (mbedtls_result == 0)
  {
    return;
  }
  switch (mbedtls_result)
  {
    case MBEDTLS_ERR_MPI_NOT_ACCEPTABLE:
      janet_panic("The input value was not acceptable");
    case MBEDTLS_ERR_MPI_NEGATIVE_VALUE: janet_panic("An input value was negative when it cannot be");
    case MBEDTLS_ERR_MPI_INVALID_CHARACTER: janet_panic("Cannot parse, an invalid character was found");
    case MBEDTLS_ERR_MPI_DIVISION_BY_ZERO: janet_panic("Division by zero");
    case MBEDTLS_ERR_MD_ALLOC_FAILED:
    case MBEDTLS_ERR_MPI_ALLOC_FAILED:
      janet_panic("Ran out of memory");
    case MBEDTLS_ERR_MD_BAD_INPUT_DATA:
    case MBEDTLS_ERR_MPI_BAD_INPUT_DATA: janet_panic("One of the inputs is bad");
    case MBEDTLS_ERR_MPI_FILE_IO_ERROR: janet_panic("File IO error with bignum");
    case MBEDTLS_ERR_MD_HW_ACCEL_FAILED: janet_panic("Unable to use hardware acceleration");
    case MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR:
    case MBEDTLS_ERR_MD_FILE_IO_ERROR: janet_panic("IO Error with file system");
    case MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE: janet_panic("Message Digest feature unavailable");
    case MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED: janet_panic("Unable to gather entropy for random number generation");
    case MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG: janet_panic("The input was too big");
    case MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG: janet_panic("Too many bytes were requested at once");
  }
  janet_panicf("An internal error occurred: %x", mbedtls_result);
}
