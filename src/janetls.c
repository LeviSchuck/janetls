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

const char * result_error_message(int result, uint8_t * unhandled)
{
  switch (result)
  {
    case 0:
      return "There is no error.";
    case MBEDTLS_ERR_MPI_NOT_ACCEPTABLE:
      return "The input value was not acceptable";
    case MBEDTLS_ERR_MPI_NEGATIVE_VALUE:
      return "An input value was negative when it cannot be";
    case MBEDTLS_ERR_MPI_INVALID_CHARACTER:
      return "Cannot parse, an invalid character was found";
    case MBEDTLS_ERR_MPI_DIVISION_BY_ZERO:
      return "Division by zero";
    case MBEDTLS_ERR_MD_ALLOC_FAILED:
    case MBEDTLS_ERR_MPI_ALLOC_FAILED:
    case JANETLS_ERR_ALLOCATION_FAILED:
      return "Ran out of memory";
    case MBEDTLS_ERR_MD_BAD_INPUT_DATA:
    case MBEDTLS_ERR_MPI_BAD_INPUT_DATA:
      return "One of the inputs is bad";
    case MBEDTLS_ERR_MPI_FILE_IO_ERROR:
      return "File IO error with bignum";
    case MBEDTLS_ERR_MD_HW_ACCEL_FAILED:
      return "Unable to use hardware acceleration";
    case MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR:
    case MBEDTLS_ERR_MD_FILE_IO_ERROR:
      return "IO Error with file system";
    case MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE:
      return "Message Digest feature unavailable";
    case MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED:
      return "Unable to gather entropy for random number generation";
    case MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG:
      return "The input was too big";
    case MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG:
      return "Too many bytes were requested at once";
    // -------------- JANETLS ERRORS ------------------
    case JANETLS_ERR_ASN1_INVALID_BIT_STRING_LENGTH:
      return "A bitstring had an invalid length while parsing";
    case JANETLS_ERR_ASN1_EMPTY_INPUT:
      return "Cannot operate on an empty ASN.1 document";
    case JANETLS_ERR_ASN1_OTHER:
      return "An internal error has occurred within ASN.1 parsing";
    case JANETLS_ERR_ASN1_INCOMPLETE:
      return "Expected more bytes while parsing ASN.1 document, but reached end of content";
    case JANETLS_ERR_ASN1_TEXT_PARSE_ERR:
      return "While decoding text, an invalid character was encountered";
    case JANETLS_ERR_ASN1_INVALID_ASN1_CLASS:
      return "Could not determine the ASN.1 class from tag byte, appears invalid";
    case JANETLS_ERR_ASN1_DATE_PARSE_ERROR:
      return "A date field could not be parsed correctly";
    case JANETLS_ERR_ASN1_LENGTH_TOO_LARGE:
      return "The length parsed on a tag is too large and is larger than the document";
    case JANETLS_ERR_ASN1_U64_OVERFLOW:
      return "The number could not fit in a u64, try a bignum instead";
    case JANETLS_ERR_ASN1_NUMBER_OVERFLOW:
      return "The number could not fit into a janet number, try a bignum instead";
    case JANETLS_ERR_ASN1_BOOLEAN_INVALID_LENGTH:
      return "Invalid boolean length, should be 1 byte";
    case JANETLS_ERR_ASN1_OBJECT_IDENTIFIER_INVALID_LENGTH:
      return "Invalid object identifier length, either too short, or overflowed";
  }
  *unhandled = 1;
  return "An internal error occurred";
}

void check_result(int result)
{
  if (result == 0)
  {
    return;
  }
  uint8_t unhandled = 0;
  const char * message = result_error_message(result, &unhandled);
  if (unhandled)
  {
    janet_panicf("%s: %d", message, result);
  }
  else
  {
    janet_panic(message);
  }
}
