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
#include "janetls-asn1.h"
#include "janetls-bignum.h"


static Janet asn1_encode_127(int32_t argc, Janet * argv);
static Janet asn1_decode_127(int32_t argc, Janet * argv);

static const JanetReg cfuns[] =
{
   {"asn1/encode-127", asn1_encode_127, "(janetls/asn1/encode-128 num)\n\n"
    "Encodes a number or a bignumber in binary big endian with bits that flag "
    "for continuing the number, used in ASN.1 DER.\n"
    "It is highly unlikely that you will have use for this function."
    },
  {"asn1/decode-127", asn1_decode_127, "(janetls/asn1/decode-128 string type)\n\n"
    "Decodes an arbitrary length byte sequence in base 127, used in ASN.1 DER\n"
    "type is by default :bignum, but can also be :number and :u64.\n"
    "It is highly unlikely that you will have use for this function."
    },
  {NULL, NULL, NULL}
};

void submod_asn1(JanetTable * env)
{
  janet_cfuns(env, "janetls", cfuns);
}

static Janet asn1_encode_127(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  JanetBuffer * buffer = janet_buffer(16);
  check_result(encode_base127(argv[0], buffer));
  return janet_wrap_string(janet_string(buffer->data, buffer->count));
}

static Janet asn1_decode_127(int32_t argc, Janet * argv)
{
  janet_arity(argc, 1, 2);
  if (!janet_is_byte_typed(argv[0]))
  {
    janet_panicf("Expected string or buffer to decode from, but got %p", argv[0]);
  }
  number_type type = BIGNUM;
  if (argc > 1)
  {
    JanetKeyword keyword = janet_getkeyword(argv, 1);
    if (janet_cstrcmp(keyword, "bignum") == 0)
    {
      type = BIGNUM;
    }
    else if (janet_cstrcmp(keyword, "number") == 0)
    {
      type = NUMBER;
    }
    else if (janet_cstrcmp(keyword, "u64") == 0)
    {
      type = U64;
    }
    else
    {
      janet_panicf("Expected :bignum, :number, or :u64 as the type for the "
        "second input, but got %p", argv[1]);
    }
  }
  JanetByteView bytes = janet_to_bytes(argv[0]);
  int position = 0;
  Janet result = janet_wrap_nil();

  check_result(decode_base127(bytes, &result, &position, type));
  if (position < bytes.len)
  {
    janet_panicf("Expected to parse the entire string or buffer as a number or bignum, but %d bytes remain", (long)(bytes.len - position));
  }
  return result;
}

// int decode_base127(const uint8_t * buffer, int buffer_length, bignum_object * destination, int * position)
#define MAX_BITS (sizeof(uint64_t) * 8)
int decode_base127(JanetByteView bytes, Janet * wrapped_destination, int * position, number_type type)
{
  int ret = 0;
  if (type == BIGNUM)
  {
    bignum_object * destination = new_bignum();
    mbedtls_mpi * num = &destination->mpi;
    mbedtls_mpi copy;
    mbedtls_mpi_init(&copy);
    ret = mbedtls_mpi_lset(num, 0);

    if (ret != 0)
    {
      return ret;
    }

    while(1)
    {
      int pos = *position;
      if (pos >= bytes.len)
      {
        // we've hit the end of the buffer
        break;
      }
      uint8_t byte = bytes.bytes[pos];
      (*position)++;
      ret = mbedtls_mpi_shift_l(num, 7);
      if (ret != 0)
      {
        break;
      }
      ret = mbedtls_mpi_copy(&copy, num);
      if (ret != 0)
      {
        break;
      }
      ret = mbedtls_mpi_add_int(num, &copy, byte & 0x7f);
      if (ret != 0)
      {
        break;
      }
      if ((byte & 0x80) == 0)
      {
        // We've hit the end!
        ret = 0;
        break;
      }
    }

    mbedtls_mpi_free(&copy);
    *wrapped_destination = janet_wrap_abstract(destination);
  }
  else
  {
    size_t bits_used = 0;
    uint64_t result = 0;
     while(1)
    {
      if (bits_used > MAX_BITS)
      {
        break;
      }

      int pos = *position;
      if (pos >= bytes.len)
      {
        // we've hit the end of the buffer
        break;
      }

      uint8_t byte = bytes.bytes[pos];
      (*position)++;
      // Filter out the higher bit as it is not part of the number encoded.
      result = (result << 7) + (byte & 0x7f);
      bits_used += 7;

      // The highest bit signals that there's more to come.
      // We observe here that there is no more.
      if ((byte & 0x80) == 0)
      {
        // We've hit the end!
        break;
      }
    }
    if (bits_used > MAX_BITS)
    {
      janet_panic("Overflowed while parsing base 127 sequence into a number, "
        "try as a bignum instead");
    }
    if (type == NUMBER)
    {
      if (result > JANET_INTMAX_INT64)
      {
        janet_panic("The number fit within a u64, but not a janet number");
      }
      *wrapped_destination = janet_wrap_number((double)result);
    }
    else
    {
      *wrapped_destination = janet_wrap_u64(result);
    }
  }

  return ret;
}

int encode_base127(Janet wrapped_source, JanetBuffer * buffer)
{
  // For now this only supports bignumbers.
  bignum_object * source = janet_unwrap_abstract(unknown_to_bignum(wrapped_source));
  int ret = 0;
  if (mbedtls_mpi_cmp_int(&source->mpi, 0) == 0)
  {
    // Trivial case.
    janet_buffer_ensure(buffer, 1, 1);
    janet_buffer_push_u8(buffer, 0);
    return 0;
  }
  // chosen 16 bytes arbitrarily..
  JanetBuffer * intermediate = janet_buffer(16);
  int size = 0;
  mbedtls_mpi acc;
  mbedtls_mpi_init(&acc);
  ret = mbedtls_mpi_copy(&acc, &source->mpi);
  if (ret != 0)
  {
    goto cleanup;
  }

  while (mbedtls_mpi_cmp_int(&acc, 0) == 1)
  {
    mbedtls_mpi_uint digit = 0;
    ret = mbedtls_mpi_mod_int(&digit, &acc, 128);
    if (ret != 0)
    {
      goto cleanup;
    }
    janet_buffer_ensure(intermediate, size, 4);
    if (size == 0)
    {
      janet_buffer_push_u8(intermediate, digit & 0xff);
    }
    else
    {
      janet_buffer_push_u8(intermediate, (digit | 0x80) & 0xff);
    }
    ret = mbedtls_mpi_shift_r(&acc, 7);
    if (ret != 0)
    {
      goto cleanup;
    }
    size++;
  }

  JanetByteView bytes = janet_to_bytes(janet_wrap_buffer(intermediate));
  janet_buffer_ensure(buffer, bytes.len, 4);
  for (int i = (bytes.len - 1); i >= 0; i--)
  {
    // Add the intermediate buffer in reverse to the output buffer, since
    // we worked on least significant 128 bit chunks at a time
    janet_buffer_push_u8(buffer, bytes.bytes[i]);
  }

cleanup:
  mbedtls_mpi_free(&acc);

  return ret;
}