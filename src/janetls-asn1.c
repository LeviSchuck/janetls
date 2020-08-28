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
#include "janetls-byteslice.h"
#include <ctype.h>

int parse_length(asn1_parser * parser, uint64_t * length);
int parse_header(asn1_parser * parser, asn1_parsed_tag * parsed);
int decode_base127(JanetByteView bytes, Janet * destination, int * position, number_type bignum);
int decode_base127_as_u64(asn1_parser * parser, uint64_t * external_result);
int encode_base127(Janet source, JanetBuffer * buffer);
int decode_class(uint8_t byte_tag, asn1_class * result);
int decode_asn1(asn1_parser * parser, JanetStruct * output);
int decode_asn1_construction(asn1_parser * parser, JanetTuple * output);

static Janet asn1_encode_127(int32_t argc, Janet * argv);
static Janet asn1_decode_127(int32_t argc, Janet * argv);
static Janet asn1_decode(int32_t argc, Janet * argv);

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
  {"asn1/decode", asn1_decode, "()"},
  {NULL, NULL, NULL}
};

void submod_asn1(JanetTable * env)
{
  janet_cfuns(env, "janetls", cfuns);
}


// ASN1 Object:
// Type (byte)
// Interpreted Type (Unknown, Boolean, Integer, BitString, OctetString, Null,
// ... ObjectIdentifier, UTF8String, PrintableString, TeletextString, IA5String,
// ... UTCTime, GeneralizedTime, UniversalString, BMPString, Sequence, Set)
// Interpreted Type constructed? (boolean)
// Interpreted Type class (Universal, Application, Context Specific, Private)
// Contextual Type number (optional)
// Length (number)
// Position (number)
// Value (depends!)
// Value Position (number)
// Value byte slice
// Object byte slice
// Parsed sub value (Optional, happens when bitstring or octetstring)

// This helps detect problems during parsing, specifically going backwards.
JANET_THREAD_LOCAL size_t thread_position = 0;

static Janet asn1_decode(int32_t argc, Janet * argv)
{
  thread_position = 0;
  janet_arity(argc, 1, 5);
  if (!janet_is_byte_typed(argv[0]))
  {
    janet_panicf("Expected string or buffer, but got %p", argv[0]);
  }
  uint64_t flags = 0;
  base64_variant base64_variant = STANDARD;

  for (int i = 1; i < argc; i++)
  {
    JanetKeyword keyword = janet_getkeyword(argv, i);
    if (janet_cstrcmp(keyword, "eager-parse") == 0)
    {
      flags |= ASN1_FLAG_EAGER_PARSE;
    }
    else if (janet_cstrcmp(keyword, "bignum-as-string") == 0)
    {
      flags |= ASN1_FLAG_BIGNUM_AS_STRING;
    }
    else if (janet_cstrcmp(keyword, "base64-non-ascii") == 0)
    {
      flags |= ASN1_BASE64_NON_ASCII;
    }
    else if (janet_cstrcmp(keyword, "base64-url") == 0)
    {
      base64_variant = URL;
    }
    else if (janet_cstrcmp(keyword, "json") == 0)
    {
      flags |= ASN1_BASE64_NON_ASCII | ASN1_FLAG_BIGNUM_AS_STRING;
      base64_variant = URL;
    }
    else
    {
      janet_panicf("Unexpected flag %p", keyword);
    }
  }

  JanetByteView bytes = janet_to_bytes(argv[0]);
  asn1_parser parser;
  parser.buffer = bytes.bytes;
  parser.length = bytes.len;
  parser.position = 0;
  parser.source = argv[0];
  parser.flags = flags;
  parser.base64_variant = base64_variant;

  JanetTuple result;
  check_result(decode_asn1_construction(&parser, &result));
  return janet_wrap_tuple(result);
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
    asn1_parser parser;
    parser.buffer = bytes.bytes;
    parser.length = bytes.len;
    parser.position = 0;
    parser.source = janet_wrap_nil();
    parser.base64_variant = STANDARD;
    parser.flags = 0;
    uint64_t result;
    ret = decode_base127_as_u64(&parser, &result);
    *position = parser.position;
    if (ret == 0)
    {
      if (type == NUMBER)
      {
        if (result > JANET_INTMAX_INT64)
        {
          return JANETLS_ERR_ASN1_NUMBER_OVERFLOW;
        }
        *wrapped_destination = janet_wrap_number((double)result);
      }
      else
      {
        *wrapped_destination = janet_wrap_u64(result);
      }
    }
  }

  return ret;
}

int decode_base127_as_u64(asn1_parser * parser, uint64_t * external_result)
{
  size_t bits_used = 0;
  uint64_t result = 0;

  while(1)
  {
    if (bits_used > MAX_BITS)
    {
      break;
    }

    if (parser->position >= parser->length)
    {
      return JANETLS_ERR_ASN1_INCOMPLETE;
    }

    uint8_t byte = parser->buffer[parser->position++];
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
    return JANETLS_ERR_ASN1_U64_OVERFLOW;
  }

  *external_result = result;

  return 0;
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

// TODO parse asn1 to tables or something.

int parse_header(asn1_parser * parser, asn1_parsed_tag * parsed)
{
  if (parser->position >= parser->length)
  {
    return JANETLS_ERR_ASN1_INCOMPLETE;
  }
  int ret = 0;
  const uint8_t * tag_start = parser->buffer + parser->position;
  const uint8_t tag_byte = parser->buffer[parser->position++];
  uint8_t constructed = (tag_byte & 0x20) != 0;
  uint8_t base_tag = tag_byte & 0x1F;
  uint64_t tag = base_tag;
  asn1_class class;
  asn1_universal_type universal_type;
  const uint8_t * value_start;
  size_t value_length;

  if (base_tag == 0x1F)
  {
    ret = decode_base127_as_u64(parser, &tag);
    if (ret != 0) goto end;
  }

  switch (base_tag)
  {
    case 1:
      universal_type = BOOLEAN;
      break;
    case 2:
      universal_type = INTEGER;
      break;
    case 3:
      universal_type = BIT_STRING;
      break;
    case 4:
      universal_type = OCTET_STRING;
      break;
    case 5:
      universal_type = NULL_TYPE;
      break;
    case 6:
      universal_type = OBJECT_IDENTIFIER;
      break;
    case 0x0c:
      universal_type = UTF8_STRING;
      break;
    case 0x10:
      universal_type = SEQUENCE;
      break;
    case 0x11:
      universal_type = SET;
      break;
    case 0x13:
      universal_type = PRINTABLE_STRING;
      break;
    case 0x14:
      universal_type = TELETEX_STRING;
      break;
    case 0x16:
      universal_type = IA5_ASCII_STRING;
      break;
    case 0x17:
      universal_type = UTC_TIME;
      break;
    case 0x18:
      universal_type = GENERALIZED_TIME;
      break;
    case 0x1C:
      universal_type = UNIVERSAL_STRINGS;
      break;
    case 0x1E:
      universal_type = BITMAP_STRING;
      break;
    default:
      universal_type = NOT_UNIVERSAL;
      break;
  }

  ret = decode_class(tag_byte, &class);
  if (ret != 0) goto end;

  if (class != UNIVERSAL)
  {
    universal_type = NOT_UNIVERSAL;
  }

  ret = parse_length(parser, &value_length);
  if (ret != 0) goto end;
  if ((parser->position + value_length) > (parser->length))
  {
    ret = JANETLS_ERR_ASN1_LENGTH_TOO_LARGE;
    goto end;
  }

  value_start = parser->buffer + parser->position;
  // Populate return value (output parameter)
  parsed->tag = tag;
  parsed->asn1_class = class;
  parsed->base_tag_byte = base_tag;
  parsed->constructed = constructed;
  parsed->tag_start = tag_start;
  parsed->value_start = value_start;
  parsed->value_end = value_start + value_length;
  parsed->tag_position = tag_start - (parser->buffer);
  parsed->value_position = value_start - (parser->buffer);
  parsed->header_length = value_start - tag_start;
  parsed->value_length = value_length;
  parsed->asn1_universal_type = universal_type;

end:
  return ret;
}

int decode_class(uint8_t byte_tag, asn1_class * result)
{
  int ret = 0;
  switch (byte_tag >> 6)
  {
    case 0:
      *result = UNIVERSAL;
      break;
    case 1:
      *result = APPLICATION;
      break;
    case 2:
      *result = CONTEXT_SPECIFIC;
      break;
    case 3:
      *result = PRIVATE;
      break;
    default:
      ret = JANETLS_ERR_ASN1_INVALID_ASN1_CLASS;
  }
  return ret;
}

int parse_length(asn1_parser * parser, uint64_t * length)
{
  if (parser->position >= parser->length)
  {
    return JANETLS_ERR_ASN1_INCOMPLETE;
  }
  uint64_t internal_length = 0;
  uint8_t byte = parser->buffer[parser->position];
  parser->position++;
  if (byte >= 0x80)
  {
    uint8_t length_length = byte & 0x7f;
    if (length_length > sizeof(uint64_t))
    {
      // The standard allows for a bignum size here, but
      // there's no way we're going to have an ASN.1 document
      // which exceeds 16 exabytes.
      return JANETLS_ERR_ASN1_LENGTH_TOO_LARGE;
    }
    for (uint8_t i = 0; i < length_length; i++)
    {
      if (parser->position >= parser->length)
      {
        return JANETLS_ERR_ASN1_INCOMPLETE;
      }

      // What follows is a big-endian number
      internal_length = (internal_length << 8) + parser->buffer[parser->position];
      parser->position++;
    }
  }
  else
  {
    internal_length = byte;
  }

  // Copy correct result upon success
  *length = internal_length;
  return 0;
}


int decode_asn1_construction(asn1_parser * parser, JanetTuple * output)
{
  JanetArray * array = janet_array(10);
  int ret = 0;
  int count = 0;
  while (parser->position < parser->length)
  {
    JanetStruct result;
    ret = decode_asn1(parser, &result);
    if (ret != 0) goto end;
    janet_array_push(array, janet_wrap_struct(result));
    count++;
  }

  if (count == 0)
  {
    ret = JANETLS_ERR_ASN1_EMPTY_INPUT;
    goto end;
  }

  *output = janet_tuple_n(array->data, array->count);

end:
  return ret;
}

int decode_asn1(asn1_parser * parser, JanetStruct * output)
{
  asn1_parsed_tag tag;
  int ret = parse_header(parser, &tag);
  if (ret != 0) goto end;

  // Arbitrary choice of 8 for now.
  JanetTable * result = janet_table(8);
  Janet value = janet_wrap_nil();
  uint8_t sub_value = 0;

  const char * class_keyword = "invalid";
  switch (tag.asn1_class)
  {
    case UNIVERSAL:
      class_keyword = "universal";
      break;
    case CONTEXT_SPECIFIC:
      class_keyword = "context-specific";
      sub_value = 1;
      break;
    case APPLICATION:
      class_keyword = "application";
      sub_value = 1;
      break;
    case PRIVATE:
      class_keyword = "private";
      sub_value = 1;
      break;
  }

  const char * type_keyword = "not-universal";

  switch (tag.asn1_universal_type)
  {
    case BOOLEAN:
    {
      if (tag.value_length != 1)
      {
        ret = JANETLS_ERR_ASN1_BOOLEAN_INVALID_LENGTH;
        goto end;
      }
      uint8_t bool_value = parser->buffer[parser->position++];
      value = janet_wrap_boolean(bool_value != 0);
      type_keyword = "boolean";
      break;
    }
    case INTEGER:
    {
      bignum_object * bignum = new_bignum();
      if (tag.value_length == 0)
      {
        // I guess it's 0?
        ret = mbedtls_mpi_lset(&bignum->mpi, 0);
      }
      else
      {
        ret = mbedtls_mpi_read_binary(&bignum->mpi, (parser->buffer) + (tag.value_position), tag.value_length);
      }
      if (ret != 0) goto end;
      if (parser->flags & ASN1_FLAG_BIGNUM_AS_STRING)
      {
        // Todo, outsource this to the bignum module
        size_t bytes = 0;
        mbedtls_mpi_write_string(&bignum->mpi, 10, NULL, 0, &bytes);
        char * string_value = janet_smalloc(bytes);
        if (string_value == NULL)
        {
          ret = JANETLS_ERR_ALLOCATION_FAILED;
          goto end;
        }
        ret = mbedtls_mpi_write_string(&bignum->mpi, 10, string_value, bytes, &bytes);
        if (ret != 0)
        {
          // Free the intermediate string_value as it will not be used
          janet_sfree(string_value);
          goto end;
        }
        value = janet_cstringv(string_value);
        // Make sure to free the intermediate value
        janet_sfree(string_value);
      }
      else
      {
        value = janet_wrap_abstract(bignum);
      }
      parser->position += tag.value_length;
      type_keyword = "integer";
      break;
    }
    case BIT_STRING:
    {
      if (tag.value_length == 0)
      {
        value = janet_cstringv("");
        janet_table_put(result, janet_ckeywordv("bits"), janet_wrap_number(0));
      }
      else if (tag.value_length > 1)
      {
        uint64_t bits = ((tag.value_length - 1) * 8) - parser->buffer[tag.value_position];
        value = janet_wrap_string(janet_string((parser->buffer) + (tag.value_position) + 1, tag.value_length));
        janet_table_put(result, janet_ckeywordv("bits"), janet_wrap_number(bits));
        parser->position += tag.value_length;
      }
      else
      {
        ret = JANETLS_ERR_ASN1_INVALID_BIT_STRING_LENGTH;
        goto end;
      }
      type_keyword = "bit-string";
      sub_value = 1;
      break;
    }
    case OCTET_STRING:
    {
      value = janet_wrap_string(janet_string((parser->buffer) + (tag.value_position), tag.value_length));
      parser->position += tag.value_length;
      type_keyword = "octet-string";
      sub_value = 1;
      break;
    }
    case NULL_TYPE:
    {
      value = janet_wrap_nil();
      parser->position += tag.value_length; // Technically should be zero..
      // but if it isn't then we'll skip it anyway.
      type_keyword = "null";
      break;
    }
    case OBJECT_IDENTIFIER:
    {
      size_t end_position = tag.value_position + tag.value_length;
      if (end_position > parser->length)
      {
        ret = JANETLS_ERR_ASN1_INCOMPLETE;
        goto end;
      }
      if (tag.value_length < 2)
      {
        ret = JANETLS_ERR_ASN1_OBJECT_IDENTIFIER_INVALID_LENGTH;
        goto end;
      }
      JanetArray * array = janet_array(10);
      uint8_t value1 = 0;
      uint8_t value2 = parser->buffer[parser->position++];
      // Value 1 is this partition around the first byte, which is assigned
      // to value2 here.
      if (value2 >= 40)
      {
        if (value2 < 80)
        {
          value1 = 1;
          value2 = value2 - 40;
        }
        else
        {
          value1 = 2;
          value2 = value2 - 80;
        }
      }
      // Add these to the result
      janet_array_push(array, janet_wrap_number(value1));
      janet_array_push(array, janet_wrap_number(value2));
      // All further numbers are base127 encoded
      // They could technically be bignums, but there's no reasonable
      // use case out there for them to be large.
      while (parser->position < end_position)
      {
        uint64_t oid_part;
        ret = decode_base127_as_u64(parser, &oid_part);
        if (ret != 0)
        {
          goto end;
        }
        janet_array_push(array, janet_wrap_number(oid_part));
      }
      if (parser->position > end_position)
      {
        // The base 127 encoded number was too powerful (overflowed)
        ret = JANETLS_ERR_ASN1_OBJECT_IDENTIFIER_INVALID_LENGTH;
        goto end;
      }
      value = janet_wrap_tuple(janet_tuple_n(array->data, array->count));
      type_keyword = "object-identifier";
      break;
    }
    case UTF8_STRING:
    {
      value = janet_wrap_string(janet_string((parser->buffer) + (tag.value_position), tag.value_length));
      parser->position += tag.value_length;
      // TODO validation
      type_keyword = "utf8-string";
      break;
    }
    case SEQUENCE:
    {
      type_keyword = "sequence";
      break;
    }
    case SET:
    {
      type_keyword = "set";
      break;
    }
    case PRINTABLE_STRING:
    {
      value = janet_wrap_string(janet_string((parser->buffer) + (tag.value_position), tag.value_length));
      parser->position += tag.value_length;
      // TODO validation
      type_keyword = "printable-string";
      break;
    }
    case TELETEX_STRING:
    {
      value = janet_wrap_string(janet_string((parser->buffer) + (tag.value_position), tag.value_length));
      parser->position += tag.value_length;
      // TODO validation
      type_keyword = "teletext-string";
      break;
    }
    case IA5_ASCII_STRING:
    {
      value = janet_wrap_string(janet_string((parser->buffer) + (tag.value_position), tag.value_length));
      parser->position += tag.value_length;
      // TODO validation
      type_keyword = "ia5-string";
      break;
    }
    case UTC_TIME:
    {
      value = janet_wrap_string(janet_string((parser->buffer) + (tag.value_position), tag.value_length));
      parser->position += tag.value_length;
      // TODO validation
      type_keyword = "utc-time";
      break;
    }
    case GENERALIZED_TIME:
    {
      value = janet_wrap_string(janet_string((parser->buffer) + (tag.value_position), tag.value_length));
      parser->position += tag.value_length;
      // TODO validation
      type_keyword = "generalized-time";
      break;
    }
    case UNIVERSAL_STRINGS:
    {
      value = janet_wrap_string(janet_string((parser->buffer) + (tag.value_position), tag.value_length));
      parser->position += tag.value_length;
      // TODO validation
      type_keyword = "universal-strings";
      break;
    }
    case BITMAP_STRING:
    {
      value = janet_wrap_string(janet_string((parser->buffer) + (tag.value_position), tag.value_length));
      parser->position += tag.value_length;
      // TODO validation
      type_keyword ="bitmap-string";
      break;
    }
    default:
    {
      // Nothing
      break;
    }
  }

  if (tag.constructed)
  {
    JanetTuple sub_value;
    ret = decode_asn1_construction(parser, &sub_value);
    if (ret != 0) goto end;
    value = janet_wrap_tuple(sub_value);
  }

  if (sub_value)
  {
    // A sub value is POSSIBLE. Not Guaranteed.
    // When we try to decode an ASN.1 document, it may fail!
    // When we fail, we should not fail this document.
    size_t old_thread_position = thread_position;
    size_t old_position = parser->position;
    size_t old_length = parser->length;

    parser->position = tag.value_position;
    parser->length = tag.value_position + tag.value_length;


    JanetTuple sub_value;
    int sub_ret = decode_asn1_construction(parser, &sub_value);

    if (sub_ret == 0)
    {
      // Decoding succeded!
      value = janet_wrap_tuple(sub_value);
    }

    // Restore position data
    thread_position = old_thread_position;
    parser->position = old_position;
    parser->length = old_length;
  }

  if (tag.asn1_class == CONTEXT_SPECIFIC || tag.asn1_class == APPLICATION || tag.asn1_class == PRIVATE)
  {
    janet_table_put(result, janet_ckeywordv("tag"), janet_wrap_number(tag.tag));
  }

  if (tag.asn1_class == UNIVERSAL)
  {
    janet_table_put(result, janet_ckeywordv("type"), janet_cstringv(type_keyword));
  }
  else
  {
    janet_table_put(result, janet_ckeywordv("type"), janet_cstringv(class_keyword));
  }

  if (janet_checktype(value, JANET_STRING) && (parser->flags & ASN1_BASE64_NON_ASCII))
  {
    JanetStringHead * head = janet_string_head(janet_unwrap_string(value));
    int is_ascii = 1;
    for (int32_t i = 0; i < head->length; i++)
    {
      if (!isprint(head->data[i]))
      {
        is_ascii = 0;
        break;
      }
    }
    if (!is_ascii)
    {
      value = base64_encode(head->data, head->length, parser->base64_variant);
      Janet encoding = janet_wrap_nil();
      switch (parser->base64_variant)
      {
        case STANDARD:
          encoding = janet_cstringv("base64");
          break;
        case URL:
          encoding = janet_cstringv("base64url");
          break;
        default:
          encoding = janet_cstringv("unspecified base64");
          break;
      }
      janet_table_put(result, janet_ckeywordv("encoding"), encoding);
    }
  }

  janet_table_put(result, janet_ckeywordv("value"), value);
  // janet_table_put(result, janet_ckeywordv("position"), janet_wrap_number(tag.tag_position));
  // janet_table_put(result, janet_cstringv("raw-tag"), janet_wrap_number(tag.tag));

  // janet_table_put(result, janet_cstringv("raw-value"), janet_wrap_abstract(gen_byteslice(parser->source, tag.value_position, tag.value_length)));
  // janet_table_put(result, janet_cstringv("raw-tag"), janet_wrap_abstract(gen_byteslice(parser->source, tag.tag_position, tag.value_length)));

  // Everything good? Populate the value.
  *output = janet_table_to_struct(result);
  // Check for corruption in parsing.
  if (parser->position < thread_position)
  {
    // We can't go backwards
    return JANETLS_ERR_ASN1_OTHER;
  }
  // Update the thread's current position
  thread_position = parser->position;
end:
  return ret;
}
