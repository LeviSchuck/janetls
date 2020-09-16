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
#include "janetls-encoding.h"
#include <ctype.h>
#include <inttypes.h>

// #define PRINT_TRACE_EVERYTHING

static int parse_length(asn1_parser * parser, uint64_t * length);
static int parse_header(asn1_parser * parser, asn1_parsed_tag * parsed);

// Decode things
static int decode_base127(JanetByteView bytes, Janet * destination, int * position, janetls_asn1_number_type bignum);
static int decode_base127_as_u64(asn1_parser * parser, uint64_t * external_result);
static int decode_class(uint8_t byte_tag, janetls_asn1_class * result);
static int decode_asn1(asn1_parser * parser, Janet * output);
static int decode_asn1_construction(asn1_parser * parser, Janet * output, size_t length);

// Encode things
static int encode_base127(Janet source, JanetBuffer * buffer);
static int encode_asn1_length(Janet * result, int32_t size);
static int encode_asn1_integer(uint8_t * bytes, int32_t * bytes_used, uint64_t number, int max_bytes);
static int encode_asn1_tag(Janet * result, uint64_t tag, janetls_asn1_class class, int constructed);
static int encode_asn1_tag_universal(Janet * result, janetls_asn1_universal_type type);
static int encode_asn1_oid_numbers(Janet * result, int32_t * size, const Janet * numbers, int32_t count);
static int encode_asn1_oid_string(Janet * result, int32_t * size, JanetByteView oid_string);

// Push values onto an in progress encoded document
static int push_asn1_tag_length_value(JanetArray * array, Janet value);
static int push_asn1_tag_universal(JanetArray * array, janetls_asn1_universal_type type);
static int push_asn1_length(JanetArray * array, int32_t length);
static int push_asn1_construction(JanetArray * array, const Janet * data, int32_t data_count);
static int push_asn1_struct(JanetArray * array, Janet value);
static int push_asn1_value(JanetArray * array, Janet value, janetls_asn1_universal_type type, int bits);

// Misc inspection
static int find_janet_field(Janet * destination, const JanetKV * view, int32_t capacity, const char * key);
static int check_if_oid_list(const Janet * data, int32_t data_count);
static int determine_types(janetls_asn1_class * class, janetls_asn1_universal_type * universal_type, int * constructed, uint64_t tag, Janet dict_type, Janet dict_value);
static int determine_type_by_value(janetls_asn1_universal_type * universal_type, int * constructed, Janet dict_value);
static int count_length_in_array(int32_t * length, JanetArray * array, int32_t start, int32_t end);

static Janet asn1_encode_127(int32_t argc, Janet * argv);
static Janet asn1_decode_127(int32_t argc, Janet * argv);
static Janet asn1_decode(int32_t argc, Janet * argv);
static Janet asn1_encode(int32_t argc, Janet * argv);

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
  {"asn1/decode", asn1_decode, "(janetls/asn1/decode str &opt options)\n\n"
    "Decode a binary ASN.1 value, the entire string will be consumed, so "
    "if there is surrounding data, you must slice it out.\n"
    "options include:\n"
    ":bignum-as-string - this will encode bignumbers as plain strings\n"
    ":base64-non-ascii - for binary data, the values will be base64 encoded\n"
    ":base64-url - when accompanying :base64-non-ascii, will use the url "
    "variant\n"
    ":string-oid - encodes OIDs as strings, instead of number tuples\n"
    ":collapse-single-constructions - When sequences or sets have only one "
    "value, the value is given directly, rather than nested in a tuple.\n"
    ":collapse-guessable-values - Certain values, such as bignumbers, OIDs, "
    "can be emitted as just strings and later classified and encoded back "
    "to the source type.\n"
    ":eager-parse - when a binary value is encountered, like :bit-string and "
    ":octet-string, or in a non-constructed non-universal tag, the parser "
    "will attempt to decode the value as an ASN.1 document. If it fails, "
    "the result is retained as a binary value, prior to encoding as base64\n"
    ":json - This is a shortcut for multiple options: :base64-as-string, "
    ":base64-url, :bignum-as-string, :collapse-single-constructions, "
    ":collapse-guessable-values, and :string-oid. Note that this shortcut "
    "may change between releases."
    },
  {"asn1/encode", asn1_encode, "(janetls/asn1/encode value)\n\n"
    "Encode a structured value into an ASN.1 document, the result is binary."
    "When the value is a string or buffer, the "
    "contents will be inspected. For example, if \"123\" is given, it will "
    "be decoded as a bignumber and encoded as an ASN.1 integer.\n"
    "When it consists of ASN.1's printable character set, :printable-string "
    "will be used.\n"
    "When it conists of ASCII only (not UTF-8), :ia5-string will be used.\n"
    "When it consists of UTF-8, :utf8-string will be used.\n"
    "Otherwise the string will be assigned the type :octet-string.\n"
    "When a tuple or array is found as a value, it will be interpreted as "
    "an ASN.1 sequence.\n"
    "When struct or table is found as a value, the following keys are probed: "
    ":value, :type, :tag, :encoding, :constructed, :bits."
    ":type should be a value within (janetls/asn1/types) or "
    "(janetls/asn1/classes) except for :universal.\n"
    ":tag is to be provided when the :type is not within (janetls/asn1/types) "
    "as a numerical value.\n"
    ":constructed may be provided as true when the non universal "
    ":type is used. This essentially marks the ASN.1 tag bit and the value "
    "is a nested ASN.1 document.\n"
    ":bits is used on :bit-string values to account for how many unused bits "
    "are in the value at the end. In general, this should only need to be set "
    "if the value is not a multiple of 8 bits."
    ":encoding may be :base64, :base64-url, or :hex. When specified the "
    ":value must be a string and in that format. It will be decoded prior to "
    "insertion into the ASN.1 document.\n"
    ":value is encoded with all the other values described above in account, "
    "if type information is missing then the inspection method described first "
    "is used.\n"
    "When the :type happens to be :bit-string or :object-string and a "
    "structured :value is given, it will be encoded like constructed "
    "non-universal types."
    },
  {"asn1/classes", janetls_search_asn1_class_set, "(janetls/asn1/classes)\n\n"
    "Enumerates ASN.1 classes, besides :universal, the others "
    "should be used as the :type value with an accompanying :tag to identify"
    "the value to the application."
    },
  {"asn1/types", janetls_search_asn1_universal_type_set, "(janetls/asn1/types)\n\n"
    "Enumerates the types this library understands."
    },
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
  janet_arity(argc, 1, 10);
  if (!janet_is_byte_typed(argv[0]))
  {
    janet_panicf("Expected string or buffer, but got %p", argv[0]);
  }
  uint64_t flags = 0;
  janetls_encoding_base64_variant base64_variant = janetls_encoding_base64_variant_standard;

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
      flags |= ASN1_FLAG_BASE64_NON_ASCII;
    }
    else if (janet_cstrcmp(keyword, "base64-url") == 0)
    {
      base64_variant = janetls_encoding_base64_variant_url;
    }
    else if (janet_cstrcmp(keyword, "string-oid") == 0)
    {
      flags |= ASN1_FLAG_STRING_OID;
    }
    else if (janet_cstrcmp(keyword, "collapse-single-constructions") == 0)
    {
      flags |= ASN1_FLAG_COLLAPSE_SINGLE_CONSTRUCTIONS;
    }
    else if (janet_cstrcmp(keyword, "collapse-guessable-values") == 0)
    {
      flags |= ASN1_FLAG_COLLAPSE_GUESSABLE_VALUES;
    }
    else if (janet_cstrcmp(keyword, "json") == 0)
    {
      flags |= ASN1_FLAG_BASE64_NON_ASCII
        | ASN1_FLAG_BIGNUM_AS_STRING
        | ASN1_FLAG_STRING_OID
        | ASN1_FLAG_COLLAPSE_SINGLE_CONSTRUCTIONS
        | ASN1_FLAG_COLLAPSE_GUESSABLE_VALUES;
      base64_variant = janetls_encoding_base64_variant_url;
    }
    else
    {
      janet_panicf("Unexpected flag %p", keyword);
    }
  }

  Janet result = janet_wrap_nil();
  check_result(janetls_asn1_decode(&result, argv[0], flags, base64_variant));
  return result;
}

static Janet asn1_encode(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  Janet result = janet_wrap_nil();
  check_result(janetls_asn1_encode(&result, argv[0]));
  return result;
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
  janetls_asn1_number_type type = janetls_asn1_number_type_bignum;
  if (argc > 1)
  {
    // TODO search list replace
    JanetKeyword keyword = janet_getkeyword(argv, 1);
    if (janet_cstrcmp(keyword, "bignum") == 0)
    {
      type = janetls_asn1_number_type_bignum;
    }
    else if (janet_cstrcmp(keyword, "number") == 0)
    {
      type = janetls_asn1_number_type_number;
    }
    else if (janet_cstrcmp(keyword, "u64") == 0)
    {
      type = janetls_asn1_number_type_u64;
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

// int decode_base127(const uint8_t * buffer, int buffer_length, janetls_bignum_object * destination, int * position)
#define MAX_BITS (sizeof(uint64_t) * 8)
static int decode_base127(JanetByteView bytes, Janet * wrapped_destination, int * position, janetls_asn1_number_type type)
{
  int ret = 0;
  if (type == janetls_asn1_number_type_bignum)
  {
    janetls_bignum_object * destination = janetls_new_bignum();
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
    parser.base64_variant = janetls_encoding_base64_variant_standard;
    parser.flags = 0;
    uint64_t result;
    ret = decode_base127_as_u64(&parser, &result);
    *position = parser.position;
    if (ret == 0)
    {
      if (type == janetls_asn1_number_type_number)
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

static int decode_base127_as_u64(asn1_parser * parser, uint64_t * external_result)
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

static int encode_base127(Janet wrapped_source, JanetBuffer * buffer)
{
  // For now this only supports bignumbers.
  janetls_bignum_object * source = janet_unwrap_abstract(unknown_to_bignum_opt(wrapped_source, 0, 10));
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

static int parse_header(asn1_parser * parser, asn1_parsed_tag * parsed)
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
  janetls_asn1_class class;
  janetls_asn1_universal_type universal_type;
  const uint8_t * value_start;
  size_t value_length;

  if (base_tag == 0x1F)
  {
    ret = decode_base127_as_u64(parser, &tag);
    if (ret != 0) goto end;
  }

  if ((base_tag >= janetls_asn1_universal_type_boolean && base_tag <= janetls_asn1_universal_type_time)
    || (base_tag >= janetls_asn1_universal_type_sequence && base_tag <= janetls_asn1_universal_type_relative_oid_iri)
    )
  {
    universal_type = base_tag;
  }
  else
  {
    // it isn't, but the value is 0 and this is how I'm marking that it isn't universal.
    universal_type = janetls_asn1_universal_type_end_of_content;
  }

  ret = decode_class(tag_byte, &class);
  if (ret != 0) goto end;

  if (class != janetls_asn1_class_universal)
  {
    universal_type = janetls_asn1_universal_type_end_of_content;
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

static int decode_class(uint8_t byte_tag, janetls_asn1_class * result)
{
  int ret = 0;
  switch (byte_tag >> 6)
  {
    case 0:
      *result = janetls_asn1_class_universal;
      break;
    case 1:
      *result = janetls_asn1_class_application;
      break;
    case 2:
      *result = janetls_asn1_class_context_specific;
      break;
    case 3:
      *result = janetls_asn1_class_private;
      break;
    default:
      ret = JANETLS_ERR_ASN1_INVALID_ASN1_CLASS;
  }
  return ret;
}

static int parse_length(asn1_parser * parser, uint64_t * length)
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


static int decode_asn1_construction(asn1_parser * parser, Janet * output, size_t length)
{
  JanetArray * array = janet_array(10);
  int ret = 0;
  int count = 0;
  size_t end_position = parser->position + length;
  while (parser->position < end_position)
  {
    Janet result = janet_wrap_nil();
    ret = decode_asn1(parser, &result);
    if (ret != 0) goto end;
    janet_array_push(array, result);
    count++;
  }

  if (count == 0)
  {
    ret = JANETLS_ERR_ASN1_EMPTY_INPUT;
    goto end;
  }

  if ((parser->flags & ASN1_FLAG_COLLAPSE_SINGLE_CONSTRUCTIONS) && count == 1)
  {
    *output = array->data[0];
  }
  else
  {
    *output = janet_wrap_tuple(janet_tuple_n(array->data, array->count));
  }

end:
  return ret;
}

static int decode_asn1(asn1_parser * parser, Janet * output)
{
  asn1_parsed_tag tag;
  int ret = parse_header(parser, &tag);
  if (ret != 0) goto end;

  // Arbitrary choice of 8 for now.
  JanetTable * result = janet_table(8);
  Janet value = janet_wrap_nil();
  uint8_t sub_value = tag.constructed;

  const char * class_keyword = "invalid";
  switch (tag.asn1_class)
  {
    case janetls_asn1_class_universal:
      class_keyword = "universal";
      break;
    case janetls_asn1_class_context_specific:
      class_keyword = "context-specific";
      break;
    case janetls_asn1_class_application:
      class_keyword = "application";
      break;
    case janetls_asn1_class_private:
      class_keyword = "private";
      break;
  }

  const char * type_keyword = janetls_search_asn1_universal_type_text(tag.asn1_universal_type);

  if (type_keyword == NULL)
  {
    type_keyword = "not-universal";
  }

  int guessable = 0;

  #define INCLUDE_RAW_VALUE do { \
    value = janet_wrap_string(janet_string((parser->buffer) + (tag.value_position), tag.value_length)); \
    parser->position += tag.value_length; \
    } while(0)
  switch (tag.asn1_universal_type)
  {
    case janetls_asn1_universal_type_boolean:
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
    case janetls_asn1_universal_type_integer:
    {
      janetls_bignum_object * bignum = janetls_new_bignum();
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
        retcheck(janetls_bignum_to_digits(&value, janet_wrap_abstract(bignum)));
      }
      else
      {
        value = janet_wrap_abstract(bignum);
      }
      guessable = 1;
      parser->position += tag.value_length;
      type_keyword = "integer";
      break;
    }
    case janetls_asn1_universal_type_bit_string:
    {
      if (tag.value_length == 0)
      {
        value = janet_cstringv("");
        janet_table_put(result, janet_ckeywordv("bits"), janet_wrap_number(0));
      }
      else if (tag.value_length > 1)
      {
        // all these plusses and minus ones are to account for the byte
        // which is part of thr value tomdescribe unused bits
        // but is techniclaly not part of the value in the decoded
        // structure,
        uint64_t bits = ((tag.value_length - 1) * 8) - parser->buffer[tag.value_position];
        value = janet_wrap_string(janet_string((parser->buffer) + (tag.value_position) + 1, tag.value_length - 1));
        janet_table_put(result, janet_ckeywordv("bits"), janet_wrap_number(bits));
        parser->position += tag.value_length;
      }
      else
      {
        ret = JANETLS_ERR_ASN1_INVALID_BIT_STRING_LENGTH;
        goto end;
      }
      type_keyword = "bit-string";
      if (parser->flags & ASN1_FLAG_EAGER_PARSE)
      {
        sub_value = 1;
      }
      break;
    }
    case janetls_asn1_universal_type_octet_string:
    {
      type_keyword = "octet-string";

      if (parser->flags & ASN1_FLAG_EAGER_PARSE)
      {
        sub_value = 1;
      }

      INCLUDE_RAW_VALUE;
      break;
    }
    case janetls_asn1_universal_type_null:
    {
      value = janet_wrap_nil();
      parser->position += tag.value_length; // Technically should be zero..
      // but if it isn't then we'll skip it anyway.
      type_keyword = "null";
      guessable = 1;
      break;
    }
    case janetls_asn1_universal_type_object_identifier:
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

      if (parser->flags & ASN1_FLAG_STRING_OID)
      {
        // 32 is 1.5x what I see normally for OIDs, so we shouldn't have
        // any reallocation.
        JanetBuffer * buffer = janet_buffer(32);
        int s_ret = 0;
        // 32 is beyond the size of a single unsigned 64 bit number in base 10
        // can be which is 18446744073709551615 (20 digits)
        char digit_buffer[32];
        s_ret = sprintf(digit_buffer, "%u.%u", value1, value2);
        if (s_ret < 0)
        {
          #ifdef PRINT_TRACE_EVERYTHING
          janet_eprintf("The numbers could not be encoded for an OID string\n");
          #endif
          ret = JANETLS_ERR_ASN1_OTHER;
          goto end;
        }
        // sprintf adds \0 to the end of the digit_buffer
        // making it a valid c string for use here.
        janet_buffer_push_cstring(buffer, digit_buffer);
        // Begin the rest of them.
        // We're guaranteed to have a prefix of numbers, so every following one
        // will have a '.' delimeter before appending to our output buffer.
        while (parser->position < end_position)
        {
          uint64_t oid_part;
          ret = decode_base127_as_u64(parser, &oid_part);
          if (ret != 0)
          {
            goto end;
          }
          // PRIu64 comes from inttypes.h, it is a macro that
          // specifies the correct formatting for uint64_t
          // This apparently differs on windows.
          s_ret = sprintf(digit_buffer, ".%"PRIu64, oid_part);
          if (s_ret < 0)
          {
            #ifdef PRINT_TRACE_EVERYTHING
            janet_eprintf("A number in the OID string could not be encoded\n");
            #endif
            ret = JANETLS_ERR_ASN1_OTHER;
            goto end;
          }
          janet_buffer_push_cstring(buffer, digit_buffer);
        }
        value = janet_wrap_string(janet_string(buffer->data, buffer->count));
        guessable = 1;
      }
      else
      {
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
        value = janet_wrap_tuple(janet_tuple_n(array->data, array->count));
        guessable = 1;
      }
      if (parser->position > end_position)
      {
        // The base 127 encoded number was too powerful (overflowed)
        ret = JANETLS_ERR_ASN1_OBJECT_IDENTIFIER_INVALID_LENGTH;
        goto end;
      }
      type_keyword = "object-identifier";
      break;
    }
    case janetls_asn1_universal_type_utf8_string:
    {
      type_keyword = "utf8-string";
      INCLUDE_RAW_VALUE;
      break;
    }
    case janetls_asn1_universal_type_sequence:
    {
      type_keyword = "sequence";
      sub_value = 1;
      break;
    }
    case janetls_asn1_universal_type_set:
    {
      type_keyword = "set";
      sub_value = 1;
      break;
    }
    case janetls_asn1_universal_type_printable_string:
    {
      type_keyword = "printable-string";
      INCLUDE_RAW_VALUE;
      break;
    }
    case janetls_asn1_universal_type_teletext_string:
    {
      type_keyword = "teletext-string";
      INCLUDE_RAW_VALUE;
      break;
    }
    case janetls_asn1_universal_type_ia5_string:
    {
      type_keyword = "ia5-string";
      INCLUDE_RAW_VALUE;
      break;
    }
    case janetls_asn1_universal_type_utc_time:
    {
      type_keyword = "utc-time";
      INCLUDE_RAW_VALUE;
      break;
    }
    case janetls_asn1_universal_type_generalized_time:
    {
      type_keyword = "generalized-time";
      INCLUDE_RAW_VALUE;
      break;
    }
    case janetls_asn1_universal_type_universal_string:
    {
      type_keyword = "universal-string";
      INCLUDE_RAW_VALUE;
      break;
    }
    case janetls_asn1_universal_type_bitmap_string:
    {
      type_keyword = "bitmap-string";
      INCLUDE_RAW_VALUE;
      break;
    }
    default:
    {
      type_keyword = "unknown";
      // Include the value verbatim as a byte string
      INCLUDE_RAW_VALUE;
      break;
    }
  }

  if (tag.constructed)
  {
    Janet nested_value;
    // Rewind to the tag value start position to continue decoding
    parser->position = tag.value_position;
    ret = decode_asn1_construction(parser, &nested_value, tag.value_length);
    // Fast forward to end of content
    parser->position = tag.value_position + tag.value_length;
    thread_position = parser->position;
    retcheck(ret);
    value = nested_value;
    sub_value = 0;
    if (tag.asn1_class != janetls_asn1_class_universal)
    {
      // This is only necessary on non universal types
      janet_table_put(result, janet_ckeywordv("constructed"), janet_wrap_boolean(1));
    }
  }

  if (sub_value)
  {
    // A sub value is POSSIBLE. Not Guaranteed.
    // When we try to decode an ASN.1 document, it may fail!
    // When we fail, we should not fail this document.
    size_t old_thread_position = thread_position;
    size_t old_length = parser->length;

    parser->position = tag.value_position;
    parser->length = tag.value_position + tag.value_length;


    Janet nested_value;
    int sub_ret = decode_asn1_construction(parser, &nested_value, tag.value_length);

    if (sub_ret == 0)
    {
      // Decoding succeded!
      value = nested_value;
    }

    // Restore position data
    thread_position = old_thread_position;
    parser->position = tag.value_position + tag.value_length;
    parser->length = old_length;
  }

  if (tag.asn1_class == janetls_asn1_class_context_specific
    || tag.asn1_class == janetls_asn1_class_application
    || tag.asn1_class == janetls_asn1_class_private
    )
  {
    janet_table_put(result, janet_ckeywordv("tag"), janet_wrap_number(tag.tag));
  }

  if (tag.asn1_class == janetls_asn1_class_universal)
  {
    janet_table_put(result, janet_ckeywordv("type"), janet_ckeywordv(type_keyword));
  }
  else
  {
    janet_table_put(result, janet_ckeywordv("type"), janet_ckeywordv(class_keyword));
  }

  if (tag.asn1_class == janetls_asn1_class_universal
    && tag.asn1_universal_type == janetls_asn1_universal_type_sequence
    && janet_checktype(value, JANET_TUPLE)
    )
  {
    const Janet * data;
    int32_t tuple_size = 0;
    if (janet_indexed_view(value, &data, &tuple_size))
    {
      if (tuple_size > 1)
      {
        guessable = 1;
      }
      else if (!(parser->flags & ASN1_FLAG_COLLAPSE_SINGLE_CONSTRUCTIONS))
      {
        // Can't guess on collapsed values.
        guessable = 1;
      }
    }
  }

  if (janet_checktype(value, JANET_STRING) && (parser->flags & ASN1_FLAG_BASE64_NON_ASCII))
  {
    JanetStringHead * head = janet_string_head(janet_unwrap_string(value));
    if (!is_ascii_string(head->data, head->length))
    {
      value = base64_encode(head->data, head->length, parser->base64_variant);
      Janet encoding = janet_wrap_nil();
      switch (parser->base64_variant)
      {
        case janetls_encoding_base64_variant_standard:
          encoding = janet_ckeywordv("base64");
          break;
        case janetls_encoding_base64_variant_url:
          encoding = janet_ckeywordv("base64-url");
          break;
        default:
          encoding = janet_cstringv("unspecified base64");
          break;
      }
      janet_table_put(result, janet_ckeywordv("encoding"), encoding);
      guessable = 0;
    }
  }

  janet_table_put(result, janet_ckeywordv("value"), value);
  // janet_table_put(result, janet_ckeywordv("position"), janet_wrap_number(tag.tag_position));
  // janet_table_put(result, janet_cstringv("raw-tag"), janet_wrap_number(tag.tag));

  // janet_table_put(result, janet_cstringv("raw-value"), janet_wrap_abstract(gen_byteslice(parser->source, tag.value_position, tag.value_length)));
  // janet_table_put(result, janet_cstringv("raw-tag"), janet_wrap_abstract(gen_byteslice(parser->source, tag.tag_position, tag.value_length)));

  if (guessable && (parser->flags & ASN1_FLAG_COLLAPSE_GUESSABLE_VALUES))
  {
    *output = value;
  }
  else
  {
    *output = janet_wrap_struct(janet_table_to_struct(result));
  }

  // Check for corruption in parsing.
  if (parser->position < thread_position)
  {
    #ifdef PRINT_TRACE_EVERYTHING
    janet_eprintf("The thread position appears to have gone backwards\n");
    #endif
    // We can't go backwards
    return JANETLS_ERR_ASN1_OTHER;
  }
  // Update the thread's current position
  thread_position = parser->position;
end:
  return ret;
}

typedef enum value_encoded {
  VALUE_ENCODED_BINARY,
  VALUE_ENCODED_BASE64,
  VALUE_ENCODED_BASE64URL,
  VALUE_ENCODED_HEX,
} value_encoded;

static int encode_asn1_integer(uint8_t * bytes, int32_t * bytes_used, uint64_t number, int max_bytes)
{
  int32_t pushed_bytes = 0;
  int byte;
  for (byte = 0; byte < max_bytes; byte++)
  {
    bytes[byte] = 0xff & number;
    number = number >> 8;
    pushed_bytes++;
    if (number <= 0)
    {
      break;
    }
  }
  if (number > 0)
  {
    return JANETLS_ERR_ASN1_NUMBER_OVERFLOW;
  }

  // Now reverse the bytes, since they were pushed opposite of big endian order.
  uint8_t * low = bytes;
  uint8_t * high = bytes + pushed_bytes - 1;
  uint8_t swap;
  while (low < high)
  {
    swap = *low;
    *low++ = *high;
    *high-- = swap;
  }
  *bytes_used = pushed_bytes;
  return 0;
}

static int encode_asn1_length(Janet * result, int32_t size)
{
  int ret = 0;
  if (size < 128)
  {
    uint8_t small_size = size;
    #ifdef PRINT_TRACE_EVERYTHING
    janet_eprintf("Encoding length of 0x%0x\n", size);
    #endif
    *result = janet_wrap_string(janet_string(&small_size, 1));
  }
  else
  {
    // DER lengths too have lengths when the value is > 128.
    // https://en.wikipedia.org/wiki/X.690#Length_octets
    // The first byte will be the length here.
    uint8_t bytes[5];
    int32_t length_bytes = 0;

    retcheck(encode_asn1_integer(bytes + 1, &length_bytes, size, 4));

    // The length length will be 0x81-0x84
    // But it is highly unlikely that it would be more than 0x82.
    bytes[0] = 0x80 | (length_bytes & 0x7f);

    *result = janet_wrap_string(janet_string(bytes, length_bytes + 1));
    return 0;
  }

end:
  return ret;
}


static int push_asn1_byteview(JanetArray * array, JanetByteView value)
{
  Janet length = janet_wrap_nil();
  int ret = 0;
  retcheck(encode_asn1_length(&length, value.len));
  janet_array_push(array, length);
  janet_array_push(array, janet_wrap_string(janet_string(value.bytes, value.len)));
end:
  return ret;
}

static int encode_asn1_oid_string(Janet * result, int32_t * size, JanetByteView oid_string)
{
  int value1;
  int value2;
  int scan_result = sscanf((const char *)oid_string.bytes, "%d.%d.", &value1, &value2);
  if ((scan_result != 2)
    || (value1 < 0 || value1 > 2)
    || (value2 < 0)
    || (value1 == 2 && value2 > 175)
    || (value1 < 2 && value2 > 39)
    )
  {
    return JANETLS_ERR_ASN1_INVALID_OBJECT_IDENTIFIER;
  }
  // size is arbitrary.
  JanetBuffer * buffer = janet_buffer(16);

  // Push the first byte (which handles the first 2 values)
  int ret = 0;
  retcheck(encode_base127(janet_wrap_number((value1 * 40) + value2), buffer));

  // Now for the rest of the numbers..
  // Technically an OID part is an arbitrary integer
  // But there are no logical cases for it exceeding a 64 bit unsigned int
  // let alone 32 bit.
  uint64_t oid_part = 0;
  int dot_count = 0;
  int digit_count = 0;
  for (int32_t i = 0; i < oid_string.len; i++)
  {
    uint8_t byte = oid_string.bytes[i];
    if (byte == '.')
    {
      if (++dot_count >= 3)
      {
        retcheck(encode_base127(janet_wrap_number(oid_part), buffer));
      }
      oid_part = 0;
      digit_count = 0;
    }
    else if (byte >= '0' && byte <= '9')
    {
      digit_count++;
      oid_part = (oid_part * 10) + (byte - '0');
    }
  }
  if (dot_count >= 3 && digit_count > 0)
  {
    retcheck(encode_base127(janet_wrap_number(oid_part), buffer));
  }

  *result = janet_wrap_buffer(buffer);
  *size = buffer->count;
end:
  return ret;
}

static int encode_asn1_oid_numbers(Janet * result, int32_t * size, const Janet * numbers, int32_t count)
{
  int ret = 0;
  if (count < 2)
  {
    ret = JANETLS_ERR_ASN1_INVALID_OBJECT_IDENTIFIER;
    goto end;
  }
  // the number in base 127
  int value1 = janet_unwrap_number(*numbers++);
  int value2 = janet_unwrap_number(*numbers++);
  if ((value1 < 0 || value1 > 2)
    || (value2 < 0)
    || (value1 == 2 && value2 > 175)
    || (value1 < 2 && value2 > 39)
    )
  {
    ret = JANETLS_ERR_ASN1_INVALID_OBJECT_IDENTIFIER;
    goto end;
  }
  // size is arbitrary.
  JanetBuffer * buffer = janet_buffer(16);

  // Push the first byte (which handles the first 2 values)
  retcheck(encode_base127(janet_wrap_number((value1 * 40) + value2), buffer));

  // Now for the rest of the numbers..
  // Subtract 2 because we handled value1/2 above.
  const Janet * end = numbers + count - 2;
  while (numbers < end)
  {
    #ifdef PRINT_TRACE_EVERYTHING
    janet_eprintf("Encoding to base 127 %p\n", *numbers);
    #endif
    retcheck(encode_base127(*numbers++, buffer));
  }

  *result = janet_wrap_buffer(buffer);
  *size = buffer->count;
end:
  return ret;
}

static int push_asn1_tag_length_value(JanetArray * array, Janet value)
{
  int ret = 0;
  int32_t size = 0;
  JanetBuffer * buffer = NULL;
  janetls_bignum_object * bignum  = NULL;
  #ifdef PRINT_TRACE_EVERYTHING
  janet_eprintf("Push tag-length-value of %p\n", value);
  #endif
  // https://en.wikipedia.org/wiki/Distinguished_Encoding_Rules
  // DER type tag numbers
  if (janet_is_byte_typed(value))
  {
    // We're working in the world of the ambiguous.
    // It's just a string! Guess what it is?
    JanetByteView bytes = janet_to_bytes(value);
    string_type string_type = classify_string(bytes.bytes, bytes.len);
    if (string_type == STRING_IS_OID)
    {
      // parse in base 10, when a dot is encountered, or end, then commit
      Janet asn1_value = janet_wrap_nil();
      int32_t length = 0;
      retcheck(encode_asn1_oid_string(&asn1_value, &length, bytes));
      retcheck(push_asn1_tag_universal(array, janetls_asn1_universal_type_object_identifier));
      retcheck(push_asn1_length(array, length));
      janet_array_push(array, asn1_value);
    }
    else if (string_type == STRING_IS_DIGITS)
    {
      // Turn into bignumber, output in little endian.
      bignum = janetls_new_bignum();
      // Read in the digit string into mbedtls bignum
      retcheck(mbedtls_mpi_read_string(&bignum->mpi, 10, (const char *)bytes.bytes));
      goto push_bignum;
    }
    else if (string_type == STRING_IS_PRINTABLE)
    {
      retcheck(push_asn1_tag_universal(array, janetls_asn1_universal_type_printable_string));
      retcheck(push_asn1_byteview(array, bytes));
    }
    else if (string_type == STRING_IS_ASCII)
    {
      retcheck(push_asn1_tag_universal(array, janetls_asn1_universal_type_ia5_string));
      retcheck(push_asn1_byteview(array, bytes));
    }
    else if (string_type == STRING_IS_UTF8)
    {
      retcheck(push_asn1_tag_universal(array, janetls_asn1_universal_type_utf8_string));
      retcheck(push_asn1_byteview(array, bytes));
    }
    else
    {
      retcheck(push_asn1_tag_universal(array, janetls_asn1_universal_type_octet_string));
      retcheck(push_asn1_byteview(array, bytes));
    }
  }
  else if (janet_checktype(value, JANET_NUMBER))
  {
    double number = janet_unwrap_number(value);
    if (janet_checkint64range(number))
    {
      uint64_t integer = number;
      uint8_t bytes[8];
      int32_t bytes_used;

      retcheck(encode_asn1_integer(bytes, &bytes_used, integer, 8));
      retcheck(push_asn1_tag_universal(array, janetls_asn1_universal_type_integer));
      retcheck(push_asn1_length(array, bytes_used));
      janet_array_push(array, janet_wrap_string(janet_string(bytes, bytes_used)));
    }
    else
    {
      // technically the REAL (float) is an option
      // but it's not really a priority.
      ret = JANETLS_ERR_ASN1_NUMBER_WAS_FRACTIONAL;
      goto end;
    }
  }
  else if (janet_checktype(value, JANET_TABLE) || janet_checktype(value, JANET_STRUCT))
  {
    retcheck(push_asn1_struct(array, value));
  }
  else if (janet_checktype(value, JANET_TUPLE) || janet_checktype(value, JANET_ARRAY))
  {
    const Janet * data = NULL;
    int32_t data_count = 0;
    if (!janet_indexed_view(value, &data, &data_count))
    {
      #ifdef PRINT_TRACE_EVERYTHING
      janet_eprintf("The tuple could not be used as an indexed view\n");
      #endif
      ret = JANETLS_ERR_ASN1_OTHER;
      goto end;
    }
    if (check_if_oid_list(data, data_count))
    {
      Janet result = janet_wrap_nil();
      int32_t length = 0;
      retcheck(encode_asn1_oid_numbers(&result, &length, data, data_count));
      retcheck(push_asn1_tag_universal(array, janetls_asn1_universal_type_integer));
      retcheck(push_asn1_length(array, length));
      janet_array_push(array, result);
    }
    else
    {
      retcheck(push_asn1_tag_universal(array, janetls_asn1_universal_type_sequence));
      // TODO structure this length wrapping stuff
      int32_t length_position = array->count;
      janet_array_push(array, janet_wrap_nil());
      int32_t start_position = length_position + 1;
      int32_t length = 0;
      // Write out the value (this may involve multiple pushes if it is constructed.)
      retcheck(push_asn1_construction(array, data, data_count));
      int32_t end_position = array->count;
      retcheck(count_length_in_array(&length, array, start_position, end_position));
      // Encode and replace the placeholder.
      #ifdef PRINT_TRACE_EVERYTHING
      janet_eprintf("replacing value %p in array at position %d\n", array->data[length_position], length_position);
      #endif
      retcheck(encode_asn1_length(array->data + length_position, length));
      #ifdef PRINT_TRACE_EVERYTHING
      janet_eprintf("Length was %d\n", length);
      #endif
    }
  }
  else if (janet_checktype(value, JANET_ABSTRACT))
  {
    void * abstract_value = janet_unwrap_abstract(value);
    JanetAbstractHead * head = janet_abstract_head(abstract_value);
    if (head->type == janetls_bignum_object_type())
    {
      bignum = abstract_value;
push_bignum:
      // Get how many bytes it will take to write this in big endian
      size = (int32_t)mbedtls_mpi_size(&bignum->mpi);
      if (size <= 0)
      {
        uint8_t zero = 0;
        // Zero needs at least one byte.
        retcheck(push_asn1_tag_universal(array, janetls_asn1_universal_type_integer));
        retcheck(push_asn1_length(array, 1));
        janet_array_push(array, janet_wrap_string(janet_string(&zero, 1)));
      }
      else
      {
        buffer = janet_buffer(size);
        // Write out the integer
        retcheck(mbedtls_mpi_write_binary(&bignum->mpi, buffer->data, size));
        buffer->count += size;

        // Now that the value is intact, prepare the other details
        retcheck(push_asn1_tag_universal(array, janetls_asn1_universal_type_integer));

        uint8_t first_byte = buffer->data[0];
        int prepend_byte = 0;
        if (first_byte & 0x80)
        {
          // ASN.1 expects two's compliment, so we prepend an extra empty byte.
          size++;
          prepend_byte = 1;
        }

        retcheck(push_asn1_length(array, size));
        if (prepend_byte)
        {
          uint8_t zero = 0;
          janet_array_push(array, janet_wrap_string(janet_string(&zero, 1)));
        }
        janet_array_push(array, janet_wrap_buffer(buffer));
      }
    }
    else
    {
      ret = JANETLS_ERR_ASN1_INVALID_VALUE_TYPE;
      goto end;
    }
  }
  else
  {
    ret = JANETLS_ERR_ASN1_UNSUPPORTED_TYPE;
    goto end;
  }

end:
  return ret;
}

static int encode_asn1_tag(Janet * result, uint64_t tag, janetls_asn1_class class, int constructed)
{
  int ret = 0;
  uint8_t first = (class & 0x3) << 6;
  if (constructed)
  {
    first |= 0x20;
  }
  if (tag <= 30)
  {
    first |= (tag & 0x1F);
    *result = janet_wrap_string(janet_string(&first, 1));
  }
  else
  {
    first |= 0x1F;
    // I really doubt we'll have tags this size.
    JanetBuffer * buffer = janet_buffer(10);
    janet_buffer_push_u8(buffer, first);
    retcheck(encode_base127(janet_wrap_number(tag), buffer));
    *result = janet_wrap_buffer(buffer);
  }
  #ifdef PRINT_TRACE_EVERYTHING
  janet_eprintf("Pushed tag 0x%0x\n", tag);
  #endif
end:
  return ret;
}

static int encode_asn1_tag_universal(Janet * result, janetls_asn1_universal_type type)
{
  int constructed = 0;

  switch (type)
  {
    case janetls_asn1_universal_type_external:
    case janetls_asn1_universal_type_embedded_pdv:
    case janetls_asn1_universal_type_sequence:
    case janetls_asn1_universal_type_set:
      constructed = 1;
      break;
    default:
      break;
  }

  return encode_asn1_tag(result, type, janetls_asn1_class_universal, constructed);
}


static int push_asn1_tag_universal(JanetArray * array, janetls_asn1_universal_type type)
{
  int ret = 0;
  #ifdef PRINT_TRACE_EVERYTHING
  janet_eprintf("Pushing universal tag 0x%0x\n", type);
  #endif
  Janet asn1_type = janet_wrap_nil();
  retcheck(encode_asn1_tag_universal(&asn1_type, type));
  janet_array_push(array, asn1_type);
end:
  return ret;
}

static int push_asn1_length(JanetArray * array, int32_t length)
{
  int ret = 0;
  #ifdef PRINT_TRACE_EVERYTHING
  janet_eprintf("Pushing length %d\n", length);
  #endif
  Janet asn1_length = janet_wrap_nil();
  retcheck(encode_asn1_length(&asn1_length, length));
  janet_array_push(array, asn1_length);
end:
  return ret;
}

static int push_asn1_construction(JanetArray * array, const Janet * data, int32_t data_count)
{
  int ret = 0;
  #ifdef PRINT_TRACE_EVERYTHING
  janet_eprintf("Push ASN1 construction, with %d values\n", data_count);
  #endif
  for (int i = 0; i < data_count; i++)
  {
    retcheck(push_asn1_tag_length_value(array, data[i]));
  }
end:
  return ret;
}

static int find_janet_field(Janet * destination, const JanetKV * view, int32_t capacity, const char * key)
{
  int ret = 0;
  Janet value = janet_dictionary_get(view, capacity, janet_ckeywordv(key));
  if (janet_checktype(value, JANET_NIL))
  {
    // Try string key too
    // In janet, it seems if a struct or table has an entry with nil as
    // the value, it is not seen as different from the entry missing.
    value = janet_dictionary_get(view, capacity, janet_cstringv(key));
    if (!janet_checktype(value, JANET_NIL))
    {
      *destination = value;
    }
  }
  else
  {
    *destination = value;
  }

  // end:
  return ret;
}

int push_asn1_struct(JanetArray * array, Janet value)
{
  int ret = 0;
  const JanetKV * view;
  int32_t length = 0;
  int32_t capacity = 0;
  if (!janet_dictionary_view(value, &view, &length, &capacity))
  {
    #ifdef PRINT_TRACE_EVERYTHING
    janet_eprintf("The struct could not be viewed like a dictionary\n");
    #endif
    ret = JANETLS_ERR_ASN1_OTHER;
    goto end;
  }

  Janet dict_value = janet_wrap_nil();
  Janet dict_type = janet_wrap_nil();
  Janet dict_tag = janet_wrap_nil();
  Janet dict_encoding = janet_wrap_nil();
  Janet dict_constructed = janet_wrap_boolean(0);
  Janet dict_bits = janet_wrap_number(0);

  retcheck(find_janet_field(&dict_value, view, capacity, "value"));
  retcheck(find_janet_field(&dict_type, view, capacity, "type"));
  retcheck(find_janet_field(&dict_tag, view, capacity, "tag"));
  retcheck(find_janet_field(&dict_encoding, view, capacity, "encoding"));
  retcheck(find_janet_field(&dict_constructed, view, capacity, "constructed"));
  retcheck(find_janet_field(&dict_bits, view, capacity, "bits"));
  #ifdef PRINT_TRACE_EVERYTHING
  janet_eprintf("Encoding %p\n- type: %p, encoding: %p\n", value, dict_type, dict_encoding);
  #endif

  int constructed = 0;
  int bits = 0;
  uint64_t tag = 0;
  value_encoded value_encoded = VALUE_ENCODED_BINARY;
  janetls_asn1_class class = janetls_asn1_class_universal;
  janetls_asn1_universal_type universal_type = janetls_asn1_universal_type_octet_string;

  // Check the tag
  if (janet_checktype(dict_tag, JANET_NIL))
  {
    // Nothing here
  }
  else if (janet_checktype(dict_tag, JANET_NUMBER))
  {
    // Okay, so we gotta encode it specially!
    double tag_number = janet_unwrap_number(dict_tag);
    tag = tag_number;
    if (tag != tag_number)
    {
      // Check that the number isn't fractional
      ret = JANETLS_ERR_ASN1_INVALID_TAG;
      goto end;
    }
  }
  else
  {
    ret = JANETLS_ERR_ASN1_INVALID_TAG;
    goto end;
  }

  if (janet_checktype(dict_constructed, JANET_BOOLEAN))
  {
    constructed = janet_unwrap_boolean(dict_constructed);
  }
  else if (!janet_checktype(dict_constructed, JANET_NIL))
  {
    ret = JANETLS_ERR_ASN1_INVALID_CONSTRUCTED_PARAMETER;
    goto end;
  }
  if (!constructed && (janet_checktype(dict_value, JANET_STRUCT)
    || janet_checktype(dict_value, JANET_TABLE)
    || janet_checktype(dict_value, JANET_ARRAY)
    || janet_checktype(dict_value, JANET_TUPLE)
    ))
  {
    constructed = 1;
  }

  // Check encoding
  if (janet_checktype(dict_encoding, JANET_NIL))
  {
    // Nothing here
  }
  else if (janet_is_byte_typed(dict_encoding))
  {
    JanetByteView bytes = janet_to_bytes(dict_encoding);
    if (janet_byte_cstrcmp_insensitive(bytes, "base64") == 0)
    {
      value_encoded = VALUE_ENCODED_BASE64;
    }
    else if (janet_byte_cstrcmp_insensitive(bytes, "base64-url") == 0)
    {
      value_encoded = VALUE_ENCODED_BASE64URL;
    }
    else if (janet_byte_cstrcmp_insensitive(bytes, "hex") == 0)
    {
      value_encoded = VALUE_ENCODED_HEX;
    }
    else if (janet_byte_cstrcmp_insensitive(bytes, "binary") == 0)
    {
      value_encoded = VALUE_ENCODED_BINARY;
    }
    else
    {
      ret = JANETLS_ERR_ASN1_UNSUPPORTED_ENCODING;
      goto end;
    }

    if (janet_is_byte_typed(dict_value))
    {
      JanetByteView value_bytes = janet_to_bytes(dict_value);
      int variant = 0;
      janetls_encoding_type encoding = janetls_encoding_type_raw;

      // decode the encoded body into binary
      switch (value_encoded)
      {
        case VALUE_ENCODED_BASE64:
        {
          encoding = janetls_encoding_type_base64;
          variant = janetls_encoding_base64_variant_standard;
          break;
        }
        case VALUE_ENCODED_BASE64URL:
        {
          encoding = janetls_encoding_type_base64;
          variant = janetls_encoding_base64_variant_url;
          break;
        }
        case VALUE_ENCODED_HEX:
        {
          encoding = janetls_encoding_type_hex;
          break;
        }
        default:
        {
          // Nothing
          break;
        }
      }

      // No need to replace when it is already in the final form (binary)
      if (value_encoded != VALUE_ENCODED_BINARY)
      {
        // Replace dict_value with the decoded portion
        retcheck(janetls_content_from_encoding(&dict_value, value_bytes.bytes, value_bytes.len, encoding, variant));
      }
    }
    else
    {
      ret = JANETLS_ERR_ASN1_INPUT_CANNOT_BE_DECODED;
      goto end;
    }
  }
  else
  {
    ret = JANETLS_ERR_ASN1_UNSUPPORTED_ENCODING;
    goto end;
  }

  if (janet_checktype(dict_bits, JANET_NIL))
  {
    if (janet_is_byte_typed(dict_value))
    {
      bits = janet_to_bytes(dict_value).len * 8;
    }
  }
  else if (janet_checktype(dict_bits, JANET_NUMBER))
  {
    double bits_number = janet_unwrap_number(dict_bits);;
    bits = bits_number;
    if (bits != bits_number)
    {
      // Check that the number isn't fractional
      ret = JANETLS_ERR_ASN1_INVALID_BITS;
      goto end;
    }
  }
  else
  {
    ret = JANETLS_ERR_ASN1_INVALID_BITS;
    goto end;
  }

  retcheck(determine_types(&class, &universal_type, &constructed, tag, dict_type, dict_value));

  if (class == janetls_asn1_class_universal)
  {
    retcheck(push_asn1_tag_universal(array, universal_type));
  }
  else
  {
    Janet asn1_type = janet_wrap_nil();
    encode_asn1_tag(&asn1_type, tag, class, constructed);
    janet_array_push(array, asn1_type);
  }

  // Push an empty value for the length
  // we will set this after we know the length.
  int32_t length_position = array->count;
  janet_array_push(array, janet_wrap_nil());
  int32_t start_position = length_position + 1;
  // Write out the value (this may involve multiple pushes if it is constructed.)
  retcheck(push_asn1_value(array, dict_value, universal_type, bits));
  int32_t end_position = array->count;
  retcheck(count_length_in_array(&length, array, start_position, end_position));
  // Encode and replace the placeholder.
  #ifdef PRINT_TRACE_EVERYTHING
  janet_eprintf("replacing value %p in array at position %d\n", array->data[length_position], length_position);
  #endif
  retcheck(encode_asn1_length(array->data + length_position, length));
  #ifdef PRINT_TRACE_EVERYTHING
  janet_eprintf("Length was %d\n", length);
  #endif
end:
  return ret;
}

static int check_if_oid_list(const Janet * data, int32_t data_count)
{
  int32_t numbers = 0;
  // Detect if this is a list of numbers. If so, it's an OID.
  for (int32_t i = 0; i < data_count; i++)
  {
    if (janet_checktype(data[i], JANET_NUMBER))
    {
      numbers++;
    }
    else
    {
      break;
    }
  }
  return numbers == data_count;
}

static int determine_types(janetls_asn1_class * class, janetls_asn1_universal_type * universal_type, int * constructed, uint64_t tag, Janet dict_type, Janet dict_value)
{
  int ret = 0;
  // By default everything is bytes..
  *universal_type = janetls_asn1_universal_type_octet_string;
  *class = janetls_asn1_class_universal;

  if (janet_is_byte_typed(dict_type))
  {
    ret = janetls_search_asn1_universal_type(dict_type, universal_type);
    if (ret == 0)
    {
      // Good to continue
    }
    else if (ret == JANETLS_ERR_SEARCH_OPTION_NOT_FOUND)
    {
      // Ah.. so the type can be universal, and can also represent non
      // universal classes.
      // Try those before giving up.
      ret = janetls_search_asn1_class(dict_type, class);
      if (ret == 0)
      {
        #ifdef PRINT_TRACE_EVERYTHING
        janet_eprintf("Parsed class for %p, got %d\n", dict_type, class);
        #endif
        if (*class == janetls_asn1_class_universal)
        {
          ret = JANETLS_ERR_ASN1_INVALID_INPUT_TYPE;
          goto end;
        }

        // So class is now set to something not universal
        // set the universal type to 0 (end of content officially)
        // But we don't really know what the content is yet.
        // The return value is ignored.
        // if it fails, then universal_type remains as octet-string
        // non universal types are gen
        determine_type_by_value(universal_type, constructed, dict_value);
      }
      else
      {
        goto end;
      }
    }
    else if (ret == 0)
    {
      // nothing
    }
    else
    {
      goto end;
    }
  }
  else if ((tag >= janetls_asn1_universal_type_boolean && tag <= janetls_asn1_universal_type_time)
    || (tag >= janetls_asn1_universal_type_sequence && tag <= janetls_asn1_universal_type_relative_oid_iri))
  {
    // The tag value is set above.
    // it is by default 0 which is out of this range.
    *universal_type = tag;
  }
  else if (janet_is_byte_typed(dict_type))
  {
    // If the content is string like, classify it.
    JanetByteView bytes = janet_to_bytes(dict_type);
    string_type string_type = classify_string(bytes.bytes, bytes.len);
    if (string_type == STRING_IS_DIGITS)
    {
      *universal_type = janetls_asn1_universal_type_integer;
    }
    else if (string_type == STRING_IS_OID)
    {
      *universal_type = janetls_asn1_universal_type_object_identifier;
    }
    else if (string_type == STRING_IS_ASCII)
    {
      *universal_type = janetls_asn1_universal_type_ia5_string;
    }
    else if (string_type == STRING_IS_PRINTABLE)
    {
      *universal_type = janetls_asn1_universal_type_printable_string;
    }
    else if (string_type == STRING_IS_UTF8)
    {
      *universal_type = janetls_asn1_universal_type_utf8_string;
    }
    else if (string_type == STRING_IS_OID)
    {
      *universal_type = janetls_asn1_universal_type_octet_string;
    }
    else
    {
      #ifdef PRINT_TRACE_EVERYTHING
      janet_eprintf("The type could not be deduced from a string\n");
      #endif
      ret = JANETLS_ERR_ASN1_OTHER;
      goto end;
    }
  }
  else
  {
    retcheck(determine_type_by_value(universal_type, constructed, dict_value));
  }
end:
  return ret;
}

static int determine_type_by_value(janetls_asn1_universal_type * universal_type, int * constructed, Janet dict_value)
{
  int ret = 0;
  if (janet_checktype(dict_value, JANET_NIL))
  {
    *universal_type = janetls_asn1_universal_type_null;
  }
  else if (janet_checktype(dict_value, JANET_NUMBER))
  {
    *universal_type = janetls_asn1_universal_type_integer;
  }
  else if (janet_checktype(dict_value, JANET_TABLE)
    || janet_checktype(dict_value, JANET_STRUCT)
    || janet_checktype(dict_value, JANET_TUPLE)
    || janet_checktype(dict_value, JANET_ARRAY)
    )
  {
    #ifdef PRINT_TRACE_EVERYTHING
    janet_eprintf("Setting type to sequence and constructed Per the value %p\n", dict_value);
    #endif
    *universal_type = janetls_asn1_universal_type_sequence;
    *constructed = 1;
  }
  else if (*constructed)
  {
    *universal_type = janetls_asn1_universal_type_sequence;
  }
  else if (janet_checktype(dict_value, JANET_ABSTRACT))
  {
    void * abstract_value = janet_unwrap_abstract(dict_value);
    JanetAbstractHead * head = janet_abstract_head(abstract_value);
    if (head->type == janetls_bignum_object_type())
    {
      *universal_type = janetls_asn1_universal_type_integer;
    }
    else
    {
      ret = JANETLS_ERR_ASN1_UNSUPPORTED_TYPE;
      goto end;
    }
  }
  else
  {
    ret = JANETLS_ERR_ASN1_UNSUPPORTED_TYPE;
    goto end;
  }

end:
  return ret;
}

int count_length_in_array(int32_t * length, JanetArray * array, int32_t start, int32_t end)
{
  int ret = 0;
  int32_t bytes = 0;
  for (int32_t i = start; i < end; i++)
  {
    Janet array_value = array->data[i];
    if (janet_is_byte_typed(array_value))
    {
      bytes += janet_to_bytes(array_value).len;
    }
    else
    {
      #ifdef PRINT_TRACE_EVERYTHING
      janet_eprintf("The length of the array could not be counted in bytes, a value is not byte-able: %p\n", array_value);
      #endif
      // Can't measure byte count.
      ret = JANETLS_ERR_ASN1_OTHER;
      goto end;
    }
  }
  *length = bytes;
end:
  return ret;
}

static int push_asn1_value(JanetArray * array, Janet value, janetls_asn1_universal_type type, int bits)
{
  int ret = 0;
  switch (type) {
    case janetls_asn1_universal_type_boolean:
    {
      uint8_t boolean = 0;

      if (janet_checktype(value, JANET_BOOLEAN))
      {
        if (janet_unwrap_boolean(value))
        {
          boolean = 1;
        }
      }
      else
      {
        ret = JANETLS_ERR_INVALID_BOOLEAN_VALUE;
        goto end;
      }

      janet_array_push(array, janet_wrap_string(janet_string(&boolean, 1)));

      break;
    }
    case janetls_asn1_universal_type_integer:
    {
      #ifdef PRINT_TRACE_EVERYTHING
      janet_eprintf("Integer value %p\n", value);
      #endif
      // three cases, a string of digits,
      // and an abstract object of a bignum,
      // or a native janet number.
      // Good news is existing conversions exist!
      Janet bignum_value = janet_wrap_nil();
      retcheck(janetls_bignum_to_bytes(&bignum_value, value));
      #ifdef PRINT_TRACE_EVERYTHING
      janet_eprintf("Bignum value written as %p\n", bignum_value);
      #endif
      JanetByteView bignum_bytes = janet_to_bytes(bignum_value);
      uint8_t zero = 0;
      if (bignum_bytes.len == 0)
      {
        #ifdef PRINT_TRACE_EVERYTHING
        janet_eprintf("Integer appears to be zero, adding zero byte\n", value);
        #endif
        // ASN.1 needs at least one byte for integers.
        janet_array_push(array, janet_wrap_string(janet_string(&zero, 1)));
        break;
      }

      if (bignum_bytes.bytes[0] & 0x80)
      {
        // ASN.1 expects two's compliment, so we prepend an extra empty byte
        // when the high order bit is 1
        #ifdef PRINT_TRACE_EVERYTHING
        janet_eprintf("Integer high bit is set, adding zero byte\n", value);
        #endif
        janet_array_push(array, janet_wrap_string(janet_string(&zero, 1)));
      }

      #ifdef PRINT_TRACE_EVERYTHING
      janet_eprintf("Integer is ready to push with a size of %d\n", bignum_bytes.len);
      #endif
      janet_array_push(array, bignum_value);
      break;
    }
    case janetls_asn1_universal_type_null:
    {
      // An easy case, we dont push any data at all here for the value.
      // Null is the type tag for it and the length,
      // both of which are handled outside
      break;
    }
    case janetls_asn1_universal_type_object_identifier:
    {
      #ifdef PRINT_TRACE_EVERYTHING
      janet_eprintf("Object identifier %p\n", value);
      #endif
      // two cases, a string case with dots,
      // and a tuple of numbers.
      Janet oid_value = value;

      if (janet_is_byte_typed(oid_value))
      {
        JanetByteView bytes = janet_to_bytes(oid_value);
        Janet result = janet_wrap_nil();
        int32_t length = 0;
        retcheck(encode_asn1_oid_string(&result, &length, bytes));
        janet_array_push(array, result);
      }
      else if (janet_checktype(oid_value, JANET_TUPLE) || janet_checktype(oid_value, JANET_ARRAY))
      {
        const Janet * data = NULL;
        int32_t data_count = 0;
        if (!janet_indexed_view(oid_value, &data, &data_count))
        {
          #ifdef PRINT_TRACE_EVERYTHING
          janet_eprintf("The tuple could not be used as an indexed view\n");
          #endif
          ret = JANETLS_ERR_ASN1_OTHER;
          goto end;
        }
        if (check_if_oid_list(data, data_count))
        {
          Janet result = janet_wrap_nil();
          int32_t length = 0;
          retcheck(encode_asn1_oid_numbers(&result, &length, data, data_count));
          janet_array_push(array, result);
        }
        else
        {
          ret = JANETLS_ERR_ASN1_INVALID_VALUE_TYPE;
          goto end;
        }
      }
      else
      {
        ret = JANETLS_ERR_ASN1_INVALID_VALUE_TYPE;
        goto end;
      }
      break;
    }
    case janetls_asn1_universal_type_bit_string:
    {
      #ifdef PRINT_TRACE_EVERYTHING
      janet_eprintf("bit string %p\n", value);
      #endif
      // Requires an unused bits byte before the rest of the bytes.
      // In most cases, the unused bit count is 0.
      uint8_t unused = 0;
      int bits_remainder = bits % 8;

      if (bits_remainder != 0)
      {
        unused = 8 - bits_remainder;
      }

      janet_array_push(array, janet_wrap_string(janet_string(&unused, 1)));
      // do not break.
      // encoding the value is the same as octet strings
      fall_through;
    }
    case janetls_asn1_universal_type_octet_string:
    {
      #ifdef PRINT_TRACE_EVERYTHING
      janet_eprintf("Octet string %p\n", value);
      #endif
      // Binary strings / buffers get put right into the array we're working on.
      if (janet_is_byte_typed(value))
      {
        janet_array_push(array, value);
        break;
      }
      else if (janet_checktype(value, JANET_NIL))
      {
        // Don't push anything.
        break;
      }

      // Do not break if the type does not match.
      // Fall through to encoding an embedded ASN.1 document.
      fall_through;
    }
    case janetls_asn1_universal_type_sequence:
    case janetls_asn1_universal_type_set:
    {
      #ifdef PRINT_TRACE_EVERYTHING
      janet_eprintf("Sequence or set with value %p\n", value);
      #endif
      if (janet_checktype(value, JANET_TUPLE) || janet_checktype(value, JANET_ARRAY))
      {
        const Janet * data = NULL;
        int32_t data_count = 0;
        if (!janet_indexed_view(value, &data, &data_count))
        {
          #ifdef PRINT_TRACE_EVERYTHING
          janet_eprintf("The tuple could not be used as an indexed view\n");
          #endif
          ret = JANETLS_ERR_ASN1_OTHER;
          goto end;
        }
        retcheck(push_asn1_construction(array, data, data_count));
      }
      else if (janet_checktype(value, JANET_TABLE) || janet_checktype(value, JANET_STRUCT))
      {
        retcheck(push_asn1_construction(array, &value, 1));
      }
      else if (janet_is_byte_typed(value))
      {
        // Strings can be interpreted as a sub value
        retcheck(push_asn1_construction(array, &value, 1));
      }
      else if (janet_checktype(value, JANET_NIL))
      {
        // an empty sequence is a sad sequence.
        // but maybe valid.
        retcheck(push_asn1_construction(array, &value, 0));
      }
      else
      {
        ret = JANETLS_ERR_ASN1_INVALID_VALUE_TYPE;
        goto end;
      }

      break;
    }
    case janetls_asn1_universal_type_utf8_string:
    case janetls_asn1_universal_type_numeric_string:
    case janetls_asn1_universal_type_time:
    case janetls_asn1_universal_type_printable_string:
    case janetls_asn1_universal_type_teletext_string:
    case janetls_asn1_universal_type_videotex_string:
    case janetls_asn1_universal_type_ia5_string:
    case janetls_asn1_universal_type_utc_time:
    case janetls_asn1_universal_type_generalized_time:
    case janetls_asn1_universal_type_graphic_string:
    case janetls_asn1_universal_type_visible_string:
    case janetls_asn1_universal_type_general_string:
    case janetls_asn1_universal_type_universal_string:
    case janetls_asn1_universal_type_character_string:
    case janetls_asn1_universal_type_bitmap_string:
    case janetls_asn1_universal_type_date:
    case janetls_asn1_universal_type_time_of_day:
    case janetls_asn1_universal_type_date_time:
    case janetls_asn1_universal_type_duration:
    {
      // These are all string like. So encode them as strings.
      // note that only octet string can house nested ASN.1 documents.
      if (janet_is_byte_typed(value))
      {
        // this is one of the easiest cases.
        janet_array_push(array, value);
      }
      else
      {
        ret = JANETLS_ERR_ASN1_INVALID_VALUE_TYPE;
        goto end;
      }
      break;
    }
    case janetls_asn1_universal_type_external:
    case janetls_asn1_universal_type_real_float:
    case janetls_asn1_universal_type_object_descriptor:
    case janetls_asn1_universal_type_enumerated:
    case janetls_asn1_universal_type_embedded_pdv:
    case janetls_asn1_universal_type_oid_iri:
    case janetls_asn1_universal_type_relative_oid:
    case janetls_asn1_universal_type_relative_oid_iri:
    default:
    {
      #ifdef PRINT_TRACE_EVERYTHING
      janet_eprintf("Type was not supported %p %d\n", value, type);
      #endif
      ret = JANETLS_ERR_ASN1_UNSUPPORTED_TYPE;
      goto end;
    }
  }
end:
  return ret;
}

int janetls_asn1_decode(Janet * result, Janet data, uint64_t flags, janetls_encoding_base64_variant base64_variant)
{
  int ret = 0;
  thread_position = 0;

  if (!janet_is_byte_typed(data))
  {
    ret = JANETLS_ERR_ASN1_INVALID_INPUT_TYPE;
    goto end;
  }

  JanetByteView bytes = janet_to_bytes(data);
  asn1_parser parser;
  parser.buffer = bytes.bytes;
  parser.length = bytes.len;
  parser.position = 0;
  parser.source = data;
  parser.flags = flags;
  parser.base64_variant = base64_variant;

  retcheck(decode_asn1_construction(&parser, result, parser.length));

  const Janet * value;
  int32_t tuple_size = 0;
  // Unwrap the first item
  // The decoding procedure is conservative and treats all constructions
  // as possibly multiple, even the root construction.
  if (janet_indexed_view(*result, &value, &tuple_size))
  {
    if (tuple_size == 1)
    {
      *result = value[0];
    }
  }

end:
  return ret;
}

int janetls_asn1_encode(Janet * result, Janet data)
{
  int ret = 0;
  // The size is arbitrary, I don't know how many are needed right now.
  JanetArray * array = janet_array(100);
  retcheck(push_asn1_tag_length_value(array, data));
  retcheck(flatten_array(result, array));
end:
  return ret;
}
