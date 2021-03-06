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
#include "janetls-encoding.h"

int janetls_hex_decode_internal(Janet * result, const uint8_t * str, unsigned int length, int panic);
int janetls_hex_encode_internal(Janet * result, const uint8_t * str, unsigned int length, int panic);
int janetls_base64_encode_internal(Janet * result, const uint8_t * data, unsigned int length, janetls_encoding_base64_variant variant, int panic);
int janetls_base64_decode_internal(Janet * result, const uint8_t * data, unsigned int length, janetls_encoding_base64_variant variant, int panic);
int janetls_base32_encode_internal(Janet * result, const uint8_t * data, unsigned int length, janetls_encoding_base32_variant variant, int panic);
int janetls_base32_decode_internal(Janet * result, const uint8_t * data, unsigned int length, janetls_encoding_base32_variant variant, int panic);
int janetls_content_to_encoding_internal(Janet * result, const uint8_t * str, unsigned int length, janetls_encoding_type encoding, int encoding_variant, int panic);
int janetls_content_from_encoding_internal(Janet * result, const uint8_t * str, unsigned int length, janetls_encoding_type encoding, int encoding_variant, int panic);

Janet hex_encode(const uint8_t * str, unsigned int length)
{
  Janet result = janet_wrap_nil();
  janetls_hex_encode_internal(&result, str, length, 1);
  return result;
}

Janet hex_decode(const uint8_t * str, unsigned int length)
{
  Janet result = janet_wrap_nil();
  janetls_hex_decode_internal(&result, str, length, 1);
  return result;
}

// Alternate version which should not panic
int janetls_hex_encode(Janet * result, const uint8_t * str, unsigned int length)
{
  return janetls_hex_encode_internal(result, str, length, 0);
}

// Alternate version which does not panic (Unless janet buffer does)
int janetls_hex_decode(Janet * result, const uint8_t * str, unsigned int length)
{
  return janetls_hex_decode_internal(result, str, length, 0);
}

static const unsigned char hex_dec_map[128] =
{
    255, 255, 255, 255, 255, 255, 255, 255, 255, 254, //
    254, 255, 255, 254, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 254, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255,   0,   1, // 0 1
      2,   3,   4,   5,   6,   7,   8,   9, 255, 255, // 2 3 4 5 6 7 8 9
    255, 255, 255, 255, 255,  10,  11,  12,  13,  14, // A B C D E
     15, 255, 255, 255, 255, 255, 255, 255, 255, 255, // F
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255,  10,  11,  12, // a b c
     13,  14,  15,  16, 255, 255, 255, 255, 255, 255, // d e f
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255,           //
};

int janetls_hex_encode_internal(Janet * result, const uint8_t * str, unsigned int length, int panic)
{
  int ret = 0;
  unsigned int hex_length = length * 2;
  JanetBuffer * buffer = janet_buffer(hex_length);
  unsigned int offset;

  for(offset = 0; offset < length; offset++)
  {
    // sprintf doesn't like unsigned chars, but we are fully within the
    // signed and unsigned overlap.
    char out[3];
    sprintf(out, "%02x", str[offset] & 0xff);
    janet_buffer_push_u8(buffer, out[0]);
    janet_buffer_push_u8(buffer, out[1]);
  }

  // from buffer, does a copy.
  // Don't free the buffer / deinit the buffer
  // it will lead to a double free.
  *result = janet_wrap_string(janet_string(buffer->data, buffer->count));
  // end:
  return ret;
}

int janetls_hex_decode_internal(Janet * result, const uint8_t * str, unsigned int length, int panic)
{
  int ret = 0;
  unsigned int hex_length = length / 2;
  JanetBuffer * buffer = janet_buffer(hex_length);
  unsigned int offset;
  unsigned int digits = 0;
  int odd = 0;

  for(offset = 0; offset < length; offset+= 2)
  {
    uint8_t higher;
    uint8_t lower;
    higher_get:
    higher = str[offset];

    if (higher & 0x80)
    {
      if (panic)
      {
        janet_panicf("Could not decode hex string at position %d, character "
          "appears outside ascii range", offset);
      }
      ret = JANETLS_ERR_ENCODING_INVALID_CHARACTER;
      goto end;
    }
    uint8_t higher_map = hex_dec_map[higher];
    if (higher_map == 254)
    {
      if (offset + 2 >= length)
      {
        break;
      }
      offset++;
      goto higher_get;
    }
    digits++;

    lower_get:
    lower = str[offset + 1];

    if (lower & 0x80)
    {
      if (panic)
      {
        janet_panicf("Could not decode hex string at position %d, character "
        "appears outside ascii range", offset + 1);
      }
      ret = JANETLS_ERR_ENCODING_INVALID_CHARACTER;
      goto end;
    }

    uint8_t lower_map = hex_dec_map[lower];
    if (lower_map == 254)
    {
      if (offset + 1 >= length)
      {
        odd = 1;
        break;
      }
      offset++;
      goto lower_get;
    }
    digits++;

    if (higher_map == 255 || lower_map == 255)
    {
      if (panic)
      {
        char pair[3] = {higher, lower, 0};
        janet_panicf("Could not decode hex string at position %d, characters "
          "must not be hex: '%s' (%d, %d)", offset, pair, higher, lower);
      }
      ret = JANETLS_ERR_ENCODING_INVALID_CHARACTER;
      goto end;
    }
    uint8_t result = (higher_map << 4) | lower_map;
    janet_buffer_push_u8(buffer, result);
  }

  if (odd)
  {
    if (panic)
    {
      janet_panicf("Could not decode hex string, the input of digis should be a "
        "multiple of two, it is %d", digits);
    }
    else
    {
      ret = JANETLS_ERR_ENCODING_INVALID_CHARACTER;
      goto end;
    }
  }

  // from buffer, does a copy.
  // Don't free the buffer / deinit the buffer
  // it will lead to a double free.
  *result = janet_wrap_string(janet_string(buffer->data, buffer->count));
end:
  return ret;
}

// The mbed tls base64 implementation does not support the variants
// That I'd like to support, it's behavior is also scoped
// specifically towards standard base64 and pem files.

static const unsigned char base64_enc_map[64] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// https://tools.ietf.org/html/rfc4648#section-5
static const unsigned char base64_web_enc_map[64] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// https://tools.ietf.org/html/rfc3501#section-5.1.3
static const unsigned char base64_imap_enc_map[64] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

static const unsigned char base32_enc_map[32] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static const unsigned char base32_z_enc_map[32] =
  "ybndrfg8ejkmcpqxot1uwisza345h769";
static const unsigned char base32_hex_enc_map[32] =
  "0123456789ABCDEFGHIJKLMNOPQRSTUV";

// Usable for both normal, web, and imap
// Though it may be best to split this up

static const unsigned char base64_dec_map[256] =
{
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255,  62,  63,  62, 255,  63,  52,  53, //       + , -   / 0 1
     54,  55,  56,  57,  58,  59,  60,  61, 255, 255, // 2 3 4 5 6 7 8 9
    255, 255, 255, 255, 255,   0,   1,   2,   3,   4, //           A B C D E
      5,   6,   7,   8,   9,  10,  11,  12,  13,  14, // F G H I J K L M N O
     15,  16,  17,  18,  19,  20,  21,  22,  23,  24, // P Q R S T U V W X Y
     25, 255, 255, 255, 255,  63, 255,  26,  27,  28, // Z         _   a b c
     29,  30,  31,  32,  33,  34,  35,  36,  37,  38, // d e f g h i j k l m
     39,  40,  41,  42,  43,  44,  45,  46,  47,  48, // n o p q r s t u v w
     49,  50,  51, 255, 255, 255, 255, 255, 255, 255, // x y z
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255                      //
};

static const unsigned char base32_dec_map[256] =
{
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //                 0 1
     26,  27,  28,  29,  30,  31, 255, 255, 255, 255, // 2 3 4 5 6 7 8 9
    255, 255, 255, 255, 255,   0,   1,   2,   3,   4, //           A B C D E
      5,   6,   7,   8,   9,  10,  11,  12,  13,  14, // F G H I J K L M N O
     15,  16,  17,  18,  19,  20,  21,  22,  23,  24, // P Q R S T U V W X Y
     25, 255, 255, 255, 255, 255, 255,   0,   1,   2, // Z             a b c
      3,   4,   5,   6,   7,   8,   9,  10,  11,  12, // d e f g h i j k l m
     13,  14,  15,  16,  17,  18,  19,  20,  21,  22, // n o p q r s t u v w
     23,  24,  25, 255, 255, 255, 255, 255, 255, 255, // x y z
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255                      //
};

static const unsigned char base32_hex_dec_map[256] =
{
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255,   0,   1, //                 0 1
      2,   3,   4,   5,   6,   7,   8,   9, 255, 255, // 2 3 4 5 6 7 8 9
    255, 255, 255, 255, 255,  10,  11,  12,  13,  14, //           A B C D E
     15,  16,  17,  18,  19,  20,  21,  22,  23,  24, // F G H I J K L M N O
     25,  26,  27,  28,  29,  30,  31, 255, 255, 255, // P Q R S T U V W X Y
    255, 255, 255, 255, 255, 255, 255,  10,  11,  12, // Z             a b c
     13,  14,  15,  16,  17,  18,  19,  20,  21,  22, // d e f g h i j k l m
     23,  24,  25,  26,  27,  28,  29,  30,  31, 255, // n o p q r s t u v w
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, // x y z
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255                      //
};

// If I ever add crockford.. http://www.crockford.com/base32.html
// There's something here about adding a checksum that I don't want
// to deal with right now.
// static const unsigned char base32_crockford_dec_map[256] =
// {
//     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
//     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
//     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
//     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
//     255, 255, 255, 255, 255, 255, 255, 255,   0,   1, //                 0 1
//       2,   3,   4,   5,   6,   7,   8,   9, 255, 255, // 2 3 4 5 6 7 8 9
//     255, 255, 255, 255, 255,  10,  11,  12,  13,  14, //           A B C D E
//      15,  16,  17,   1,  18,  19,   1,  20,  21,   0, // F G H I J K L M N O
//      22,  23,  24,  25,  26, 255,  27,  28,  29,  30, // P Q R S T U V W X Y
//      31, 255, 255, 255, 255, 255, 255,  10,  11,  12, // Z             a b c
//      13,  14,  15,  16,  17,   1,  18,  19,   1,  20, // d e f g h i j k l m
//      21,   0,  22,  23,  24,  25,  26, 255,  27,  28, // n o p q r s t u v w
//      29,  30,  31, 255, 255, 255, 255, 255, 255, 255, // x y z
//     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
//     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
//     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
//     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
//     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
//     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
//     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
//     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
//     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
//     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
//     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
//     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
//     255, 255, 255, 255, 255, 255                      //
// };

static const unsigned char base32_z_dec_map[256] =
{
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255,  18, //                 0 1
    255,  25,  26,  27,  30,  29,   7,  31, 255, 255, // 2 3 4 5 6 7 8 9
    255, 255, 255, 255, 255,  24,   1,  12,   3,   8, //           A B C D E
      5,   6,  28,  21,   9,  10, 255,  11,   2,  16, // F G H I J K L M N O
     13,  14,   4,  22,  17,  19, 255,  20,  15,   0, // P Q R S T U V W X Y
     23, 255, 255, 255, 255, 255, 255,  24,   1,  12, // Z             a b c
      3,   8,   5,   6,  28,  21,   9,  10, 255,  11, // d e f g h i j k l m
      2,  16,  13,  14,   4,  22,  17,  19, 255,  20, // n o p q r s t u v w
     15,   0,  23, 255, 255, 255, 255, 255, 255, 255, // x y z
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255                      //
};

Janet base64_encode(const uint8_t * data, unsigned int length, janetls_encoding_base64_variant variant)
{
  Janet result = janet_wrap_nil();
  janetls_base64_encode_internal(&result, data, length, variant, 1);
  return result;
}

Janet base32_encode(const uint8_t * data, unsigned int length, janetls_encoding_base32_variant variant)
{
  Janet result = janet_wrap_nil();
  janetls_base32_encode_internal(&result, data, length, variant, 1);
  return result;
}

void panic_base64_slice(const uint8_t * data, unsigned int length, unsigned int index)
{
  // One of these is 64 or higher. Therefore, there is an invalid
  // character present.
  uint8_t chunk[5] = {0, 0, 0, 0, 0};
  unsigned int position = (index / 4) * 4;
  unsigned int count = length - position;
  uint8_t value = data[index];
  memcpy(chunk, data + position, (count > 4) ? 4 : count);

  janet_panicf("base64 invalid character discovered within chunk "
    "starting at position %d with value 0x%02x, within chunk: %s", index, value, chunk);
}

void panic_base32_slice(const uint8_t * data, unsigned int length, unsigned int index)
{
  // One of these is 64 or higher. Therefore, there is an invalid
  // character present.
  uint8_t chunk[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0};
  unsigned int position = (index / 8) * 8;
  unsigned int count = length - position;
  uint8_t value = data[index];
  memcpy(chunk, data + position, (count > 8) ? 8 : count);

  janet_panicf("base32 invalid character discovered within chunk "
    "starting at position %d with value 0x%02x, within chunk: %s", index, value, chunk);
}

Janet base64_decode(const uint8_t * data, unsigned int length, janetls_encoding_base64_variant variant)
{
  Janet result = janet_wrap_nil();
  janetls_base64_decode_internal(&result, data, length, variant, 1);
  return result;
}

Janet base32_decode(const uint8_t * data, unsigned int length, janetls_encoding_base32_variant variant)
{
  Janet result = janet_wrap_nil();
  janetls_base32_decode_internal(&result, data, length, variant, 1);
  return result;
}

// Alternative which does not panic (unless out of memory for janet buffer)
int janetls_base64_encode(Janet * result, const uint8_t * data, unsigned int length, janetls_encoding_base64_variant variant)
{
  return janetls_base64_encode_internal(result, data, length, variant, 0);
}
// Alternative which does not panic (unless out of memory for janet buffer)
int janetls_base64_decode(Janet * result, const uint8_t * data, unsigned int length, janetls_encoding_base64_variant variant)
{
  return janetls_base64_decode_internal(result, data, length, variant, 0);
}


// Alternative which does not panic (unless out of memory for janet buffer)
int janetls_base64_encode_internal(Janet * result, const uint8_t * data, unsigned int length, janetls_encoding_base64_variant variant, int panic)
{
  int ret = 0;
  // TODO Make it so that it can split lines for PGP (76 characters)
  // 64 characters for PEM, and add separators (\r\n)
  // As well as a 24 bit CRC (PGP only)

  uint8_t s1, s2, s3;
  uint8_t padded = 1; // Padding is mandatory in most cases.
  const unsigned char * map = base64_enc_map;
  if (variant == janetls_encoding_base64_variant_standard_unpadded
    || variant == janetls_encoding_base64_variant_url_unpadded
    || variant == janetls_encoding_base64_variant_imap)
  {
    padded = 0;
  }
  if (variant == janetls_encoding_base64_variant_url
    || variant == janetls_encoding_base64_variant_url_unpadded)
  {
    map = base64_web_enc_map;
  }
  if (variant == janetls_encoding_base64_variant_imap)
  {
    map = base64_imap_enc_map;
  }

  unsigned int unpadded_multiplier = length / 3;
  unsigned int unpadded_length = unpadded_multiplier * 3;
  unsigned int remainder_length = length - unpadded_length;
  unsigned int padded_length = (remainder_length > 0) ? 4 : 0;
  if (!padded && remainder_length > 0)
  {
    // Remainders can only be 1 and 2, so the answer will be 2 characters or 3
    // Again, this is in the context where the '=' padding character is omitted
    // Examples
    // 123   : MTIz     : 4 characters, 4 + 0
    // 1234  : MTIzNA== : 6 characters, 4 + 2
    // 12345 : MTIzNDQ= : 7 characters, 4 + 3
    // 123456: MTIzNDU2 : 8 characters, 8 + 0
    padded_length = remainder_length + 1;
  }
  // We finally have our encoding size, and can refer to the above safely.
  unsigned int encoded_length = unpadded_length * 4 + padded_length;
  // A janet buffer is used because I find it unsafe to have
  // variable sized stacks which rely on user input.
  // Copying will also be necessary in order to create
  // A Janet string anyway. Rather be safe than sorry.
  JanetBuffer * buffer = janet_buffer(encoded_length);


  for (unsigned int i = 0; i < unpadded_multiplier; i++)
  {
    s1 = *data++;
    s2 = *data++;
    s3 = *data++;

    janet_buffer_push_u8(buffer, map[                    (s1 >> 2)  & 0x3F]);
    janet_buffer_push_u8(buffer, map[(((s1 &  3) << 4) + (s2 >> 4)) & 0x3F]);
    janet_buffer_push_u8(buffer, map[(((s2 & 15) << 2) + (s3 >> 6)) & 0x3F]);
    janet_buffer_push_u8(buffer, map[   s3                          & 0x3F]);
  }

  if (padded_length)
  {
    // There are at minimum 2 characters coming
    s1 = *data++;
    s2 = (remainder_length == 2) ? *data++ : 0;
    janet_buffer_push_u8(buffer,   map[                    (s1 >> 2)  & 0x3F]);
    janet_buffer_push_u8(buffer,   map[(((s1 &  3) << 4) + (s2 >> 4)) & 0x3F]);

    // Followed by a conditional third character
    if (remainder_length == 2)
    {
      // s3 will be 0, and is therefore omitted.
      janet_buffer_push_u8(buffer, map[((s2 & 15) << 2)               & 0x3F]);
    }
    // Finished by padding, if applicable
    if (padded)
    {
      janet_buffer_push_u8(buffer, '=');
      if (remainder_length == 1)
      {
        // Up to two = afterwards, but only if there's only
        // one remainding byte.
        janet_buffer_push_u8(buffer, '=');
      }
    }
  }

  // from buffer, does a copy.
  // Don't free the buffer / deinit the buffer
  // it will lead to a double free.
  *result = janet_wrap_string(janet_string(buffer->data, buffer->count));
  // end:
  return ret;
}

// Alternative which does not panic (unless out of memory for janet buffer)
int janetls_base32_encode_internal(Janet * result, const uint8_t * data, unsigned int length, janetls_encoding_base32_variant variant, int panic)
{
  int ret = 0;

  uint8_t s1, s2, s3, s4, s5;
  uint8_t padded = 1;
  const unsigned char * map = base32_enc_map;
  if (variant == janetls_encoding_base32_variant_standard_unpadded
    || variant == janetls_encoding_base32_variant_z_base
    || variant == janetls_encoding_base32_variant_hex_unpadded)
  {
    padded = 0;
  }
  if (variant == janetls_encoding_base32_variant_z_base)
  {
    map = base32_z_enc_map;
  }
  if (variant == janetls_encoding_base32_variant_hex
    || variant == janetls_encoding_base32_variant_hex_unpadded)
  {
    map = base32_hex_enc_map;
  }

  unsigned int unpadded_multiplier = length / 5;
  unsigned int unpadded_length = unpadded_multiplier * 5;
  unsigned int remainder_length = length - unpadded_length;
  unsigned int padding_bytes = 0;
  unsigned int padded_length = (remainder_length > 0) ? 8 : 0;
  if (remainder_length > 0)
  {
    // Remainders can only be 1 and 2, so the answer will be 2 characters or 3
    // Again, this is in the context where the '=' padding character is omitted
    // Examples
    // 1     : GE====== : 2 characters, 2 + 6
    // 12    : GEZA==== : 4 characters, 4 + 4
    // 123   : GEZDG=== : 5 characters, 5 + 3
    // 1234  : GEZDGNA= : 7 characters, 7 + 1
    // 12345 : GEZDGNBV : 8 characters, 8 + 0
    unsigned int lengths[] = {0,6,4,3,1,0,0,0};
    padding_bytes = lengths[remainder_length];

    if (!padded) {
      padded_length = remainder_length + padding_bytes;
    }
  }
  // We finally have our encoding size, and can refer to the above safely.
  unsigned int encoded_length = unpadded_length * 8 + padded_length;
  // A janet buffer is used because I find it unsafe to have
  // variable sized stacks which rely on user input.
  // Copying will also be necessary in order to create
  // A Janet string anyway. Rather be safe than sorry.
  JanetBuffer * buffer = janet_buffer(encoded_length);
  for (unsigned int i = 0; i < unpadded_multiplier; i++)
  {
    s1 = *data++;
    s2 = *data++;
    s3 = *data++;
    s4 = *data++;
    s5 = *data++;

    janet_buffer_push_u8(buffer, map[                            ((s1 & 0b11111000) >> 3)  & 0x1F]); // 5 bits from s1
    janet_buffer_push_u8(buffer, map[(((s1 & 0b00000111) << 2) | ((s2 & 0b11000000) >> 6)) & 0x1F]); // 3 bits from s1 ++ 2 bits from s2
    janet_buffer_push_u8(buffer, map[                            ((s2 & 0b00111110) >> 1)  & 0x1F]); // 5 bits from s2
    janet_buffer_push_u8(buffer, map[(((s2 & 0b00000001) << 4) | ((s3 & 0b11110000) >> 4)) & 0x1F]); // 1 bits from s2 + 4 bits from s3
    janet_buffer_push_u8(buffer, map[(((s3 & 0b00001111) << 1) | ((s4 & 0b10000000) >> 7)) & 0x1F]); // 4 bits from s3 + 1 bits from s4
    janet_buffer_push_u8(buffer, map[                            ((s4 & 0b01111100) >> 2)  & 0x1F]); // 5 bits from s4
    janet_buffer_push_u8(buffer, map[(((s4 & 0b00000011) << 3) | ((s5 & 0b11100000) >> 5)) & 0x1F]); // 2 bits from s4 + 3 bits from s5
    janet_buffer_push_u8(buffer, map[                             (s5 & 0b00011111)        & 0x1F]); // 5 bits from s5
  }

  if (padded_length)
  {
    s1 = *data++;
    s2 = (remainder_length >= 2) ? *data++ : 0;
    s3 = (remainder_length >= 3) ? *data++ : 0;
    s4 = (remainder_length >= 4) ? *data++ : 0;
    s5 = 0;
    janet_buffer_push_u8(buffer, map[                            ((s1 & 0b11111000) >> 3)  & 0x1F]); // 5 bits from s1
    janet_buffer_push_u8(buffer, map[(((s1 & 0b00000111) << 2) | ((s2 & 0b11000000) >> 6)) & 0x1F]); // 3 bits from s1 ++ 2 bits from s2

    // Followed by conditional bytes
    if (remainder_length >= 2)
    {
      janet_buffer_push_u8(buffer, map[                            ((s2 & 0b00111110) >> 1)  & 0x1F]); // 5 bits from s2
      janet_buffer_push_u8(buffer, map[(((s2 & 0b00000001) << 4) | ((s3 & 0b11110000) >> 4)) & 0x1F]); // 1 bits from s2 + 4 bits from s3
    } else if (padded) {
      janet_buffer_push_u8(buffer, '=');
      janet_buffer_push_u8(buffer, '=');
    }
    if (remainder_length >= 3)
    {
      janet_buffer_push_u8(buffer, map[(((s3 & 0b00001111) << 1) | ((s4 & 0b10000000) >> 7)) & 0x1F]); // 4 bits from s3 + 1 bits from s4
    } else if (padded) {
      janet_buffer_push_u8(buffer, '=');
    }
    if (remainder_length >= 4)
    {
      // s5 is 0 and is therefore omitted
      janet_buffer_push_u8(buffer, map[                            ((s4 & 0b01111100) >> 2)  & 0x1F]); // 5 bits from s4
      janet_buffer_push_u8(buffer, map[(((s4 & 0b00000011) << 3) | ((s5 & 0b11100000) >> 5)) & 0x1F]); // 2 bits from s4 + 3 bits from s5
    } else if (padded) {
      janet_buffer_push_u8(buffer, '=');
      janet_buffer_push_u8(buffer, '=');
    }

    if (padded) {
      janet_buffer_push_u8(buffer, '=');
    }
  }

  // from buffer, does a copy.
  // Don't free the buffer / deinit the buffer
  // it will lead to a double free.
  *result = janet_wrap_string(janet_string(buffer->data, buffer->count));
  // end:
  return ret;
}

// Alternative which does not panic (unless out of memory for janet buffer)
int janetls_base64_decode_internal(Janet * result, const uint8_t * data, unsigned int length, janetls_encoding_base64_variant variant, int panic)
{
  int ret = 0;
  if (length == 0)
  {
    *result = janet_wrap_string(janet_cstring(""));
    goto end;
  }
  // A janet buffer is used because I find it unsafe to have
  // variable sized stacks which rely on user input.
  // Copying will also be necessary in order to create
  // A Janet string anyway. Rather be safe than sorry.
  // Allocating just a bit more in case.
  unsigned int buffer_size = ((length + 4) / 4) * 3;
  JanetBuffer * buffer = janet_buffer(buffer_size);

  const unsigned char * map = base64_dec_map;
  // TODO differentiate by variant

  // Now all complete and partial chunks have been accounted for.
  int index = 0;
  int end = length;
  uint32_t chunk = 0;
  uint8_t revolver = 0;

  while (index < end)
  {
    uint8_t ch = data[index];

    switch (ch) {
      case ' ':
      case '\r':
      case '\n':
      case '\t':
        // Whitespace is ignored.. in some variants.
        // TODO.
        index++;
        continue;
      case '=':
        end = index;
        // This also breaks the switch.
        // TODO ensure the remainder is padding and
        // or whitespace (in applicable variants)
        continue;
    }

    uint8_t c = map[ch];
    if (c == 255)
    {
      if (panic)
      {
        panic_base64_slice(data, length, index);
      }
      else
      {
        ret = JANETLS_ERR_ENCODING_INVALID_CHARACTER;
        goto end;
      }
    }

    chunk = chunk << 6 | c;
    if (++revolver == 4)
    {
      // We've hit a full chunk.
      janet_buffer_push_u8(buffer, (chunk >> 16) & 0xff);
      janet_buffer_push_u8(buffer, (chunk >>  8) & 0xff);
      janet_buffer_push_u8(buffer,  chunk        & 0xff);
      // reset chunk
      revolver = 0;
      chunk = 0;
    }
    index++;
  }

  if (revolver == 3)
  {
    janet_buffer_push_u8(buffer, (chunk >> 10) & 0xff);
    janet_buffer_push_u8(buffer, (chunk >>  2) & 0xff);
  }
  else if (revolver == 2)
  {
    janet_buffer_push_u8(buffer, (chunk >>  4) & 0xff);
  }
  else if (revolver == 1)
  {
    if (panic)
    {
      janet_panic("base64 decode failed, appears to be truncated by at least one "
        "character.");
    }
    ret = JANETLS_ERR_ENCODING_INVALID_CHARACTER;
    goto end;
  }
  // Possible values at this point are 0, which means the last
  // chunk was fully processed.

  // from buffer, does a copy.
  // Don't free the buffer / deinit the buffer
  // it will lead to a double free.
  *result = janet_wrap_string(janet_string(buffer->data, buffer->count));
end:
  return ret;
}

// Alternative which does not panic (unless out of memory for janet buffer)
int janetls_base32_decode_internal(Janet * result, const uint8_t * data, unsigned int length, janetls_encoding_base32_variant variant, int panic)
{
  int ret = 0;
  if (length == 0)
  {
    *result = janet_wrap_string(janet_cstring(""));
    goto end;
  }
  // A janet buffer is used because I find it unsafe to have
  // variable sized stacks which rely on user input.
  // Copying will also be necessary in order to create
  // A Janet string anyway. Rather be safe than sorry.
  // Allocating just a bit more in case.
  unsigned int buffer_size = ((length + 8) / 8) * 5;
  JanetBuffer * buffer = janet_buffer(buffer_size);

  const unsigned char * map = base32_dec_map;
  if (variant == janetls_encoding_base32_variant_z_base)
  {
    map = base32_z_dec_map;
  }
  if (variant == janetls_encoding_base32_variant_hex
    || variant == janetls_encoding_base32_variant_hex_unpadded)
  {
    map = base32_hex_dec_map;
  }

  // Now all complete and partial chunks have been accounted for.
  int index = 0;
  int end = length;
  uint64_t chunk = 0;
  uint8_t revolver = 0;

  while (index < end)
  {
    uint8_t ch = data[index];

    switch (ch) {
      case ' ':
      case '\r':
      case '\n':
      case '\t':
        // Whitespace is ignored.. in some variants.
        // TODO.
        index++;
        continue;
      case '=':
        end = index;
        // This also breaks the switch.
        // TODO ensure the remainder is padding and
        // or whitespace (in applicable variants)
        continue;
    }

    uint8_t c = map[ch];
    if (c == 255)
    {
      if (panic)
      {
        panic_base32_slice(data, length, index);
      }
      else
      {
        ret = JANETLS_ERR_ENCODING_INVALID_CHARACTER;
        goto end;
      }
    }

    chunk = chunk << 5 | c;
    if (++revolver == 8)
    {
      // We've hit a full chunk.
      // eight input bytes, 40 bits of info, 2 spare bits
      janet_buffer_push_u8(buffer, (chunk >> 32) & 0xff);
      janet_buffer_push_u8(buffer, (chunk >> 24) & 0xff);
      janet_buffer_push_u8(buffer, (chunk >> 16) & 0xff);
      janet_buffer_push_u8(buffer, (chunk >> 8) & 0xff);
      janet_buffer_push_u8(buffer,  chunk        & 0xff);
      // reset chunk
      revolver = 0;
      chunk = 0;
    }
    index++;
  }

  if (revolver == 7)
  {
    // [xxxxx] [xxx | xx] [xxxxx] [x | xxxx] [xxxx | x] [xxxxx] [xx | ddd] [_____]
    janet_buffer_push_u8(buffer, (chunk >> 27) & 0xff);
    janet_buffer_push_u8(buffer, (chunk >> 19) & 0xff);
    janet_buffer_push_u8(buffer, (chunk >> 11) & 0xff);
    janet_buffer_push_u8(buffer, (chunk >>  3) & 0xff);
  }
  else if (revolver == 5)
  {
    // [xxxxx] [xxx | xx] [xxxxx] [x | xxxx] [xxxx | d] [_____] [__ | ___] [_____]
    janet_buffer_push_u8(buffer, (chunk >> 17) & 0xff);
    janet_buffer_push_u8(buffer, (chunk >>  9) & 0xff);
    janet_buffer_push_u8(buffer, (chunk >>  1) & 0xff);
  }
  else if (revolver == 4)
  {
    // [xxxxx] [xxx | xx] [xxxxx] [x | dddd] [____ | _] [_____] [__ | ___] [_____]
    janet_buffer_push_u8(buffer, (chunk >> 12) & 0xff);
    janet_buffer_push_u8(buffer, (chunk >> 4) & 0xff);
  }
  else if (revolver == 2)
  {
    // [xxxxx] [xxx | dd] [_____] [_ | ____] [____ | _] [_____] [__ | ___] [_____]
    janet_buffer_push_u8(buffer, (chunk >> 2) & 0xff);
  }
  else if (revolver != 0)
  {
    if (panic)
    {
      janet_panic("base32 decode failed, appears to be truncated by at least one or two "
        "characters.");
    }
    ret = JANETLS_ERR_ENCODING_INVALID_CHARACTER;
    goto end;
  }
  // Possible values at this point are 0, which means the last
  // chunk was fully processed.

  // from buffer, does a copy.
  // Don't free the buffer / deinit the buffer
  // it will lead to a double free.
  *result = janet_wrap_string(janet_string(buffer->data, buffer->count));
end:
  return ret;
}

Janet content_to_encoding(const uint8_t * str, unsigned int length, janetls_encoding_type encoding, int encoding_variant)
{
  Janet result = janet_wrap_nil();
  janetls_content_to_encoding_internal(&result, str, length, encoding, encoding_variant, 1);
  return result;
}

Janet content_from_encoding(const uint8_t * str, unsigned int length, janetls_encoding_type encoding, int encoding_variant)
{
  switch (encoding)
  {
    case janetls_encoding_type_raw: return janet_wrap_string(janet_string(str, length));
    case janetls_encoding_type_hex: return hex_decode(str, length);
    case janetls_encoding_type_base64: return base64_decode(str, length, (janetls_encoding_base64_variant) encoding_variant);
    case janetls_encoding_type_base32: return base32_decode(str, length, (janetls_encoding_base32_variant) encoding_variant);
  }
  janet_panicf("Internal error: the content encoding provided could not be "
    "used, it is %d", encoding);
  // unreachable
  return janet_wrap_nil();
}

int janetls_content_to_encoding(Janet * result, const uint8_t * str, unsigned int length, janetls_encoding_type encoding, int encoding_variant)
{
  return janetls_content_to_encoding_internal(result, str, length, encoding, encoding_variant, 0);
}

int janetls_content_from_encoding(Janet * result, const uint8_t * str, unsigned int length, janetls_encoding_type encoding, int encoding_variant)
{
  return janetls_content_from_encoding_internal(result, str, length, encoding, encoding_variant, 0);
}

int janetls_content_to_encoding_internal(Janet * result, const uint8_t * str, unsigned int length, janetls_encoding_type encoding, int encoding_variant, int panic)
{
  int ret = 0;
  switch (encoding)
  {
    case janetls_encoding_type_raw:
    {
      *result = janet_wrap_string(janet_string(str, length));
      break;
    }
    case janetls_encoding_type_hex:
    {
      retcheck(janetls_hex_encode_internal(result, str, length, panic));
      break;
    }
    case janetls_encoding_type_base64:
    {
      retcheck(janetls_base64_encode_internal(result, str, length, (janetls_encoding_base64_variant) encoding_variant, panic));
      break;
    }
    case janetls_encoding_type_base32:
    {
      retcheck(janetls_base32_encode_internal(result, str, length, (janetls_encoding_base32_variant) encoding_variant, panic));
      break;
    }
    default:
    {
      if (panic)
      {
        janet_panicf("Internal error: the content encoding provided could not be "
        "used, it is %d", encoding);
      }
      ret = JANETLS_ERR_ENCODING_INVALID_TYPE;
      goto end;
    }
  }

end:
  return ret;
}

int janetls_content_from_encoding_internal(Janet * result, const uint8_t * str, unsigned int length, janetls_encoding_type encoding, int encoding_variant, int panic)
{
  int ret = 0;
  switch (encoding)
  {
    case janetls_encoding_type_raw:
    {
      *result = janet_wrap_string(janet_string(str, length));
      break;
    }
    case janetls_encoding_type_hex:
    {
      retcheck(janetls_hex_decode_internal(result, str, length, panic));
      break;
    }
    case janetls_encoding_type_base64:
    {
      retcheck(janetls_base64_decode_internal(result, str, length, (janetls_encoding_base64_variant) encoding_variant, panic));
      break;
    }
    case janetls_encoding_type_base32:
    {
      retcheck(janetls_base32_decode_internal(result, str, length, (janetls_encoding_base32_variant) encoding_variant, panic));
      break;
    }
    default:
    {
      if (panic)
      {
        janet_panicf("Internal error: the content encoding provided could not be "
        "used, it is %d", encoding);
      }
      ret = JANETLS_ERR_ENCODING_INVALID_TYPE;
      break;
    }
  }

end:
  return ret;
}