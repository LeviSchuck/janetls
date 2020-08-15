/*
Copyright (c) 2020 Levi Schuck

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "janetls.h"

Janet hex_string(const uint8_t * str, unsigned int length)
{
  unsigned int hex_length = length * 2;
  char hexresult[hex_length + 1];
  unsigned int offset;

  memset(hexresult, 0, hex_length + 1);

  for(offset = 0; offset < length; offset++)
  {
    // sprintf doesn't like unsigned chars, but we are fully within the
    // signed and unsigned overlap.
    sprintf(&hexresult[offset * 2], "%02x", str[offset] & 0xff);
  }

  return janet_stringv((uint8_t *)hexresult, hex_length);
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

// Usable for both normal, web, and imap
// Though it may be best to split this up

static const unsigned char base64_dec_map[256] =
{
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
    255, 255, 255,  62,  63,  62, 255,  63,  52,  53, // + , - / 0 1
     54,  55,  56,  57,  58,  59,  60,  61, 255, 255, // 2 3 4 5 6 7 8 9
    255, 255, 255, 255, 255,   0,   1,   2,   3,   4, // A B C D E
      5,   6,   7,   8,   9,  10,  11,  12,  13,  14, // F G H I J K L M N O
     15,  16,  17,  18,  19,  20,  21,  22,  23,  24, // P Q R S T U V W X Y
     25, 255, 255, 255, 255,  63, 255,  26,  27,  28, // Z _ a b c
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

Janet base64_encode(const uint8_t * data, unsigned int length, base64_variant variant)
{
  // TODO Make it so that it can split lines for PGP (76 characters)
  // 64 characters for PEM, and add separators (\r\n)
  // As well as a 24 bit CRC (PGP only)

  uint8_t s1, s2, s3;
  uint8_t padded = 1; // Padding is mandatory in most cases.
  const unsigned char * map = base64_enc_map;
  if (variant == STANDARD_UNPADDED || variant == URL_UNPADDED)
  {
    padded = 0;
  }
  if (variant == URL || variant == URL_UNPADDED)
  {
    map = base64_web_enc_map;
  }
  if (variant == IMAP)
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
  return janet_wrap_string(janet_string(buffer->data, buffer->count));
}

void panic_base64_slice(const uint8_t * data, unsigned int length, unsigned int index)
{
  // One of these is 64 or higher. Therefore, there is an invalid
  // character present.
  uint8_t chunk[5] = {0, 0, 0, 0, 0};
  unsigned int position = (index / 4) * 4;
  unsigned int count = length - position;
  memcpy(chunk, data + position, (count > 4) ? 4 : count);

  janet_panicf("base64 invalid character discovered within chunk "
    "starting at position %d, within chunk: %s", index, chunk);
}

Janet base64_decode(const uint8_t * data, unsigned int length, base64_variant variant)
{
  if (length == 0)
  {
    return janet_wrap_string(janet_cstring(""));
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
        break;
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
      panic_base64_slice(data, length, index);
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
    janet_panic("base64 decode failed, appears to be truncated by at least one "
      "character.");
  }
  // Possible values at this point are 0, which means the last
  // chunk was fully processed.

  // from buffer, does a copy.
  // Don't free the buffer / deinit the buffer
  // it will lead to a double free.
  return janet_wrap_string(janet_string(buffer->data, buffer->count));
}

