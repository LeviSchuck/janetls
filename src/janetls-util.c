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

#include <ctype.h>
#include "janetls.h"

static Janet constant_equals(int32_t argc, Janet * argv);
static Janet crc32(int32_t argc, Janet * argv);

static const JanetReg cfuns[] =
{
  {"constant=", constant_equals,"(janetls/constant_equals str1 str2)\n\n"
    "Compares two strings or buffers in constant time."
    },
  {"crc32", crc32, "(janetls/crc32 str)\n\n"
    "Calculates a CRC32 of a string or buffer"
    },
  {NULL, NULL, NULL}
};

void submod_util(JanetTable *env)
{
  janet_cfuns(env, "janetls", cfuns);
}

int janet_byte_cstrcmp_sensitive(JanetByteView str, const char * other) {
    int32_t len = str.len;
    int32_t index;
    for (index = 0; index < len; index++) {
        uint8_t c = str.bytes[index];
        uint8_t k = ((const uint8_t *)other)[index];
        if (c < k) return -1;
        if (c > k) return 1;
        if (k == '\0') break;
    }
    return (other[index] == '\0') ? 0 : -1;
}

int janet_byte_cstrcmp_insensitive(JanetByteView str, const char * other) {
    int32_t len = str.len;
    int32_t index;
    for (index = 0; index < len; index++) {
        uint8_t c = tolower(str.bytes[index]);
        uint8_t k = tolower(((const uint8_t *)other)[index]);
        if (c < k) return -1;
        if (c > k) return 1;
        if (k == '\0') break;
    }
    return (other[index] == '\0') ? 0 : -1;
}

JanetByteView janet_to_bytes(Janet x) {
    JanetByteView view;
    if (!janet_bytes_view(x, &view.bytes, &view.len)) {
        janet_panicf("Expected a %T for %p", JANET_TFLAG_BYTES, x);
    }
    return view;
}

JanetByteView empty_byteview() {
  JanetByteView value;
  value.bytes = NULL;
  value.len = 0;
  return value;
}

int janet_is_byte_typed(Janet x)
{
  return janet_checktype(x, JANET_STRING)  ||
         janet_checktype(x, JANET_SYMBOL)  ||
         janet_checktype(x, JANET_KEYWORD) ||
         janet_checktype(x, JANET_BUFFER);
}

int search_option_list(option_list_entry * list, int list_size, JanetByteView str, int * destination)
{
  for (int i = 0; i < list_size; i++)
  {
    option_list_entry * entry = list + i;
    if (entry->flags & OPTION_LIST_CASE_SENSITIVE)
    {
      if (janet_byte_cstrcmp_sensitive(str, entry->option) == 0)
      {
        *destination = entry->value;
        return 1;
      }
    }
    else
    {
      if (janet_byte_cstrcmp_insensitive(str, entry->option) == 0)
      {
        *destination = entry->value;
        return 1;
      }
    }
  }
  return 0;
}

Janet enumerate_option_list(option_list_entry * list, int size)
{
  // We will make space on the stack for all of them
  // Though we may not populate all of them.
  Janet * values = janet_smalloc(sizeof(Janet) * size);
  if (values == NULL)
  {
    janet_panic("Could not allocate memory");
  }
  int offset = 0;
  for (int i = 0; i < size; i++)
  {
    if (list[i].flags & OPTION_LIST_HIDDEN)
    {
      continue;
    }
    values[offset++] = janet_ckeywordv(list[i].option);
  }

  Janet tuple = janet_wrap_tuple(janet_tuple_n(values, offset));
  janet_sfree(values);
  return tuple;
}

Janet value_to_option(option_list_entry * list, int size, int value)
{
  for (int i = 0; i < size; i++)
  {
    option_list_entry * entry = list + i;
    if (value == entry->value)
    {
      return janet_ckeywordv(entry->option);
    }
  }
  return janet_wrap_nil();
}

const char * value_to_option_text(option_list_entry * list, int size, int value)
{
  for (int i = 0; i < size; i++)
  {
    option_list_entry * entry = list + i;
    if (value == entry->value)
    {
      return entry->option;
    }
  }
  return NULL;
}

int flatten_array(Janet * output, JanetArray * array)
{
  int ret = 0;
  JanetBuffer * buffer = janet_buffer(1000);
  int32_t array_size = array->count;
  for (int32_t i = 0; i < array_size; i++)
  {
    Janet value = array->data[i];
    if (janet_is_byte_typed(value))
    {
      JanetByteView bytes = janet_to_bytes(value);
      janet_buffer_push_bytes(buffer, bytes.bytes, bytes.len);
    }
    else
    {
      ret = JANETLS_ERR_ASN1_OTHER;
      goto end;
    }
  }
  *output = janet_wrap_string(janet_string(buffer->data, buffer->count));
end:
  return ret;
}

int is_ascii_string(const uint8_t * data, int32_t length)
{
  switch (classify_string(data, length))
  {
    case STRING_IS_BINARY:
    case STRING_IS_UTF8:
      return 0;
    default:
      return 1;
  }
}

int is_digit_string(const uint8_t * data, int32_t length)
{
  return classify_string(data, length) == STRING_IS_DIGITS;
}

int is_utf8_string(const uint8_t * data, int32_t length)
{
  switch (classify_string(data, length))
  {
    case STRING_IS_BINARY:
      return 0;
    default:
      return 1;
  }
}

string_type classify_string(const uint8_t * data, int32_t length)
{
  if (length <= 0)
  {
    // If we're going to have a sane default..?
    return STRING_IS_ASCII;
  }

  int binary = 0;
  int ascii = 0;
  int not_ascii = 0;
  int digits = 0;
  int not_digits = 0;
  int utf8 = 0;
  int oid = 0;
  int not_oid = 0;
  int printable = 0;
  int not_printable = 0;
  const uint8_t * end = data + length;
  while (data < end)
  {
    uint8_t first = *data++;
    if (first == 0)
    {
      binary = 1;
    }
    else if (first == '\n' || first == '\t' || first == '\r')
    {
      // standard whitespace is ascii..
      ascii = 1;
      utf8 = 1;
    }
    else if (first < ' ')
    {
      // But the other values there are just terminal control codes.
      binary = 1;
    }
    else if (first >= ' ' && first < 0x80)
    {
      // ascii is technically 0-128
      ascii = 1;
      // and UTF-8 contains ascii.
      utf8 = 1;

      // Printable check (a subset of ascii)
      // https://en.wikipedia.org/wiki/PrintableString
      if ((first >= 65 && first <= 90)
        || (first >= 97 && first <= 122)
        || (first >= 48 && first <= 57)
        || first == 32
        || (first >= 39 && first <= 47)
        || first == 58
        || first == 61
        || first == 63)
      {
        printable = 1;
      }
      else
      {
        not_printable = 1;
      }

      // digits check
      if (first >= '0' && first <= '9')
      {
        digits = 1;
      }
      else
      {
        not_digits = 1;
      }

      // OID check
      if (digits && first == '.')
      {
        // In order to be oid, one must first have digits.
        oid = 1;
      }
      else if (digits && oid && first >= '0' && first <= '9')
      {
        // Nothing changes, still oid
      }
      else if (digits && oid)
      {
        // only relevant if already oid
        // don't leave this as a blank else
        // or it will catch everything.
        not_oid = 1;
      }
      continue;
    }
    if (data + 1 > end)
    {
      break;
    }

    not_ascii = 1;

    uint8_t second = *data++;
    if ((second >> 6) != 2)
    {
      binary = 1;
      break;
    }
    if (first < 0xE0)
    {
      utf8 = 1;
      not_ascii = 1;
      not_digits = 1;
      not_oid = 1;
      continue;
    }
    if (data + 1 > end)
    {
      break;
    }

    uint8_t third = *data++;
    if ((third >> 6) != 2)
    {
      binary = 1;
      break;
    }
    if (first < 0xF0)
    {
      utf8 = 1;
      not_ascii = 1;
      not_digits = 1;
      not_oid = 1;
      continue;
    }
    if (data + 1 > end)
    {
      break;
    }

    uint8_t fourth = *data++;
    if ((fourth >> 6) != 2)
    {
      binary = 1;
      break;
    }
    if (first < 0xF8)
    {
      utf8 = 1;
      not_ascii = 1;
      not_digits = 1;
      not_oid = 1;
      continue;
    }

    binary = 1;

    break;
  }

  if (binary)
  {
    return STRING_IS_BINARY;
  }
  if (oid && !not_oid)
  {
    return STRING_IS_OID;
  }
  if (digits && !not_digits)
  {
    return STRING_IS_DIGITS;
  }
  if (printable && not_printable)
  {
    return STRING_IS_PRINTABLE;
  }
  if (ascii && !not_ascii)
  {
    return STRING_IS_ASCII;
  }
  if (utf8)
  {
    return STRING_IS_UTF8;
  }

  // This isn't logical.
  return STRING_IS_BINARY;
}

int janetls_constant_compare(Janet x, Janet y)
{
  if (!janet_is_byte_typed(x))
  {
    return -1;
  }

  if (!janet_is_byte_typed(y))
  {
    return 1;
  }

  JanetByteView xv = janet_to_bytes(x);
  JanetByteView yv = janet_to_bytes(y);

  if (xv.len < yv.len)
  {
    return -1;
  }

  if (yv.len < xv.len)
  {
    return 1;
  }

  int diff = 0;

  // Constant time, every byte is compared
  // now that we know the buffers are of equal length
  // (This is where constant time matters)
  for (int32_t i = 0; i < xv.len; i++)
  {
    diff |= xv.bytes[i] ^ yv.bytes[i];
  }

  // The result will zero if equal
  // Will be between 1-255 otherwise, the actual value
  // carries no meaning.
  return diff;
}

static Janet constant_equals(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 2);
  return janet_wrap_boolean(janetls_constant_compare(argv[0], argv[1]) == 0);
}

// A CRC32 implementation
// This table is precalculated.
// Rosetta code shows how to calculate it
// https://rosettacode.org/wiki/CRC-32
// Other sources have the table inline like freebsd:
// https://web.mit.edu/freebsd/head/sys/libkern/crc32.c
// or zip compression like:
// https://web.mit.edu/wwwdev/src/harvest-1.3.pl3/components/gatherer/standard/unbinhex/crc/zip.c

static uint32_t crc_table[] = {
0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

uint32_t janetls_crc32(const uint8_t * data, int32_t length)
{
  uint32_t crc_value = 0xFFFFFFFF;
  const uint8_t * end = data + length;

  while (data < end)
  {
    uint8_t index = (crc_value ^ (*data++)) & 0xff;
    crc_value = crc_table[index] ^ (crc_value >> 8);
  }

  return ~crc_value;
}

static Janet crc32(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  if (!janet_is_byte_typed(argv[0]))
  {
    janet_panicf("Expected a string or buffer, but got %p", argv[0]);
  }
  JanetByteView bytes = janet_to_bytes(argv[0]);
  return janet_wrap_number(janetls_crc32(bytes.bytes, bytes.len));
}

JanetBuffer * buffer_from_output(Janet * output, int32_t max_size)
{
  JanetBuffer * buffer;
  if (janet_checktype(*output, JANET_BUFFER))
  {
    buffer = janet_unwrap_buffer(*output);
  }
  else
  {
    // create a new buffer for the result
    buffer = janet_buffer(max_size);
    *output = janet_wrap_buffer(buffer);
  }
  return buffer;
}
