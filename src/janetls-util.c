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
    if (first < 0x80)
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
      else
      {
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