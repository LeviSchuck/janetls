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
