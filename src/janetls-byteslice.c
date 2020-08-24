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
#include "janetls-byteslice.h"

static int byteslice_get_fn(void * data, Janet key, Janet * out);
static int byteslice_gcmark(void *data, size_t len);
static Janet byteslice_start(int32_t argc, Janet * argv);
static Janet byteslice_get_bytes(int32_t argc, Janet * argv);

JanetAbstractType byteslice_object_type = {
  "janetls/byteslice",
  NULL,
  byteslice_gcmark,
  byteslice_get_fn,
  JANET_ATEND_GET
};

static JanetMethod byteslice_methods[] = {
  {"get", byteslice_get_bytes},
  {NULL, NULL}
};

static int byteslice_get_fn(void *data, Janet key, Janet * out)
{
  (void)data;

  if (!janet_checktype(key, JANET_KEYWORD))
  {
    janet_panicf("expected keyword, got %p", key);
  }

  return janet_getmethod(janet_unwrap_keyword(key), byteslice_methods, out);
}

static int byteslice_gcmark(void *data, size_t len)
{
  (void)len;
  byteslice_object * byteslice = (byteslice_object *)data;
  janet_mark(byteslice->reference);
  janet_mark(byteslice->cached);
  return 0;
}

static const JanetReg cfuns[] =
{
  {"byteslice", byteslice_start, "(janetls/byteslice bytes position length)\n\n"
    },
  {"byteslice/get", byteslice_get_bytes, "(janetls/byteslice/get byteslice)\n\n"
    "Reads the bytes within this slice"
    },

  {NULL, NULL, NULL}
};

void submod_byteslice(JanetTable *env)
{
  janet_cfuns(env, "janetls", cfuns);
  janet_register_abstract_type(&byteslice_object_type);
}

byteslice_object * gen_byteslice(Janet value, int position, int length)
{
  byteslice_object * byteslice = janet_abstract(&byteslice_object_type, sizeof(byteslice_object));
  memset(byteslice, 0, sizeof(byteslice_object));

  if (length > 0)
  {
    byteslice->length = length;
  }

  if (position > 0)
  {
    byteslice->position = position;
  }

  byteslice->reference = value;
  byteslice->cached = janet_wrap_nil();
  return byteslice;
}

static Janet byteslice_start(int32_t argc, Janet * argv)
{
  janet_arity(argc, 2, 3);
  if (!janet_is_byte_typed(argv[0]))
  {
    janet_panicf("Expected a byte type for which bytes could be sliced from, but got %p", argv[0]);
  }
  int position = janet_getinteger(argv, 1);
  int length = INT32_MAX;

  if (argc > 2)
  {
    length = janet_getinteger(argv, 2);
  }

  if (position < 0)
  {
    janet_panicf("The position (slot #1) cannot be negative, but got %p", argv[1]);
  }
  if (length < 0)
  {
    janet_panicf("The length (slot #2) cannot be less than zero, but got %p", argv[2]);
  }

  // Position and length checks are done when getting bytes.

  return janet_wrap_abstract(gen_byteslice(argv[0], position, length));
}

static Janet byteslice_get_bytes(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  byteslice_object * byteslice = janet_getabstract(argv, 0, &byteslice_object_type);

  if (janet_checktype(byteslice->cached, JANET_STRING))
  {
    // No need to view the reference anymore if it's been taken.
    return byteslice->cached;
  }

  JanetByteView view = janet_to_bytes(byteslice->reference);
  int position = byteslice->position;
  int length = byteslice->length;

  if (position >= view.len)
  {
    byteslice->cached = janet_cstringv("");
    byteslice->reference = janet_wrap_nil();
    return byteslice->cached;
  }

  if ((length == INT32_MAX) || ((position + length) >= view.len))
  {
    // Length needs to be clamped to the byteview's size
    length = view.len - position;
  }

  if (length <= 0)
  {
    byteslice->cached = janet_cstringv("");
    byteslice->reference = janet_wrap_nil();
    return byteslice->cached;
  }

  // Viewing it lazily produces a value for the slice.
  // No need to keep the original around now that we've duplicated the contents.
  Janet value = janet_wrap_string(janet_string(view.bytes + position, length));
  byteslice->cached = value;
  byteslice->reference = janet_wrap_nil();
  return value;
}

