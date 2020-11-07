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
#include "janetls-hkdf.h"
#include "janetls-md.h"

static Janet derive(int32_t argc, Janet * argv);

static const JanetReg cfuns[] =
{
  {"hkdf/derive", derive, ""},
  {NULL, NULL, NULL}
};

void submod_hkdf(JanetTable * env)
{
  janet_cfuns(env, "janetls", cfuns);
}

static Janet derive(int32_t argc, Janet * argv)
{
  janet_arity(argc, 2, 5);
  mbedtls_md_type_t alg = symbol_to_alg(argv[0]);
  JanetByteView key = janet_to_bytes(argv[1]);
  const mbedtls_md_info_t * md_info = mbedtls_md_info_from_type(alg);
  size_t md_length = mbedtls_md_get_size(md_info);
  size_t length = md_length;
  JanetByteView salt = empty_byteview();
  JanetByteView info = empty_byteview();
  int ret = 0;
  Janet result = janet_wrap_nil();

  if (argc > 2)
  {
    length = janet_getinteger(argv, 2);
    size_t max_length = md_length * 255;
    if (length > max_length)
    {
      janet_panicf("HKDF can only produce at most %d "
        "bytes with %p, but %d bytes were requested.", max_length, argv[0], length);
    }
  }
  
  if (argc > 3)
  {
    salt = janet_to_bytes(argv[3]);
  }

  if (argc > 4)
  {
    info = janet_to_bytes(argv[4]);
  }

  uint8_t * output = janet_smalloc(length);
  if (output == NULL)
  {
    janet_panic("Could not allocate memory");
  }
  
  ret = mbedtls_hkdf(md_info, salt.bytes, salt.len, key.bytes, key.len, info.bytes, info.len, output, length);
  
  if (ret == 0)
  {
    result = janet_wrap_string(janet_string(output, length));
  }

  janet_sfree(output);
  check_result(ret);

  return result;
}
