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
#include "janetls-nistkw.h"

static Janet wrap(int32_t argc, Janet * argv);
static Janet unwrap(int32_t argc, Janet * argv);

static const JanetReg cfuns[] =
{
  {"nistkw/wrap", wrap, "e"},
  {"nistkw/unwrap", unwrap, "e"},
  {NULL, NULL, NULL}
};

void submod_nistkw(JanetTable * env)
{
  janet_cfuns(env, "janetls", cfuns);
}

#define MAX_KEY_SIZE 8192

static void check_kek(JanetByteView kek)
{
  switch (kek.len)
  {
    case 16:
      return;
    case 24:
      return;
    case 32:
      return;
    default:
      janet_panicf("The key encryption key must be 128 bits, "
        "192 bits, or 256 bits, but is %d bits.", kek.len * 8);
  }
}

static void check_cek(JanetByteView cek)
{
  if (cek.len == 0)
  {
    janet_panic("The content encryption key is empty, use "
      "janetls/util/random to generate a new key of proper length.");
  }
  else if (cek.len > MAX_KEY_SIZE)
  {
    janet_panicf("The max content encryption key size is %d bytes, "
      "but %d bytes were given.", MAX_KEY_SIZE, cek.len);
  }
}

static int get_kw_mode(int32_t argc, Janet * argv)
{
  if (argc > 2 && janet_getboolean(argv, 2))
  {
    return MBEDTLS_KW_MODE_KWP;
  }
  return MBEDTLS_KW_MODE_KW;
}

static Janet wrap_or_unwrap(int32_t argc, Janet * argv, int wrap)
{
  janet_arity(argc, 2, 3);
  mbedtls_nist_kw_context kwctx;
  uint8_t enc_cek[MAX_KEY_SIZE];
  size_t out_length = 0;
  int ret = 0;
  Janet result = janet_wrap_nil();
  JanetByteView kek = janet_to_bytes(argv[0]);
  JanetByteView cek = janet_to_bytes(argv[1]);
  int mode = get_kw_mode(argc, argv);
  check_kek(kek);
  check_cek(cek);

  mbedtls_nist_kw_init(&kwctx);

  retcheck(mbedtls_nist_kw_setkey(&kwctx, MBEDTLS_CIPHER_ID_AES, kek.bytes, kek.len * 8, wrap));

  if (wrap)
  {
    retcheck(mbedtls_nist_kw_wrap(&kwctx, mode, cek.bytes, cek.len, enc_cek, &out_length, MAX_KEY_SIZE));
  }
  else
  {
    retcheck(mbedtls_nist_kw_unwrap(&kwctx, mode, cek.bytes, cek.len, enc_cek, &out_length, MAX_KEY_SIZE));
  }

  result = janet_wrap_string(janet_string(enc_cek, out_length));

  end:
  mbedtls_nist_kw_free(&kwctx);
  mbedtls_platform_zeroize(enc_cek, MAX_KEY_SIZE);
  check_result(ret);

  return result;
}

static Janet wrap(int32_t argc, Janet * argv)
{
  return wrap_or_unwrap(argc, argv, 1);
}

static Janet unwrap(int32_t argc, Janet * argv)
{
  return wrap_or_unwrap(argc, argv, 0);
}