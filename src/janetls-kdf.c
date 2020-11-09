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
#include "janetls-kdf.h"
#include "janetls-md.h"
#include "mbedtls/platform_util.h"

static Janet hkdf(int32_t argc, Janet * argv);
static Janet pbkdf2(int32_t argc, Janet * argv);
static Janet concatkdf(int32_t argc, Janet * argv);

static const JanetReg cfuns[] =
{
  {"kdf/hkdf", hkdf,
    "(janetls/kdf/hkdf alg input &opt length otherinfo salt)\n\n"
    "\nInputs:\n"
    "alg - digest algorithm keyword, options listed in janetls/md/algorithms\n"
    "input - input material to derive a key\n"
    "length - optional output material length, by default as long as the digest algorithm size\n"
    "otherinfo - optional application specific context information\n"
    "salt - optional but highly recommended cryptographic salt\n"
    "\nExamples:\n"
    "(def salt (util/random 16))\n"
    "(def otherinfo \"AlgorithmID || PartyUInfo || PartyVInfo\")\n"
    "(def input \"computed value\")\n"
    "(kdf/hkdf :sha256 input)\n"
    "(kdf/hkdf :sha256 input 32 otherinfo salt)\n"
    "\nReturns a byte string suitable for use as key material"
    },
  {"kdf/pbkdf2", pbkdf2,
    "(janetls/kdf/pbkdf2 alg input length salt rounds)\n\n"
    "\nInputs:\n"
    "alg - digest algorithm keyword, options listed in janetls/md/algorithms\n"
    "input - input material to derive a key\n"
    "length - optional output material length, by default as long as the digest algorithm size\n"
    "salt - optional but highly recommended cryptographic salt\n"
    "rounds - optional iterations count, by default 10000\n"
    "\nExamples:\n"
    "(def salt (util/random 16))\n"
    "(def input \"computed value\")\n"
    "(kdf/pbkdf2 :sha256 input)\n"
    "(kdf/pbkdf2 :sha256 input 32 salt)\n"
    "(kdf/pbkdf2 :sha256 input 32 salt 1000)\n"
    "\nReturns a byte string suitable for use as key material"
    },
  {"kdf/concatkdf", concatkdf,
    "(janetls/kdf/concatkdf alg input length otherinfo salt)\n\n"
    "\nInputs:\n"
    "alg - digest algorithm keyword, options listed in janetls/md/algorithms\n"
    "input - input material to derive a key\n"
    "length - optional output material length, by default as long as the digest algorithm size\n"
    "otherinfo - optional application specific context information\n"
    "salt - optional but highly recommended cryptographic salt\n"
    "\nExamples:\n"
    "(def salt (util/random 16))\n"
    "(def otherinfo \"AlgorithmID || PartyUInfo || PartyVInfo\")\n"
    "(def input \"computed value\")\n"
    "(kdf/concatkdf :sha256 input)\n"
    "(kdf/concatkdf :sha256 input 32 otherinfo)\n"
    "(kdf/concatkdf :sha256 input 32 otherinfo \"\")\n"
    "(kdf/concatkdf :sha256 input 32 otherinfo salt)\n"
    "(kdf/concatkdf :sha256 input 32 \"\" salt)\n"
    "(kdf/concatkdf :sha256 input 32 \"\" \"\")\n"
    "\nReturns a byte string suitable for use as key material"
    },
  {NULL, NULL, NULL}
};

void submod_kdf(JanetTable * env)
{
  janet_cfuns(env, "janetls", cfuns);
}

static Janet hkdf(int32_t argc, Janet * argv)
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
  uint8_t * output = NULL;

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
    info = janet_to_bytes(argv[3]);
  }

  if (argc > 4)
  {
    salt = janet_to_bytes(argv[4]);
  }

  output = janet_smalloc(length);
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

static Janet pbkdf2(int32_t argc, Janet * argv)
{
  janet_arity(argc, 2, 5);
  mbedtls_md_type_t alg = symbol_to_alg(argv[0]);
  JanetByteView key = janet_to_bytes(argv[1]);
  const mbedtls_md_info_t * md_info = mbedtls_md_info_from_type(alg);
  size_t md_length = mbedtls_md_get_size(md_info);
  size_t length = md_length;
  size_t iterations = 10000;
  mbedtls_md_context_t md_ctx;
  JanetByteView salt = empty_byteview();
  int ret = 0;
  Janet result = janet_wrap_nil();

  if (argc > 2)
  {
    length = janet_getinteger(argv, 2);
  }

  if (argc > 3)
  {
    salt = janet_to_bytes(argv[3]);
  }

  if (argc > 4)
  {
    iterations = janet_getinteger(argv, 4);
  }

  mbedtls_md_init(&md_ctx);
  mbedtls_md_setup(&md_ctx, md_info, 1);

  uint8_t * output = janet_smalloc(length);
  if (output == NULL)
  {
    janet_panic("Could not allocate memory");
  }

  ret = mbedtls_pkcs5_pbkdf2_hmac(
    &md_ctx,
    key.bytes, key.len,
    salt.bytes, salt.len,
    iterations,
    length, output);

  if (ret == 0)
  {
    result = janet_wrap_string(janet_string(output, length));
  }
  mbedtls_md_free(&md_ctx);
  janet_sfree(output);
  check_result(ret);
  return result;
}

// A reference implementation
// https://github.com/pyca/cryptography/blob/master/src/cryptography/hazmat/primitives/kdf/concatkdf.py
// Another
// https://github.com/patrickfav/singlestep-kdf/blob/master/src/main/java/at/favre/lib/crypto/singlstepkdf/SingleStepKdf.java
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-56ar.pdf
// Section 5.8.1 (page 46-48)
// OR
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf
// Section 5.8.2.1 (page 55)
// PLUS "one-step key-derivation"
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr1.pdf
// Section 4.1 (page 11-14)

static Janet concatkdf(int32_t argc, Janet * argv)
{
  janet_arity(argc, 2, 5);
  mbedtls_md_type_t alg = symbol_to_alg(argv[0]);
  JanetByteView key = janet_to_bytes(argv[1]);
  const mbedtls_md_info_t * md_info = mbedtls_md_info_from_type(alg);
  size_t md_length = mbedtls_md_get_size(md_info);
  size_t length = md_length;
  int hmac = 0;
  mbedtls_md_context_t md_ctx;
  JanetByteView salt = empty_byteview();
  JanetByteView otherinfo = empty_byteview();
  uint8_t zeros[MBEDTLS_MD_MAX_SIZE];
  uint8_t working[MBEDTLS_MD_MAX_SIZE];
  Janet result = janet_wrap_nil();
  int ret = 0;
  uint8_t * buf = NULL;
  uint8_t * working_buf = NULL;
  size_t length_remaining = 0;
  uint32_t counter = 1;

  if (argc > 2)
  {
    length = janet_getinteger(argv, 2);
  }

  if (argc > 3)
  {
    otherinfo = janet_to_bytes(argv[3]);
  }

  if (argc > 4)
  {
    salt = janet_to_bytes(argv[4]);
    hmac = 1;

    if (salt.len == 0)
    {
      salt.bytes = zeros;
      salt.len = md_length;
      mbedtls_platform_zeroize(zeros, md_length);
    }
  }

  buf = janet_smalloc(length);
  working_buf = buf;

  if (buf == NULL)
  {
    janet_panic("Could not allocate memory");
  }

  length_remaining = length;
  mbedtls_platform_zeroize(buf, length);
  mbedtls_md_init(&md_ctx);

  retcheck(mbedtls_md_setup(&md_ctx, md_info, hmac));

  if (hmac)
  {
    retcheck(mbedtls_md_hmac_starts(&md_ctx, salt.bytes, salt.len));
  }

  uint32_t reps = length / md_length;
  if ((length % md_length) > 0)
  {
    reps++;
  }

  for (counter = 1; counter <= reps; counter++, working_buf += md_length)
  {
    uint8_t big_endian_counter[4];
    big_endian_counter[3] = counter & 0xff;
    big_endian_counter[2] = (counter >> 8) & 0xff;
    big_endian_counter[1] = (counter >> 16) & 0xff;
    big_endian_counter[0] = (counter >> 24) & 0xff;

    if (hmac)
    {
      retcheck(mbedtls_md_hmac_reset(&md_ctx));
      retcheck(mbedtls_md_hmac_update(&md_ctx, big_endian_counter, 4));
      retcheck(mbedtls_md_hmac_update(&md_ctx, key.bytes, key.len));
      if (otherinfo.len) {
        retcheck(mbedtls_md_hmac_update(&md_ctx, otherinfo.bytes, otherinfo.len));
      }
      retcheck(mbedtls_md_hmac_finish(&md_ctx, working));
    }
    else
    {
      retcheck(mbedtls_md_starts(&md_ctx));
      retcheck(mbedtls_md_update(&md_ctx, big_endian_counter, 4));
      retcheck(mbedtls_md_update(&md_ctx, key.bytes, key.len));
      if (otherinfo.len) {
        retcheck(mbedtls_md_update(&md_ctx, otherinfo.bytes, otherinfo.len));
      }
      retcheck(mbedtls_md_finish(&md_ctx, working));
    }

    if (length_remaining > md_length)
    {
      memcpy(working_buf, working, md_length);
      length_remaining -= md_length;
    }
    else
    {
      memcpy(working_buf, working, length_remaining);
      length_remaining = 0;
      break;
    }
  }

  if (ret == 0)
  {
    result = janet_wrap_string(janet_string(buf, length));
  }

end:
  mbedtls_platform_zeroize(buf, length);
  mbedtls_platform_zeroize(working, MBEDTLS_MD_MAX_SIZE);
  janet_sfree(buf);
  mbedtls_md_free(&md_ctx);
  check_result(ret);

  return result;
}
