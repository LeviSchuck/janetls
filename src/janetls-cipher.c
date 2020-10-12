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
#include "janetls-cipher.h"

// Abstract Object functions
static int cipher_gc_fn(void * data, size_t len);
static int cipher_gcmark(void * data, size_t len);
static int cipher_get_fn(void * data, Janet key, Janet * out);

// Janet c functions
static Janet ciphers(int32_t argc, Janet * argv);

// internal helpers
static mbedtls_cipher_type_t cipher_type_from(
  janetls_cipher_class cipher_class,
  int key_size,
  janetls_cipher_mode mode);

JanetAbstractType cipher_object_type = {
  "janetls/cipher",
  cipher_gc_fn,
  cipher_gcmark,
  cipher_get_fn,
  JANET_ATEND_GET
};

static JanetMethod cipher_methods[] = {
  {NULL, NULL}
};

static const JanetReg cfuns[] =
{
  {"cipher/modes", janetls_search_cipher_mode_set, "(janetls/cipher/modes)\n\n"
    "Provides an tuple of keywords for available cipher modes"},
  {"cipher/paddings", janetls_search_cipher_padding_set, "(janetls/cipher/paddings)\n\n"
    "Provides an tuple of keywords for available cipher paddings"},
  {"cipher/classes", janetls_search_cipher_class_set, "(janetls/cipher/classes)\n\n"
    "Provides an tuple of keywords for available cipher classes (like aes)"},
  {"cipher/native-ciphers", ciphers, "internal use, use (cipher/ciphers)"
    },
  {NULL, NULL, NULL}
};

void submod_cipher(JanetTable * env)
{
  janet_cfuns(env, "janetls", cfuns);
  janet_register_abstract_type(janetls_cipher_object_type());
}

janetls_cipher_object * janetls_new_cipher()
{
  janetls_cipher_object * cipher = janet_abstract(&cipher_object_type, sizeof(janetls_cipher_object));
  memset(cipher, 0, sizeof(janetls_cipher_object));
  mbedtls_cipher_init(&cipher->ctx);
  return cipher;
}

JanetAbstractType * janetls_cipher_object_type()
{
  return &cipher_object_type;
}

static int cipher_gc_fn(void * data, size_t len)
{
  janetls_cipher_object * cipher = (janetls_cipher_object *)data;
  mbedtls_cipher_free(&cipher->ctx);
  return 0;
}

static int cipher_gcmark(void * data, size_t len)
{
  (void)data;
  (void)len;
  return 0;
}

static int cipher_get_fn(void * data, Janet key, Janet * out)
{
  (void)data;

  if (!janet_checktype(key, JANET_KEYWORD))
  {
    janet_panicf("expected keyword, got %p", key);
  }

  return janet_getmethod(janet_unwrap_keyword(key), cipher_methods, out);
}

struct local_mbedtls_cipher_map_t
{
  janetls_cipher_class cipher_class;
  janetls_cipher_mode mode;
  int key_size;
  mbedtls_cipher_type_t mbedtls_type;
};

static const struct local_mbedtls_cipher_map_t mbedtls_cipher_map[] = {
  {janetls_cipher_class_aes, janetls_cipher_mode_cbc, 128, MBEDTLS_CIPHER_AES_128_CBC},
  {janetls_cipher_class_aes, janetls_cipher_mode_cbc, 192, MBEDTLS_CIPHER_AES_192_CBC},
  {janetls_cipher_class_aes, janetls_cipher_mode_cbc, 256, MBEDTLS_CIPHER_AES_256_CBC},
  {janetls_cipher_class_aes, janetls_cipher_mode_ccm, 128, MBEDTLS_CIPHER_AES_128_CCM},
  {janetls_cipher_class_aes, janetls_cipher_mode_ccm, 192, MBEDTLS_CIPHER_AES_192_CCM},
  {janetls_cipher_class_aes, janetls_cipher_mode_ccm, 256, MBEDTLS_CIPHER_AES_256_CCM},
  {janetls_cipher_class_aes, janetls_cipher_mode_cfb, 128, MBEDTLS_CIPHER_AES_128_CFB128},
  {janetls_cipher_class_aes, janetls_cipher_mode_cfb, 192, MBEDTLS_CIPHER_AES_192_CFB128},
  {janetls_cipher_class_aes, janetls_cipher_mode_cfb, 256, MBEDTLS_CIPHER_AES_256_CFB128},
  {janetls_cipher_class_aes, janetls_cipher_mode_ctr, 128, MBEDTLS_CIPHER_AES_128_CTR},
  {janetls_cipher_class_aes, janetls_cipher_mode_ctr, 192, MBEDTLS_CIPHER_AES_192_CTR},
  {janetls_cipher_class_aes, janetls_cipher_mode_ctr, 256, MBEDTLS_CIPHER_AES_256_CTR},
  {janetls_cipher_class_aes, janetls_cipher_mode_ecb, 128, MBEDTLS_CIPHER_AES_128_ECB},
  {janetls_cipher_class_aes, janetls_cipher_mode_ecb, 192, MBEDTLS_CIPHER_AES_192_ECB},
  {janetls_cipher_class_aes, janetls_cipher_mode_ecb, 256, MBEDTLS_CIPHER_AES_256_ECB},
  {janetls_cipher_class_aes, janetls_cipher_mode_gcm, 128, MBEDTLS_CIPHER_AES_128_GCM},
  {janetls_cipher_class_aes, janetls_cipher_mode_gcm, 192, MBEDTLS_CIPHER_AES_192_GCM},
  {janetls_cipher_class_aes, janetls_cipher_mode_gcm, 256, MBEDTLS_CIPHER_AES_256_GCM},
  {janetls_cipher_class_aes, janetls_cipher_mode_ofb, 128, MBEDTLS_CIPHER_AES_128_OFB},
  {janetls_cipher_class_aes, janetls_cipher_mode_ofb, 192, MBEDTLS_CIPHER_AES_192_OFB},
  {janetls_cipher_class_aes, janetls_cipher_mode_ofb, 256, MBEDTLS_CIPHER_AES_256_OFB},
  {janetls_cipher_class_aes, janetls_cipher_mode_xts, 256, MBEDTLS_CIPHER_AES_128_XTS},
  {janetls_cipher_class_aes, janetls_cipher_mode_xts, 512, MBEDTLS_CIPHER_AES_256_XTS},
  {janetls_cipher_class_blowfish, janetls_cipher_mode_cbc, 128, MBEDTLS_CIPHER_BLOWFISH_CBC},
  {janetls_cipher_class_blowfish, janetls_cipher_mode_cbc, 192, MBEDTLS_CIPHER_BLOWFISH_CBC},
  {janetls_cipher_class_blowfish, janetls_cipher_mode_cbc, 256, MBEDTLS_CIPHER_BLOWFISH_CBC},
  {janetls_cipher_class_blowfish, janetls_cipher_mode_cfb, 128, MBEDTLS_CIPHER_BLOWFISH_CFB64},
  {janetls_cipher_class_blowfish, janetls_cipher_mode_cfb, 192, MBEDTLS_CIPHER_BLOWFISH_CFB64},
  {janetls_cipher_class_blowfish, janetls_cipher_mode_cfb, 256, MBEDTLS_CIPHER_BLOWFISH_CFB64},
  {janetls_cipher_class_blowfish, janetls_cipher_mode_ctr, 128, MBEDTLS_CIPHER_BLOWFISH_CTR},
  {janetls_cipher_class_blowfish, janetls_cipher_mode_ctr, 192, MBEDTLS_CIPHER_BLOWFISH_CTR},
  {janetls_cipher_class_blowfish, janetls_cipher_mode_ctr, 256, MBEDTLS_CIPHER_BLOWFISH_CTR},
  {janetls_cipher_class_blowfish, janetls_cipher_mode_ecb, 128, MBEDTLS_CIPHER_BLOWFISH_ECB},
  {janetls_cipher_class_blowfish, janetls_cipher_mode_ecb, 192, MBEDTLS_CIPHER_BLOWFISH_ECB},
  {janetls_cipher_class_blowfish, janetls_cipher_mode_ecb, 256, MBEDTLS_CIPHER_BLOWFISH_ECB},
  {janetls_cipher_class_camellia, janetls_cipher_mode_cbc, 128, MBEDTLS_CIPHER_CAMELLIA_128_CBC},
  {janetls_cipher_class_camellia, janetls_cipher_mode_cbc, 192, MBEDTLS_CIPHER_CAMELLIA_192_CBC},
  {janetls_cipher_class_camellia, janetls_cipher_mode_cbc, 256, MBEDTLS_CIPHER_CAMELLIA_256_CBC},
  {janetls_cipher_class_camellia, janetls_cipher_mode_ccm, 128, MBEDTLS_CIPHER_CAMELLIA_128_CCM},
  {janetls_cipher_class_camellia, janetls_cipher_mode_ccm, 192, MBEDTLS_CIPHER_CAMELLIA_192_CCM},
  {janetls_cipher_class_camellia, janetls_cipher_mode_ccm, 256, MBEDTLS_CIPHER_CAMELLIA_256_CCM},
  {janetls_cipher_class_camellia, janetls_cipher_mode_cfb, 128, MBEDTLS_CIPHER_CAMELLIA_128_CFB128},
  {janetls_cipher_class_camellia, janetls_cipher_mode_cfb, 192, MBEDTLS_CIPHER_CAMELLIA_192_CFB128},
  {janetls_cipher_class_camellia, janetls_cipher_mode_cfb, 256, MBEDTLS_CIPHER_CAMELLIA_256_CFB128},
  {janetls_cipher_class_camellia, janetls_cipher_mode_ctr, 128, MBEDTLS_CIPHER_CAMELLIA_128_CTR},
  {janetls_cipher_class_camellia, janetls_cipher_mode_ctr, 192, MBEDTLS_CIPHER_CAMELLIA_192_CTR},
  {janetls_cipher_class_camellia, janetls_cipher_mode_ctr, 256, MBEDTLS_CIPHER_CAMELLIA_256_CTR},
  {janetls_cipher_class_camellia, janetls_cipher_mode_ecb, 128, MBEDTLS_CIPHER_CAMELLIA_128_ECB},
  {janetls_cipher_class_camellia, janetls_cipher_mode_ecb, 192, MBEDTLS_CIPHER_CAMELLIA_192_ECB},
  {janetls_cipher_class_camellia, janetls_cipher_mode_ecb, 256, MBEDTLS_CIPHER_CAMELLIA_256_ECB},
  {janetls_cipher_class_camellia, janetls_cipher_mode_gcm, 128, MBEDTLS_CIPHER_CAMELLIA_128_GCM},
  {janetls_cipher_class_camellia, janetls_cipher_mode_gcm, 192, MBEDTLS_CIPHER_CAMELLIA_192_GCM},
  {janetls_cipher_class_camellia, janetls_cipher_mode_gcm, 256, MBEDTLS_CIPHER_CAMELLIA_256_GCM},
  {janetls_cipher_class_chacha20, janetls_cipher_mode_chachapoly, 256, MBEDTLS_CIPHER_CHACHA20_POLY1305},
  {janetls_cipher_class_chacha20, janetls_cipher_mode_stream, 256, MBEDTLS_CIPHER_CHACHA20},
  {janetls_cipher_class_des, janetls_cipher_mode_cbc, 64, MBEDTLS_CIPHER_DES_CBC},
  {janetls_cipher_class_des, janetls_cipher_mode_cbc, 128, MBEDTLS_CIPHER_DES_EDE_CBC},
  {janetls_cipher_class_des, janetls_cipher_mode_cbc, 192, MBEDTLS_CIPHER_DES_EDE3_CBC},
  {janetls_cipher_class_des, janetls_cipher_mode_ecb, 64, MBEDTLS_CIPHER_DES_ECB},
  {janetls_cipher_class_des, janetls_cipher_mode_ecb, 128, MBEDTLS_CIPHER_DES_EDE_ECB},
  {janetls_cipher_class_des, janetls_cipher_mode_ecb, 192, MBEDTLS_CIPHER_DES_EDE3_ECB},
  {janetls_cipher_class_none, janetls_cipher_mode_none, 0, MBEDTLS_CIPHER_NONE},
};

#define CIPHERS_COUNT (sizeof(mbedtls_cipher_map) / sizeof(struct local_mbedtls_cipher_map_t))
static Janet ciphers(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 0);
  Janet values[CIPHERS_COUNT];
  int size = CIPHERS_COUNT - 1;
  for (int i = 0; i < size; i++)
  {
    struct local_mbedtls_cipher_map_t local = mbedtls_cipher_map[i];
    Janet cipher[3];
    cipher[0] = janetls_search_cipher_class_to_janet(local.cipher_class);
    cipher[1] = janetls_search_cipher_mode_to_janet(local.mode);
    cipher[2] = janet_wrap_number(local.key_size);
    values[i] = janet_wrap_tuple(janet_tuple_n(cipher, 3));
  }
  return janet_wrap_tuple(janet_tuple_n(values, size));
}

static mbedtls_cipher_type_t cipher_type_from(janetls_cipher_class cipher_class, int key_size, janetls_cipher_mode mode)
{
  const struct local_mbedtls_cipher_map_t * mapping = mbedtls_cipher_map;
  while(mapping->cipher_class != janetls_cipher_class_none)

   {
    if (cipher_class == mapping->cipher_class
      && key_size == mapping->key_size
      && mode == mapping->mode)
    {
      return mapping->mbedtls_type;
    }
    mapping++;
   }
  return MBEDTLS_CIPHER_NONE;
}


