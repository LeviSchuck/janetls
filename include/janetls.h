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

#ifndef JANETLS_H
#define JANETLS_H
#include <janet.h>
#include "janetls-errors.h"

typedef struct option_list_entry {
  int value;
  char option[32];
  uint8_t flags;
} option_list_entry;

#define OPTION_LIST_HIDDEN 1
#define OPTION_LIST_CASE_SENSITIVE 2

// Option list helpers
int search_option_list(option_list_entry * list, int list_size, JanetByteView str, int * destination);
Janet enumerate_option_list(option_list_entry * list, int size);
Janet value_to_option(option_list_entry * list, int size, int value);
const char * value_to_option_text(option_list_entry * list, int size, int value);

// Byte view helpers
JanetByteView janet_to_bytes(Janet x);
JanetByteView empty_byteview();
int janet_is_byte_typed(Janet x);
void check_result(int return_code);
const char * result_error_message(int result, uint8_t * unhandled);
int flatten_array(Janet * output, JanetArray * array);
int janet_byte_cstrcmp_insensitive(JanetByteView str, const char * other);
int janet_byte_cstrcmp_sensitive(JanetByteView str, const char * other);
int janetls_constant_compare(Janet x, Janet y);
uint32_t janetls_crc32(const uint8_t * data, int32_t length);
JanetBuffer * buffer_from_output(Janet * output, int32_t size);

int janetls_util_padding_pkcs7(
  uint8_t * data,
  uint8_t block_length,
  uint8_t length
  );
int janetls_util_padding_unpkcs7(
  const uint8_t * data,
  uint8_t block_length,
  uint8_t * length
  );

typedef enum string_type {
  STRING_IS_DIGITS,
  STRING_IS_OID,
  STRING_IS_ASCII,
  STRING_IS_PRINTABLE,
  STRING_IS_UTF8,
  STRING_IS_BINARY,
} string_type;

int is_ascii_string(const uint8_t * data, int32_t length);
int is_digit_string(const uint8_t * data, int32_t length);
int is_utf8_string(const uint8_t * data, int32_t length);
string_type classify_string(const uint8_t * data, int32_t length);

void submod_md(JanetTable * env);
void submod_util(JanetTable * env);
void submod_encoding(JanetTable * env);
void submod_bignum(JanetTable * env);
void submod_random(JanetTable * env);
void submod_byteslice(JanetTable * env);
void submod_asn1(JanetTable * env);
void submod_rsa(JanetTable * env);
void submod_ecp(JanetTable * env);
void submod_ecdsa(JanetTable * env);
void submod_cipher(JanetTable * env);
void submod_aes(JanetTable * env);
void submod_chacha(JanetTable * env);
void submod_chachapoly(JanetTable * env);
void submod_gcm(JanetTable * env);
void submod_ecdh(JanetTable * env);
void submod_hkdf(JanetTable * env);
void submod_nistkw(JanetTable * env);
void submod_pkcs5(JanetTable * env);

#define retcheck(x) do {ret=x;if (ret != 0){goto end;}} while(0)

#if defined(__GNUC__) && __GNUC__ >= 7
 #define fall_through __attribute__ ((fallthrough))
#else
 #define fall_through ((void)0)
#endif /* __GNUC__ >= 7 */

#ifndef NULL
#define NULL 0
#endif

#endif
