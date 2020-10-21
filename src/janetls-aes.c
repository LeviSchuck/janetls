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
#include "janetls-random.h"
#include "janetls-aes.h"

janetls_aes_object * janetls_new_aes()
{
  return NULL;
}
JanetAbstractType * janetls_aes_object_type()
{
  return NULL;
}
int janetls_setup_aes(
  janetls_aes_object * aes_object,
  janetls_aes_mode mode,
  const uint8_t * key,
  size_t key_length,
  const uint8_t * iv,
  size_t iv_length,
  janetls_cipher_operation operation,
  janetls_cipher_padding padding
  )
{
  return 0;
}
int janetls_aes_update(
  janetls_aes_object * aes_object,
  const uint8_t * data,
  size_t length,
  Janet * output)
{
  return 0;
}
int janetls_aes_finish(
  janetls_aes_object * aes_object,
  Janet * output)
{
  return 0;
}

// The following comment was found in mbedtls
// The final block is awlays padded in CBC
// Padding is only for CBC
/* Encryption: only cache partial blocks
* Decryption w/ padding: always keep at least one whole block
* Decryption w/o padding: only cache partial blocks
*/
