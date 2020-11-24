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

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_DEPRECATE)
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

// error.c seems to use string functions without including it.
#include <string.h>

// Provides access to files should they need to be digested
//#define MBEDTLS_FS_IO
// Essentially required for error building.
#define MBEDTLS_ERROR_C

// Sets up mbedtls_{calloc|free|sprintf|etc.}
// This is required on platforms like windows
#define MBEDTLS_PLATFORM_C

// Core message digest interface
#define MBEDTLS_MD_C
// Message digest algorithms
// Note that MD5 is considered no longer secure, however it is commonly used
// for e-tags or file syncing
#define MBEDTLS_MD5_C
// Note that SHA1 is considered no longer secure
#define MBEDTLS_SHA1_C
// SHA256 AND SHA224
#define MBEDTLS_SHA256_C
// SHA512 and SHA384
#define MBEDTLS_SHA512_C

// For Cipher
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_MODE_CFB
#define MBEDTLS_CIPHER_MODE_OFB
#define MBEDTLS_CIPHER_MODE_CTR
// #define MBEDTLS_CIPHER_MODE_XTS
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_POLY1305_C
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CHACHAPOLY_C
// #define MBEDTLS_CCM_C
// Cipher is used in GCM and is therefore necessary
// Further, a companion object cipher_wrap.c is necessary for cipher.c
#define MBEDTLS_CIPHER_C
// #define MBEDTLS_BLOWFISH_C
// #define MBEDTLS_CAMELLIA_C
// #define MBEDTLS_DES_C

// For randomness, entropy gives access to using a random syscall
// However in testing, it was not sufficient for generating 4096 bit primes
// So other Deterministic Random Bit Generators (DRBGs) will be used
// In this case, the AES CTR DRBG will be used for efficiency.
// The HMAC DRBG is capable of generating primes but is not sufficient.
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C
// #define MBEDTLS_HMAC_DRBG_C

// To enable big-number stuff, required for RSA and ECC
// ASM is required for fast operations on big numbers
// Practically every arch is supported by mbedtls.
// Bignumber genprime also needs randomness.
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_GENPRIME

// RSA support
#define MBEDTLS_RSA_C
#define MBEDTLS_OID_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21

// ECC support
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP192R1_ENABLED
#define MBEDTLS_ECP_DP_SECP224R1_ENABLED
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_DP_SECP521R1_ENABLED
#define MBEDTLS_ECP_DP_SECP192K1_ENABLED
#define MBEDTLS_ECP_DP_SECP224K1_ENABLED
#define MBEDTLS_ECP_DP_SECP256K1_ENABLED
#define MBEDTLS_ECP_DP_BP256R1_ENABLED
#define MBEDTLS_ECP_DP_BP384R1_ENABLED
#define MBEDTLS_ECP_DP_BP512R1_ENABLED
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED
#define MBEDTLS_ECP_DP_CURVE448_ENABLED
#define MBEDTLS_ECP_NIST_OPTIM
// ECC - ECDSA
#define MBEDTLS_ECDSA_C

// Accessories
#define MBEDTLS_HKDF_C
#define MBEDTLS_NIST_KW_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_PKCS5_C

// ASN1, although I don't use it directly
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C

#include "mbedtls/check_config.h"

#endif
