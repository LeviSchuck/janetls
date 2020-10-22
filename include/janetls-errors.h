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

#ifndef JANETLS_ERRORS_H
#define JANETLS_ERRORS_H

// Encoding
#define JANETLS_ERR_ENCODING_INVALID_CHARACTER 0x0100
#define JANETLS_ERR_ENCODING_INVALID_LENGTH 0x0101
#define JANETLS_ERR_ENCODING_INVALID_TYPE 0x0102

// Message Digest
#define JANETLS_ERR_MD_INVALID_INPUT_TYPE 0x0200
#define JANETLS_ERR_MD_INVALID_ALGORITHM 0x0201

// Ciphers
#define JANETLS_ERR_CIPHER_INVALID_CIPHER 0x0300
#define JANETLS_ERR_CIPHER_INVALID_MODE 0x0301
#define JANETLS_ERR_CIPHER_INVALID_ALGORITHM 0x0302
#define JANETLS_ERR_CIPHER_INVALID_KEY_SIZE 0x0303
#define JANETLS_ERR_CIPHER_INVALID_IV_SIZE 0x0304
#define JANETLS_ERR_CIPHER_INVALID_STATE 0x0305
#define JANETLS_ERR_CIPHER_INVALID_PADDING 0x0306
#define JANETLS_ERR_CIPHER_INVALID_TAG_SIZE 0x0307
#define JANETLS_ERR_CIPHER_INVALID_OPERATION 0x3008
#define JANETLS_ERR_CIPHER_INVALID_DATA_SIZE 0x3009

// ASN1
#define JANETLS_ERR_ASN1_INCOMPLETE 0x1001
#define JANETLS_ERR_ASN1_LENGTH_TOO_LARGE 0x1002
#define JANETLS_ERR_ASN1_EMPTY_INPUT 0x1003
#define JANETLS_ERR_ASN1_TEXT_PARSE_ERR 0x1004
#define JANETLS_ERR_ASN1_DATE_PARSE_ERROR 0x1005
#define JANETLS_ERR_ASN1_INVALID_BIT_STRING_LENGTH 0x1006
#define JANETLS_ERR_ASN1_INVALID_ASN1_CLASS 0x1007
#define JANETLS_ERR_ASN1_U64_OVERFLOW 0x1008
#define JANETLS_ERR_ASN1_NUMBER_OVERFLOW 0x1009
#define JANETLS_ERR_ASN1_BOOLEAN_INVALID_LENGTH 0x1010
#define JANETLS_ERR_ASN1_OBJECT_IDENTIFIER_INVALID_LENGTH 0x1011
#define JANETLS_ERR_ASN1_INVALID_OBJECT_IDENTIFIER 0x1012
#define JANETLS_ERR_ASN1_NUMBER_WAS_FRACTIONAL 0x1013
#define JANETLS_ERR_ASN1_MISSING_VALUE 0x1014
#define JANETLS_ERR_ASN1_INVALID_TAG 0x1015
#define JANETLS_ERR_ASN1_UNSUPPORTED_ENCODING 0x1016
#define JANETLS_ERR_ASN1_LENGTH_OVERFLOW 0x1017
#define JANETLS_ERR_ASN1_UNSUPPORTED_TYPE 0x1018
#define JANETLS_ERR_ASN1_UNUSED1 0x1019
#define JANETLS_ERR_ASN1_INPUT_CANNOT_BE_DECODED 0x1020
#define JANETLS_ERR_ASN1_INVALID_CONSTRUCTED_PARAMETER 0x1021
#define JANETLS_ERR_ASN1_INPUT_TYPE_MISSING 0x1022
#define JANETLS_ERR_ASN1_INVALID_INPUT_TYPE 0x1023
#define JANETLS_ERR_ASN1_INPUT_TYPE_NOT_IMPLEMENTED 0x1024
#define JANETLS_ERR_ASN1_INVALID_BITS 0x1025
#define JANETLS_ERR_INVALID_BOOLEAN_VALUE 0x1026
#define JANETLS_ERR_ASN1_INVALID_INTEGER 0x1027
#define JANETLS_ERR_ASN1_INVALID_VALUE_TYPE 0x1028
#define JANETLS_ERR_ASN1_OTHER 0x1099
// Big numbers
#define JANETLS_ERR_BIGNUM_COULD_NOT_CONVERT 0x1100

// Everything
#define JANETLS_ERR_SEARCH_OPTION_NOT_FOUND 0x9000
#define JANETLS_ERR_SEARCH_OPTION_INPUT_INVALID_TYPE 0x9001
#define JANETLS_ERR_ALLOCATION_FAILED 0x9999

#endif
