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
#define JANETLS_ERR_ASN1_OTHER 0x1012
#define JANETLS_ERR_ALLOCATION_FAILED 0x9999

#endif