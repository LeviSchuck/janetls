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
#include "janetls-encoding.h"

Janet hex_encoder(int argc, Janet * argv)
{
  janet_fixarity(argc, 1);

  JanetByteView data = janet_getbytes(argv, 0);
  return hex_encode(data.bytes, data.len);
}

Janet hex_decoder(int argc, Janet * argv)
{
  janet_fixarity(argc, 1);

  JanetByteView data = janet_getbytes(argv, 0);
  return hex_decode(data.bytes, data.len);
}

int get_base64_variant(int argc, Janet * argv, int index, uint8_t panic, janetls_encoding_base64_variant * variant)
{
  if (index < argc)
  {
    int result = janetls_search_encoding_base64_variant(argv[index], variant);
    if (panic && result != 0)
    {
      janet_panicf("Given option %p is not expected, please review "
        "janetls/base64/variants for supported options", argv[index]);
    }
    return result;
  }

  return -1;
}

int get_content_encoding(int argc, Janet * argv, int index, uint8_t panic, janetls_encoding_type * encoding)
{
  if (index < argc)
  {
    int result = janetls_search_encoding_type(argv[index], encoding);
    if (panic && result != 0)
    {
      janet_panicf("Given option %p is not expected, please review "
          "janetls/encoding/types for supported options", argv[index]);
    }
    return result;
  }

  return -1;
}

Janet base64_encoder(int argc, Janet * argv)
{
  janet_arity(argc, 1, 2);
  JanetByteView data = janet_getbytes(argv, 0);
  janetls_encoding_base64_variant variant = janetls_encoding_base64_variant_standard;
  if (argc > 1) {
    get_base64_variant(argc, argv, 1, 1, &variant);
  }
  return base64_encode(data.bytes, data.len, variant);
}

Janet base64_decoder(int argc, Janet * argv)
{
  janet_arity(argc, 1, 2);
  JanetByteView data = janet_getbytes(argv, 0);
  janetls_encoding_base64_variant variant = janetls_encoding_base64_variant_standard;
  if (argc > 1) {
    get_base64_variant(argc, argv, 1, 1, &variant);
  }
  return base64_decode(data.bytes, data.len, variant);
}

int extract_encoding(int argc, Janet * argv, int offset, janetls_encoding_type * encoding, int * variant)
{
  int consumed = 0;
  if (argc + offset > 0)
  {
    if (get_content_encoding(argc, argv, offset + 0, 0, encoding) == 0)
    {
      consumed++;
      if (*encoding == janetls_encoding_type_base64)
      {
        if (argc + offset > 1 && get_base64_variant(argc, argv, offset + 1, 0, (janetls_encoding_base64_variant *)variant) == 0) {
          consumed++;
        }
      }
    }
  }

  // Return how many arguments were consumed
  return consumed;
}

void assert_generic_encoding_parameters(int argc, Janet * argv, janetls_encoding_type * encoding, int * variant)
{
  // Sanity check the parameters
  int consumed_arguments = extract_encoding(argc, argv, 1, encoding, variant);
  // We expect all arguments to be processed, thus the consumed arguments + 1
  // (the data to be encoded is the first parameter) should be equal to argc.
  // we panic if not all arguments are consumed.
  if (argc == 2 && consumed_arguments == 0)
  {
    janet_panicf("The second parameter %p could not be mapped to an "
        "encoding type. Please review janetls/encoding/types for options.",
        argv[1]);
  }
  else if (argc == 3 && consumed_arguments == 1)
  {
    janet_panicf("The third parameter %p could not be mapped to an "
        "encoding variant. Please review janetls/%S/types for options.",
        argv[2], janet_unwrap_keyword(argv[1]));
  }
}

Janet generic_encoder(int argc, Janet * argv)
{
  janet_arity(argc, 2, 3);
  janetls_encoding_type encoding = janetls_encoding_type_raw;
  int variant = 0;
  JanetByteView data = janet_getbytes(argv, 0);
  assert_generic_encoding_parameters(argc, argv, &encoding, &variant);
  return content_to_encoding(data.bytes, data.len, encoding, variant);
}

Janet generic_decoder(int argc, Janet * argv)
{
  janet_arity(argc, 2, 3);
  janetls_encoding_type encoding = janetls_encoding_type_raw;
  int variant = 0;
  JanetByteView data = janet_getbytes(argv, 0);
  assert_generic_encoding_parameters(argc, argv, &encoding, &variant);
  return content_from_encoding(data.bytes, data.len, encoding, variant);
}


static const JanetReg cfuns[] =
{
  {"hex/encode", hex_encoder,
    "(janetls/encode/hex str)\n\n"
    "Encodes an arbitrary string as hex."
    },
  {"hex/decode", hex_decoder,
    "(janetls/decode/hex str)\n\n"
    "Decodes an a hex string into an arbitrary string."
    },
  {"base64/encode", base64_encoder,
    "(janetls/base64/encode str &opt variant)\n\n"
    "Permitted variants are described in (janetls/base64/variants). "
    "It will by by default :standard"
    },
  {"base64/decode", base64_decoder,
    "(janetls/base64/decode str &opt variant)\n\n"
    "Permitted variants are described in (janetls/base64/variants). "
    "It will by by default :standard"
    },
  {"base64/variants", janetls_search_encoding_base64_variant_set,
    "(janetls/base64/variants)\n\n"
    "Enumerates acceptable variants for other base64 functions"
    },
  {"encoding/types", janetls_search_encoding_type_set,
    "(janetls/encoding/types)\n\n"
    "Enumerates acceptable encoding types which are supplied to the encode "
    "and decode functions."
    },
  {"encoding/encode", generic_encoder,
    "(janetls/encoding/encode str type &opt variant)\n\n"
    "Encodes the str into the type, is practically a no-op if given :raw.\n"
    "The optional-variant is specific to the type, for example :bas64 has "
    ":url-unpadded as a variant."
    },
  {"encoding/decode", generic_decoder,
    "(janetls/encoding/decode str type &opt variant)\n\n"
    "Decode the str into the type, is practically a no-op if given :raw.\n"
    "The optional-variant is specific to the type, for example :bas64 has "
    ":url-unpadded as a variant."
    },
  {NULL, NULL, NULL}
};

void submod_util(JanetTable *env)
{
  janet_cfuns(env, "janetls", cfuns);
}
