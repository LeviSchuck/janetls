# JaneTLS - Security primitives

This project wraps another TLS library, specifically Apache 2.0 Licensed 
[mbed TLS](https://tls.mbed.org/)). 
It's description reads as follows:

> Mbed TLS is a C library that implements cryptographic primitives, 
> X.509 certificate manipulation and the SSL/TLS and DTLS protocols.
> Its small code footprint makes it suitable for embedded systems.

This library is a work in progress and may not cover all functionality within
the wrapped TLS implementation.

mbed TLS is chosen for it's permissive license, small code footprint, and
active support.

> mbed TLS is supported by ARM with a young dynamic team which aims to keep
> customers happy with its straightforward and easygoing philosophy.
> 
> mbed TLS offers an SSL library with an intuitive API and readable source code,
> so you can actually understand what the code does.
> Also the mbed TLS modules are as loosely coupled as possible and written in
> the portable C language. 
> This allows you to use the parts you need, without having to include the total
> library. 

## mbed TLS version

mbed TLS is added as a submodule to this repository.
As of August 9th, 2020, the submodule points to the latest release v2.23.0
Releases can be found on: https://github.com/ARMmbed/mbedtls/releases 

## License - MIT

```
Copyright (c) 2020 Levi Schuck

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
