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
As of May 29, 2023, the submodule points to the release v2.28.3.
Releases can be found on: https://github.com/ARMmbed/mbedtls/releases

## Local Development

This project is set up with a [VS Code Dev Container](https://code.visualstudio.com/docs/remote/containers), which will install the latest janet, jpm.
You may need to install the plugin and docker desktop.
_This will not function with VS Codium._

Use the [Command Palette](https://code.visualstudio.com/docs/getstarted/userinterface#_command-palette) to "Remote Containers: Reopen in container"

This project uses submodules, you must run the following in the base directory to get the submodules downloaded.

```
git submodule update --init --recursive
```

Finally, you will need to install dependencies, pull up at the bottom to open a terminal and run
```
sudo jpm deps
```
Because this is in a dev container, sudo will not impact the host.

You may then run `jpm test` in `/workspaces/janetls` to verify it's functionality is intact.

## Security Audits

This project has not undergone a security audit.
Please contact me if you would like to fund or perform a security audit.
Use of this library is at your own risk.

Security advisories for dependencies are available at

* mbedtls: https://tls.mbed.org/security

## License - MIT

```
Copyright (c) 2020-2021 Levi Schuck

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
