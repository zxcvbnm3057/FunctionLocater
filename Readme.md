# Function Locater

This is an utility class for reverse engineering or third-party program function hijacking. It is build for Linux and wrote with C++. Because of some methods are related to ELF file format, it isn't a cross-platform library for now.

## Installation

The simplest way to develop with it is using Git submodule. You can run a command in your project src dir like this:

```shell
git submodule add https://github.com/zxcvbnm3057/FunctionLocater.git
```

Then add follow line into your Makefile

```makefile
include ./FunctionLocater/Makefile
```

Add `$(FunctionLocater)` as .o object file to be link to your executable file and `$(FunctionLocater_H)` as header file depandence to your .cpp source code.

Now rebuild your project.

All functions have comment about what is it using for and meaning of most of parameters.

Futher more, There is a [repository](https://github.com/CN-DST-DEVELOPER/Faster_DST) that might use for reference

## LICENSE

```
MIT License

Copyright (c) 2023 Fengying <zxcvbnm3057@outlook.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

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
