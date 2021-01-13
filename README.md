ESP8266 HTTP Rest API Client sample modules
=============================

This repository provides some examples in respect of how to use ESP8266 as HTTP Rest API Client,
and represents some other useful utilities.

Requirements and Dependencies
-----------------------------

This repository contains some C-code reference samples only
and it is not considered as complete project to make an executable
build right after source code checkout. Build will require
additional configuration based on your current ESP SDK setup and build environment specifics.
In order to make full project build and execution please refer full guidance
at the following YouTube Video:

https://www.youtube.com/watch?v=zjnGn_kKrik

ESP Mods
-----------------------------

This repository represents the following C-programming language modules for ESP8266:

* mod_http - This toolset can be used to process basic HTTP(S) communication between REST Service and Client.
             It contains various useful functions such as:
                   - URLs Parsing
                   - HTTP Headers Parsing
                   - Support of "Transfer-Encoding: chunked" data retrieval\parsing over HTTP
                   - Support of conventional HTTP body retrieval\parsing mechanisms using HTTP "Content-Length" header definitions.

* mod_enums - Basic toolset for debugging and tracing in logs. Used to represent various
              ESP SDK enums as string values.

License
-----------------------------

ESP8266 HTTP Rest API Client sample modules

Project is distributed under GNU GENERAL PUBLIC LICENSE 3.0

Copyright (C) 2020 - www.sigmaprj.com

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
