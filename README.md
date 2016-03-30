# Grade Oven
## About
Grade Oven is a minimalist single-machine web server where instructors can make assignments to build/run/grade student code.  In practice, it's more flexible than that, but the main goal is allow students to submit programming assignments and get instant feedback with a focus on security (protecting the server from potentially malicious students).

## Setup (run it!)
This has only been tested on Ubuntu.  Adding support for other distributions of Linux should be trivial.  Adding support to any operating system that can run Docker should be possible, but may be difficult.

#### Ubuntu
1. Ensure you have root (in order to run sudo apt-get and create users)
1. Create a random key (just a bunch of random bytes) at data/secret_key.txt
1. Create an SSL key and certificate at data/ssl/server.key and data/ssl/server.crt
1. Change into the "setup" directory in a shell
1. Run ./setup.sh
1. Change into the "src" directory
1. Run python2 run.py --prod
1. Go to https://localhost/login
1. Login as "admin" with password "admin"
1. Profit (or don't, actually)

## License
Copyright (c) 2016 Mikel Dmitri Mcdaniel

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.