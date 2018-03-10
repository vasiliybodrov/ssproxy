# ##############################################################################
# The MIT License (MIT)
#
# Copyright (c) 2018 Vasiliy V. Bodrov aka Bodro, Ryazan, Russia
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT
# OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
# THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# ##############################################################################

cmake_minimum_required(VERSION 2.8)

project(proxy)

set(SOURCES
    ssproxy.cpp
)

# DEBUG
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} \
    -std=gnu++14 \
    -Wall -Wextra \
    -gdwarf-4 -fvar-tracking-assignments -O0 \
    -m64 -mtune=native -march=native -mfpmath=sse")

# RELEASE
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}
#    -std=gnu++14
#    -Wall -Wextra
#    -O2
#    -m64 -mtune=native -march=native -mfpmath=sse")

include_directories(${HEADERS_DIRECTORIES})

add_executable(${PROJECT_NAME} ${SOURCES})
