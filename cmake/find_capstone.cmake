#
# Copyright 2017, Intel Corporation
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

find_package(capstone QUIET)

if(NOT capstone_FOUND)
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        message(STATUS "pkg-config found: ${PKG_CONFIG_EXECUTABLE}")
        message(STATUS "Using pkg-config path: $ENV{PKG_CONFIG_PATH}")
        pkg_search_module(capstone capstone QUIET)
    else()
        message(FATAL_ERROR "pkg-config not found. Please install pkg-config.")
    endif()
endif()
# Add debug messages to check where the variables are pointing
message(STATUS "PKG_CONFIG_PATH: $ENV{PKG_CONFIG_PATH}")
message(STATUS "CMAKE_PREFIX_PATH: ${CMAKE_PREFIX_PATH}")
message(STATUS "CMAKE_MODULE_PATH: ${CMAKE_MODULE_PATH}")

if(NOT capstone_FOUND)
	message(FATAL_ERROR
"Unable to find capstone. Please install pkg-config and capstone development files, e.g.:
sudo apt-get install pkg-config libcapstone-dev (on Debian, Ubuntu)
or
sudo dnf install capstone-devel (on Fedora)
or see instructions for other ways of installing capstone: http://www.capstone-engine.org/download.html
If casptone is installed, but cmake didn't manage to find it, there is a slight chance of fixing things by setting some of the following environment variables:
PKG_CONFIG_PATH, CMAKE_PREFIX_PATH, CMAKE_MODULE_PATH")
else()
    message(STATUS "Capstone found: ${capstone_FOUND}")
    message(STATUS "Capstone include directories: ${capstone_INCLUDE_DIRS}")
    message(STATUS "Capstone library directories: ${capstone_LIBRARY_DIRS}")
    message(STATUS "Capstone libraries: ${capstone_LIBRARIES}")
endif()
