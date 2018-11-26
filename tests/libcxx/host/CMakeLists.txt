# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(libcxx_host host.cpp)
if (UNIX)
    target_compile_options(libcxx_host PRIVATE -std=c++14)
endif()
target_link_libraries(libcxx_host oehostapp)
