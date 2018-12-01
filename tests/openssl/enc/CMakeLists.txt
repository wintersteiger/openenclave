# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oessl STATIC oe_shim.c)
target_include_directories(oessl PRIVATE .)

add_executable(openssl_enc enc.c)
target_include_directories(openssl_enc PRIVATE .)
target_link_libraries(openssl_enc oeenclave oessl)
