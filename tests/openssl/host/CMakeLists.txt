# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(openssl_host host.c)
target_link_libraries(openssl_host oehostapp)
