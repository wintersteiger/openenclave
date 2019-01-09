# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

project(switchless)
subdirs(shared host enc)

#if (UNIX)
#	add_subdirectory(enc)
#endif()

add_enclave_test(tests/switchless switchless_host switchless_enc)
