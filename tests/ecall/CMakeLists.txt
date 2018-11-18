# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (UNIX OR (WIN32 AND USE_CLANG))
	add_subdirectory(enc)
endif()

add_enclave_test(tests/ecall ./host ecall_host ./enc ecall_enc)
