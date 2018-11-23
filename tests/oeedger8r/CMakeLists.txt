# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (UNIX OR USE_PORTABLE_ENCLAVES)
	add_subdirectory(enc)
endif()

add_enclave_test(tests/oeedger8r ./host edl_host ./enc edl_enc)
