# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(SampleAppCRTHost)

if (UNIX OR USE_PORTABLE_ENCLAVES)
	add_subdirectory(SampleAppCRT)
endif()

add_enclave_test(tests/SampleAppCRT ./SampleAppCRTHost SampleAppCRTHost ./SampleAppCRT SampleAppCRT)

