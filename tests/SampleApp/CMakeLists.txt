# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(SampleAppHost)

if (UNIX OR USE_PORTABLE_ENCLAVES)
	add_subdirectory(SampleApp)
endif()

add_enclave_test(tests/SampleApp ./SampleAppHost SampleAppHost ./SampleApp SampleApp)
