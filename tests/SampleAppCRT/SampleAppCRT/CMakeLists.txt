# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_executable(SampleAppCRT SampleAppCRT.cpp)
target_link_libraries(SampleAppCRT oeenclave)

if (USE_PORTABLE_ENCLAVES)
	include(make_portable)
    make_portable(SampleAppCRT)
endif()
