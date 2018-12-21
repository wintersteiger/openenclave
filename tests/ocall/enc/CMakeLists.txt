# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(ocall_enc enc.cpp)
target_link_libraries(ocall_enc oeenclave)

if (USE_PORTABLE_ENCLAVES)
  make_portable(ocall_enc)
endif ()
