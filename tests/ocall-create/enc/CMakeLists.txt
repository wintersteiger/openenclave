# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(ocall_create_enc enc.c)
target_link_libraries(ocall_create_enc oeenclave)

if (USE_PORTABLE_ENCLAVES)
  make_portable(ocall_create_enc)
endif ()
