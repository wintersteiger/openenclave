# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../getenclave.edl enclave gen)

add_executable(getenclave_enc enc.c ${gen})

target_include_directories(getenclave_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(getenclave_enc oeenclave)

if (USE_PORTABLE_ENCLAVES)
  make_portable(getenclave_enc)
endif ()
