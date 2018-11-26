# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave_executable)

oeedl_file(../props.edl enclave gen)

add_enclave_executable(props_enc sign.conf enc.c props.c ${gen})

target_include_directories(props_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(props_enc oeenclave)

if (USE_PORTABLE_ENCLAVES)
    include(make_portable)
    make_portable(props_enc)
endif()
