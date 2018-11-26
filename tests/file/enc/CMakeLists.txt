# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave_executable)

oeedl_file(../file.edl enclave gen)
add_executable(file_enc
    enc.cpp
    ${gen}
    )

target_include_directories(file_enc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(file_enc oeenclave)

if (USE_PORTABLE_ENCLAVES)
    include(make_portable)
    make_portable(file_enc)
endif()
