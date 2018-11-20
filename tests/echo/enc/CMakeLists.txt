# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave_executable)

oeedl_file(../echo.edl enclave gen)

add_executable(echo_enc enc.c ${gen})
target_compile_definitions(echo_enc PRIVATE FOO=1)

target_include_directories(echo_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(echo_enc oeenclave)

if (USE_PORTABLE_ENCLAVES)
    include(make_portable)
    make_portable(echo_enc)
endif()
