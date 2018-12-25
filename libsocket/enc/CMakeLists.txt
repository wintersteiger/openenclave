# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../../include/openenclave/socket.edl 
    enclave-headers 
    socket_t_h)

add_library(oesocket_enc STATIC
    socket_enc.c
    ${socket_t_h})

if(CMAKE_C_COMPILER_ID MATCHES GNU)
target_compile_options(oesocket_enc PRIVATE -Wjump-misses-init)
endif()

target_link_libraries(oesocket_enc PUBLIC
    oelibc)

target_include_directories(oesocket_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

set_property(TARGET oesocket_enc PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

install(TARGETS oesocket_enc ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
