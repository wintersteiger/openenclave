# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../../../include/openenclave/socket.edl 
    host-headers 
    socket_u_h)

add_library(oesocket_host STATIC
    socket_host.c
    ${socket_u_h})

if(CMAKE_C_COMPILER_ID MATCHES GNU)
target_compile_options(oesocket_host PRIVATE -Wjump-misses-init)
endif()

#target_link_libraries(oesocket_host PUBLIC
#    oelibc)

target_include_directories(oesocket_host PRIVATE 
    ${CMAKE_CURRENT_BINARY_DIR}
    ../../../include/
    )

set_property(TARGET oesocket_host PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/host)

install(TARGETS oesocket_host ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/host)
