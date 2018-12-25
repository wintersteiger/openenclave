# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../socket_test.edl 
    enclave socket_test_t
    --edl-search-dir ../../../include
)

#/home/soccerl/sockets/build/tests/sockets/enc/socket_test_t.c:276:55: error: implicit conversion changes signedness: 'int' to 'size_t'
#      (aka 'unsigned long') [-Werror,-Wsign-conversion]
#    if (a_Name) OE_ADD_SIZE(_input_buffer_size, _args.a_nNameLen);
#                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^~~~~~~~~~~
#/home/soccerl/sockets/include/openenclave/edger8r/common.h:72:33: note: expanded from macro 'OE_ADD_SIZE'

set_source_files_properties(
   ${socket_test_t}
   PROPERTIES COMPILE_FLAGS "-Wno-unused-variable -Wno-conversion")

add_enclave(TARGET socket_enc SOURCES enc.c ${socket_test_t})
target_link_libraries(socket_enc oesocket_enc)
target_include_directories(socket_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
