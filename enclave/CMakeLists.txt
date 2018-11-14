# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if (USE_CLANG)
    message("oeenclave: Using clang to cross compile to linux")
    set(CMAKE_C_COMPILER enclave_cc)
    set(CMAKE_LINKER enclave_ar)
endif()

add_library(oeenclave STATIC
    ../common/asn1.c
    ../common/cert.c
    ../common/datetime.c
    ../common/qeidentity.c
    ../common/quote.c
    ../common/report.c
    ../common/revocation.c
    ../common/sgxcertextensions.c
    ../common/tcbinfo.c
    asn1.c
    cert.c
    crl.c
    ec.c
    cmac.c
    key.c
    link.c
    qeidinfo.c
    random.c
    report.c
    revocationinfo.c
    rsa.c
    sha.c
    start.S)

if(CMAKE_C_COMPILER_ID MATCHES GNU)
target_compile_options(oeenclave PRIVATE -Wjump-misses-init)
endif()

if (USE_CLANG)
    message("Changing libray prefix and suffix to linux style")
    set_target_properties(oeenclave PROPERTIES 
        PREFIX "lib"
        SUFFIX ".a"
    ) 
    # Treat .S files as C files to compile them
    set_source_files_properties(start.S PROPERTIES LANGUAGE C)
endif()


if(USE_LIBSGX)
target_compile_definitions(oeenclave PUBLIC OE_USE_LIBSGX)
endif()    

target_link_libraries(oeenclave PUBLIC
    mbedcrypto
    oelibc)

set_property(TARGET oeenclave PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

install(TARGETS oeenclave ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
