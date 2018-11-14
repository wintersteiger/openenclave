# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Copy MUSL headers to collector dir and wrap
# actual compilation and lib-generation happens in <ROOT>/libc/

set(CFLAGS "-fPIC -DSYSCALL_NO_INLINE -target x86_64-pc-linux")
set(PATCHES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/patches)
set(MUSL_DIR ${CMAKE_CURRENT_BINARY_DIR}/musl)

include (ExternalProject)
ExternalProject_Add(oelibc_includes
    DOWNLOAD_COMMAND
        ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_LIST_DIR}/musl
        ${CMAKE_CURRENT_BINARY_DIR}/musl
    PATCH_COMMAND
        COMMAND ${CMAKE_COMMAND} -E copy
            ${MUSL_DIR}/arch/x86_64/syscall_arch.h
            ${MUSL_DIR}/arch/x86_64/__syscall_arch.h
        COMMAND ${CMAKE_COMMAND} -E copy
            ${PATCHES_DIR}/syscall_arch.h
            ${MUSL_DIR}/arch/x86_64/syscall_arch.h
        COMMAND ${CMAKE_COMMAND} -E copy
            ${PATCHES_DIR}/pthread_arch.h
            ${MUSL_DIR}/arch/x86_64/pthread_arch.h
    CONFIGURE_COMMAND
        ${CMAKE_COMMAND} -E chdir ${CMAKE_CURRENT_BINARY_DIR}/musl
        bash -x ./configure
            --includedir=${OE_INCDIR}/openenclave/libc
            CFLAGS=${CFLAGS}
            CC=clang
            CXX=clang++
    BUILD_COMMAND
        #${CMAKE_COMMAND} -E chdir ${CMAKE_CURRENT_BINARY_DIR}/musl
        #nmake install-headers

        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_CURRENT_BINARY_DIR}/musl/include
            ${OE_INCDIR}/openenclave/libc

        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_CURRENT_BINARY_DIR}/musl/arch/generic/bits
            ${OE_INCDIR}/openenclave/libc/bits

        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_CURRENT_BINARY_DIR}/musl/arch/x86_64/bits
            ${OE_INCDIR}/openenclave/libc/bits 

        COMMAND sed -f ${CMAKE_CURRENT_BINARY_DIR}/musl/tools/mkalltypes.sed 
            ${CMAKE_CURRENT_BINARY_DIR}/musl/arch/x86_64/bits/alltypes.h.in 
            ${CMAKE_CURRENT_BINARY_DIR}/musl/include/alltypes.h.in > 
            ${OE_INCDIR}//openenclave/libc/bits/alltypes.h
        
        COMMAND ${CMAKE_COMMAND} -E copy 
            ${CMAKE_CURRENT_BINARY_DIR}/musl/arch/x86_64/bits/syscall.h.in
            ${OE_INCDIR}/openenclave/libc/bits/syscall.h

        COMMAND sed -n -e s/__NR_/SYS_/p
            < ${CMAKE_CURRENT_BINARY_DIR}/musl/arch/x86_64/bits/syscall.h.in
            >> ${OE_INCDIR}/openenclave/libc/bits/syscall.h

        COMMAND ${CMAKE_COMMAND} -E copy
            ${OE_INCDIR}/openenclave/libc/endian.h
            ${OE_INCDIR}/openenclave/libc/__endian.h
        COMMAND ${CMAKE_COMMAND} -E copy
            ${PATCHES_DIR}/endian.h
            ${OE_INCDIR}/openenclave/libc/endian.h

        # Append deprecations.h to all C header files.
        # COMMAND ${CMAKE_CURRENT_LIST_DIR}/append-deprecations
        #    ${OE_INCDIR}/openenclave/libc

        # Copy local deprecations.h to include/bits/deprecated.h.
        COMMAND ${CMAKE_COMMAND} -E copy
            ${CMAKE_CURRENT_LIST_DIR}/deprecations.h
            ${OE_INCDIR}/openenclave/libc/bits/deprecations.h

    BUILD_BYPRODUCTS
        ${OE_INCDIR}/openenclave/libc ${CMAKE_CURRENT_BINARY_DIR}/musl
    INSTALL_COMMAND "")

# install-rule can be generated here, usage requirements defined in
# <ROOT>/libc/.
install(DIRECTORY
    ${OE_INCDIR}/openenclave/libc
    DESTINATION
    ${CMAKE_INSTALL_INCLUDEDIR}/openenclave/3rdparty)
