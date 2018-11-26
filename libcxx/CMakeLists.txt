# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# CMake project for CXX lib - re-archive the objects from
# external libcxx, libcxxrt, libunwind and wrap in easy-to-use CMake target
#
# Note: This approach might not work on Windows.
# Solutions are either to convert to OBJECT libraries (see below), or
# place/install all three libs (cxx, rt, unwind) and link against all
# three.

if (USE_PORTABLE_ENCLAVES)
    set(AR "llvm-ar")
    set(OBJ_FILES "@files.txt")
else()
    set(AR "ar")
    set(OBJ_FILES "*.o")
endif()

set (MRI_FILE "${CMAKE_CURRENT_BINARY_DIR}/combine.mri")
file(WRITE ${MRI_FILE} "create ${OE_LIBDIR}/openenclave/enclave/liboelibcxx.a\n")
file(APPEND ${MRI_FILE} 
    "addlib ${CMAKE_BINARY_DIR}/3rdparty/libcxx/liboelibcxx_cxx.a\n")
file(APPEND ${MRI_FILE} 
    "addlib ${CMAKE_BINARY_DIR}/3rdparty/libunwind/liboelibcxx_unwind.a\n")
file(APPEND ${MRI_FILE} 
    "addlib ${CMAKE_BINARY_DIR}/3rdparty/libcxxrt/libcxxrt/src/libcxxrt.a\n")
file(APPEND ${MRI_FILE} "save\n")
file(APPEND ${MRI_FILE} "end\n")

# Use intermediate project and add properties later using an interface library
include (ExternalProject)
ExternalProject_Add(oelibcxx_tmp
    DEPENDS cxxrt-static oelibcxx_unwind oelibcxx_cxx
    DOWNLOAD_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${AR} -M < "${MRI_FILE}"        
    INSTALL_COMMAND ""
)

# Interface lib to propagate includes&lib and install-rule
add_library(oelibcxx INTERFACE)
add_dependencies(oelibcxx oelibcxx_tmp)
target_link_libraries(oelibcxx INTERFACE
    $<BUILD_INTERFACE:${OE_LIBDIR}/openenclave/enclave/liboelibcxx.a>
    $<INSTALL_INTERFACE:\${_IMPORT_PREFIX}/${CMAKE_INSTALL_LIBDIR}/openenclave/enclave/liboelibcxx.a>
    )
target_link_libraries(oelibcxx INTERFACE oelibcxx_cxx)
install(FILES ${OE_LIBDIR}/openenclave/enclave/liboelibcxx.a DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
install(TARGETS oelibcxx EXPORT openenclave-targets)

# At some point, we should convert the 3rdparty-libs into true CMake OBJECT libs,
# so we could source the objects directly like this:
#add_library(oelibcxx STATIC
#   $<TARGET_OBJECTS:cxxrt-static>
#   $<TARGET_OBJECTS:oelibcxx_unwind>
#   $<TARGET_OBJECTS:oelibcxx_cxx>
#   )
#target_link_libraries(oelibcxx cxxrt-static)
#target_link_libraries(oelibcxx oelibcxx_unwind)
#target_link_libraries(oelibcxx oelibcxx_cxx)
# assemble lib-archive into proper dir
#set_property(TARGET oelibcxx PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/enclave)
# install lib-archive upon install-time
#install (TARGETS oelibcxx EXPORT openenclave ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/enclave)
