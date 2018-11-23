
set(CXXRT_SOURCES
    dynamic_cast.cc
    exception.cc
    guard.cc
    stdexcept.cc
    typeinfo.cc
    memory.cc
    auxhelper.cc
    libelftc_dem_gnu3.c
   )

# Ignore unused char variable in __cxa_call_unexpected function.
set_property(SOURCE exception.cc PROPERTY COMPILE_FLAGS -Wno-unused-variable)

add_definitions(-D_GNU_SOURCE)
add_library(cxxrt-static STATIC ${CXXRT_SOURCES})
target_link_libraries(cxxrt-static ${CMAKE_DL_LIBS})
set_target_properties(cxxrt-static PROPERTIES
                      OUTPUT_NAME "cxxrt"
                     )

if (UNIX)
# cxxrt-shared is used for testing on host side
# This is possible only on linux
add_library(cxxrt-shared SHARED ${CXXRT_SOURCES})
target_link_libraries(cxxrt-shared ${CMAKE_DL_LIBS})
set_target_properties(cxxrt-shared PROPERTIES
                      OUTPUT_NAME "cxxrt"
                     )
endif()

if (USE_PORTABLE_ENCLAVES)
    include(make_portable)
    make_portable(cxxrt-static)
endif()

