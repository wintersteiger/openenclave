# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_executable(pthread_enc
    enc.cpp
    cond_tests.cpp
    rwlock_tests.cpp)

target_link_libraries(pthread_enc oelibcxx oeenclave)

if (USE_PORTABLE_ENCLAVES)
    include(make_portable)
    make_portable(pthread_enc)
endif()
