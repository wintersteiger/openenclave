# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_executable(sealKey_enc enc.cpp)

target_compile_features(sealKey_enc PRIVATE cxx_generalized_initializers)
target_link_libraries(sealKey_enc oelibcxx oeenclave)

if (USE_PORTABLE_ENCLAVES)
    include(make_portable)
    make_portable(sealKey_enc)
endif()
