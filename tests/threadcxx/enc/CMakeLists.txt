# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(threadcxx_enc enc.cpp cond_tests.cpp)
target_link_libraries(threadcxx_enc oelibcxx oeenclave)

if (USE_PORTABLE_ENCLAVES)
  make_portable(threadcxx_enc)
endif ()
