# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


add_executable(SampleAppCRT SampleAppCRT.cpp)
target_link_libraries(SampleAppCRT oeenclave)

if (USE_PORTABLE_ENCLAVES)
  make_portable(SampleAppCRT)
endif ()
