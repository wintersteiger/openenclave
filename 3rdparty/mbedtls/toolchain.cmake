# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

SET(CMAKE_SYSTEM_NAME Linux)

include(CMakeForceCompiler)

CMAKE_FORCE_C_COMPILER(enclave_cc Clang)
CMAKE_FORCE_CXX_COMPILER(enclave_cc Clang)