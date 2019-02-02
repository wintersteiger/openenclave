# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)
add_subdirectory(no_tdata_host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
  add_subdirectory(no_tdata_enc)
endif()

# Test enclaves without exported thread-locals.
add_enclave_test(tests/thread_local 
  thread_local_host
  thread_local_enc)

# Test enclaves with exported thread-locals.
add_enclave_test(tests/thread_local_exported
  thread_local_host
  thread_local_enc_exported
  --exported-thread-locals)

# Test that enclaves without tdata can be loaded
add_enclave_test(tests/thread_locals_no_tdata
  no_tdata_host no_tdata_enc)
