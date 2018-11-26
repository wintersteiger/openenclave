// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

OE_SET_ENCLAVE_SGX(
    1234, /* ProductID */
    5678, /* SecurityVersion */
    true, /* AllowDebug */
    64,  /* HeapPageCount */
    32,  /* StackPageCount */
    4);   /* TCSCount */
