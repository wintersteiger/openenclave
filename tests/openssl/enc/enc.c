// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/jump.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include "openssl/x509.h"

OE_ECALL void Test(void* args_)
{
    X509_REQ* req = X509_REQ_new();
    X509_REQ_free(req);
   printf("inside enclave\n");
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */

OE_DEFINE_EMPTY_ECALL_TABLE();
