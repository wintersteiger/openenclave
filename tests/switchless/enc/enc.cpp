// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/thread.h>

#include "thread_control.h"
#include "switchless_t.h"


OE_ECALL void enc_worker_thread(void* args)
{
    size_t count = 0;
    thread_control* ptc = reinterpret_cast<thread_control*>(args);
    while (thread_control::RUNNING == tc_get_state(ptc) &&
           ptc->count_limit > count++)
    {
        queue_node* pnode = tc_pop_enc_queue(ptc);
        if (nullptr != pnode)
        {
            count = 0;
            
            // process the request
            handle_ecall(ptc, pnode->function_id, pnode->args);

            oe_host_free(pnode);
        }
    }
    tc_set_state(ptc, thread_control::STOPPED);
}




// arg1, arg2
void enc_sum(thread_control* ptc, int arg1, int arg2)
{
    oe_host_printf("enc_sum: %d + %d = %d\n", arg1, arg2, arg1 + arg2);
    host_sum(ptc, arg1, arg2, arg1 + arg2);
}




//OE_ECALL void test(void*)
//{
//}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    128,  /* HeapPageCount */
    16,   /* StackPageCount */
    16);  /* TCSCount */

//OE_DEFINE_EMPTY_ECALL_TABLE();
