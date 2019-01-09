// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
//#include <atomic>
#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <limits>
#include <thread>
#include <vector>
#include "../../../host/sgx/enclave.h"

#include "thread_control.h"
#include "switchless_u.h"


void test_single_thread_enc_queue()
{
    const size_t COUNT = 100;
    thread_control tc;
    init_thread_control(&tc, thread_control::RUNNING, 0x06FFFFFF);

    OE_TEST(nullptr == tc_pop_enc_queue(&tc));
    OE_TEST(nullptr == tc_pop_host_queue(&tc));

    queue_node nodes[COUNT];
    for (queue_node* pnode = nodes; pnode != nodes + COUNT; ++pnode)
    {
        tc_push_enc_queue(&tc, pnode);
    }
    for (size_t i = 0; i < COUNT; ++i)
    {
        queue_node* pnode = tc_pop_enc_queue(&tc);
        OE_TEST(nodes + i == pnode);
    }

    for (queue_node* pnode = nodes; pnode != nodes + COUNT; ++pnode)
    {
        tc_push_host_queue(&tc, pnode);
    }
    for (size_t i = 0; i < COUNT; ++i)
    {
        queue_node* pnode = tc_pop_host_queue(&tc);
        OE_TEST(nodes + i == pnode);
    }

    OE_TEST(nullptr == tc_pop_enc_queue(&tc));
    OE_TEST(nullptr == tc_pop_host_queue(&tc));
}


void test_multi_thread_enc_queue_reader_thread(
    thread_control* ptc, queue_node* pnodes, size_t count)
{
    printf("  <test_multi_thread_enc_queue_reader_thread>\n");
    std::unique_ptr<size_t[]> counters(new size_t[count]);
    std::fill(counters.get(), counters.get() + count, 0);

    // pop all of the nodes
    for (size_t i = 0; i < count; ++i)
    {
        queue_node* pnode = nullptr;
        do {
            pnode = tc_pop_enc_queue(ptc);
        } while (nullptr == pnode);
        size_t index = static_cast<size_t>(std::distance(pnodes, pnode));
        OE_TEST(index < count);
        ++counters[index];
    }

    // test that each node was popped exactly once
    OE_TEST(count ==
            static_cast<size_t>(
                std::count(counters.get(), counters.get() + count, 1)));
    
    // test that the queue is now empty
    OE_TEST(nullptr == tc_pop_enc_queue(ptc));
    printf("  </test_multi_thread_enc_queue_reader_thread>\n");
}

void test_multi_thread_enc_queue_writer_thread(
    thread_control* ptc, queue_node* pnodes, size_t count)
{
    printf("  <test_multi_thread_enc_queue_writer_thread>\n");
    for (size_t i = 0; i < count; ++i)
    {
        tc_push_enc_queue(ptc, pnodes + i);
    }
    printf("  </test_multi_thread_enc_queue_writer_thread>\n");
}

void test_multi_thread_enc_queue()
{
    printf("<test_multi_thread_enc_queue>\n");
    const size_t NODE_COUNT = 100000;
    const size_t WRITER_THREAD_COUNT = 5;
    const size_t WRITER_NODE_COUNT = NODE_COUNT / WRITER_THREAD_COUNT;
    thread_control tc;
    init_thread_control(&tc, thread_control::RUNNING, 0x06FFFFFF);
    queue_node nodes[NODE_COUNT];

    std::thread reader_thread = std::thread(
        test_multi_thread_enc_queue_reader_thread, &tc, nodes, NODE_COUNT);
    std::thread writer_threads[WRITER_THREAD_COUNT];
    for (size_t i = 0; i < WRITER_THREAD_COUNT; ++i)
    {
        writer_threads[i] = std::thread(
            test_multi_thread_enc_queue_writer_thread, &tc,
            nodes + i * WRITER_NODE_COUNT, WRITER_NODE_COUNT);
    }
    for (size_t i = 0; i < WRITER_THREAD_COUNT; ++i)
    {
        writer_threads[i].join();
    }
    reader_thread.join();
    printf("</test_multi_thread_enc_queue>\n");
}


void enc_worker_thread(oe_enclave_t* enclave, thread_control* ptc)
{
    oe_result_t result = oe_call_enclave(enclave, "enc_worker_thread", ptc);
    OE_TEST(OE_OK == result);
    OE_TEST(thread_control::STOPPED == tc_get_state(ptc));
    tc_set_state(ptc, thread_control::EXITED);
}


void host_worker_thread(thread_control* ptc)
{
    while (thread_control::RUNNING == tc_get_state(ptc))
    {
        queue_node* pnode = tc_pop_host_queue(ptc);
        if (nullptr != pnode)
        {
            handle_ocall(ptc, pnode->function_id, pnode->args);
            free (pnode);
        }
    }
}



// arg1, arg2, sum
void host_sum(thread_control*, int arg1, int arg2, int sum)
{
    printf("host_sum: %d + %d = %d\n", arg1, arg2, sum);
}




int main(int argc, const char* argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();
    oe_enclave_t* enclave = nullptr;
    oe_result_t result = oe_create_switchless_enclave(
    argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);

    if (result != OE_OK)
    {
        oe_put_err("oe_create_host_enclave(): result=%u", result);
    }

#if (1) // disable all tests

    // test that the queues work
    test_single_thread_enc_queue();
    test_multi_thread_enc_queue();

    thread_control tc;
    std::thread worker_thread;

    // test that the thread can be stopped
    init_thread_control(
        &tc, thread_control::RUNNING, std::numeric_limits<size_t>::max());

    worker_thread = std::thread(enc_worker_thread, enclave, &tc);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    OE_TEST(thread_control::RUNNING == tc_get_state(&tc));
    tc_set_state(&tc, thread_control::STOPPING);
    worker_thread.join();
    OE_TEST(thread_control::EXITED == tc_get_state(&tc));

    // test that the thread can exit after the count expires
    init_thread_control(&tc, thread_control::RUNNING, 0x06FFFFFF);

    worker_thread = std::thread(enc_worker_thread, enclave, &tc);
    enc_sum(&tc, 1, 2);
    worker_thread.join();
    OE_TEST(thread_control::EXITED == tc_get_state(&tc));
    queue_node* pnode = tc_pop_host_queue(&tc);
    OE_TEST(nullptr != pnode);
    if (nullptr != pnode)
    {
        handle_ocall(&tc, pnode->function_id, pnode->args);
        free (pnode);
    }


    // test worker thread popping host calls
    init_thread_control(&tc, thread_control::RUNNING, 0x06FFFFFF);

    worker_thread = std::thread(enc_worker_thread, enclave, &tc);
    std::thread listener = std::thread(host_worker_thread, &tc);

    for (int i = 0; i < 1000; ++i)
    {
        enc_sum(&tc, i, i * 2);
    }
    worker_thread.join();
    listener.join();
    OE_TEST(thread_control::EXITED == tc_get_state(&tc));
    

#endif // disable all tests

    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
    {
        oe_put_err("oe_terminate_enclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
