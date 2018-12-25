// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

#include "socket_test_u.h"

#define SERVER_PORT "12345"

void* server_thread(void* arg)
{
    oe_enclave_t* server_enclave = (oe_enclave_t*)arg;
    int retval = 0;
    OE_TEST(ecall_run_server(server_enclave, &retval, SERVER_PORT) == OE_OK);
    return NULL;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* server_enclave = NULL;
    oe_enclave_t* client_enclave = NULL;
    pthread_t server_thread_id = 0;
    int ret = 0;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }
    // disable buffering
    setvbuf(stdout, NULL, _IONBF, 0);

    const uint32_t flags = oe_get_create_flags();

    result = oe_create_socket_test_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &server_enclave);
    OE_TEST(result == OE_OK);

    result = oe_create_socket_test_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &client_enclave);
    OE_TEST(result == OE_OK);

    // Launch server on a separate thread
    OE_TEST(
        pthread_create(
            &server_thread_id, NULL, server_thread, server_enclave) == 0);

    // Lauch client and talk to server
    OE_TEST(
        ecall_run_client(client_enclave, &ret, "localhost", SERVER_PORT) ==
        OE_OK);

    pthread_join(server_thread_id, NULL);

    OE_TEST(oe_terminate_enclave(client_enclave) == OE_OK);
    OE_TEST(oe_terminate_enclave(server_enclave) == OE_OK);

    printf("=== passed all tests (socket_test)\n");

    return 0;
}
