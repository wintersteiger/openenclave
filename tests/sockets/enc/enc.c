/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <openenclave/enclave.h>

// enclave.h must come before socket.h
#include <openenclave/bits/socket.h>

#include <socket_test_t.h>
#include <stdio.h>
#include <string.h>

/* This client connects to an echo server, sends a text message,
 * and outputs the text reply.
 */
int ecall_run_client(char* server, char* serv)
{
    int status = OE_FAILURE;
    struct addrinfo* ai = NULL;
    SOCKET s = INVALID_SOCKET;

    printf("Connecting to %s %s...\n", server, serv);

    /* Resolve server name. */
    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int err = getaddrinfo(server, serv, &hints, &ai);
    if (err != 0)
    {
        goto Done;
    }

    /* Create connection. */
    s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (s == INVALID_SOCKET)
    {
        goto Done;
    }
    if (connect(s, ai->ai_addr, (int)(ai->ai_addrlen)) == SOCKET_ERROR)
    {
        goto Done;
    }

    /* Send a message, prefixed by its size. */
    const char* message = "Hello, world!";
    printf("Sending message: %s\n", message);
    int messageLength = (int)strlen(message);
    int netMessageLength = (int)htonl((uint32_t)messageLength);
    int bytesSent =
        send(s, (char*)&netMessageLength, sizeof(netMessageLength), 0);
    if (bytesSent == SOCKET_ERROR)
    {
        goto Done;
    }
    bytesSent = send(s, message, messageLength, 0);
    if (bytesSent == SOCKET_ERROR)
    {
        goto Done;
    }

    /* Receive a text reply, prefixed by its size. */
    int replyLength;
    char reply[80];
    int bytesReceived =
        (int)recv(s, (char*)&replyLength, sizeof(replyLength), MSG_WAITALL);
    if (bytesReceived == SOCKET_ERROR)
    {
        goto Done;
    }
    replyLength = (int)ntohl((uint32_t)replyLength);
    if ((size_t)replyLength > sizeof(reply) - 1)
    {
        goto Done;
    }
    bytesReceived = (int)(recv(s, reply, (size_t)replyLength, MSG_WAITALL));
    if (bytesReceived != bytesSent)
    {
        goto Done;
    }

    /* Add null termination. */
    reply[replyLength] = 0;

    /* Print the reply. */
    printf("Received reply: %s\n", reply);

    status = OE_OK;

Done:
    if (s != INVALID_SOCKET)
    {
        printf("Client closing socket\n");        
        closesocket(s);
    }
    if (ai != NULL)
    {
        freeaddrinfo(ai);
    }
    return status;
}

/* This server acts as an echo server.  It accepts a connection,
 * receives messages, and echoes them back.
 */
int ecall_run_server(char* serv)
{
    int status = OE_FAILURE;
    struct addrinfo* ai = NULL;
    SOCKET listener = INVALID_SOCKET;
    SOCKET s = INVALID_SOCKET;

    /* Resolve service name. */
    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    int err = getaddrinfo(NULL, serv, &hints, &ai);
    if (err != 0)
    {
        goto Done;
    }

    /* Create listener socket. */
    listener = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (listener == INVALID_SOCKET)
    {
        goto Done;
    }
    if (bind(listener, ai->ai_addr, (int)(ai->ai_addrlen)) == SOCKET_ERROR)
    {
        goto Done;
    }
    if (listen(listener, SOMAXCONN) == SOCKET_ERROR)
    {
        goto Done;
    }
    printf("Listening on %s...\n", serv);

    /* Accept a client connection. */
    struct sockaddr_storage addr;
    int addrlen = sizeof(addr);
    s = accept(listener, (struct sockaddr*)&addr, &addrlen);
    if (s == INVALID_SOCKET)
    {
        goto Done;
    }

    /* Receive a text message, prefixed by its size. */
    int netMessageLength;
    int messageLength;
    char message[80];
    int bytesReceived = (int)(recv(
        s, (char*)&netMessageLength, sizeof(netMessageLength), MSG_WAITALL));
    if (bytesReceived == SOCKET_ERROR)
    {
        goto Done;
    }
    messageLength =(int)ntohl((uint32_t)netMessageLength);
    if ((size_t)messageLength > sizeof(message))
    {
        goto Done;
    }
    bytesReceived = (int)(recv(s, message, (size_t)messageLength, MSG_WAITALL));
    if (bytesReceived != messageLength)
    {
        goto Done;
    }

    /* Send it back to the client, prefixed by its size. */
    int bytesSent =
        send(s, (char*)&netMessageLength, sizeof(netMessageLength), 0);
    if (bytesSent == SOCKET_ERROR)
    {
        goto Done;
    }
    bytesSent = send(s, message, messageLength, 0);
    if (bytesSent == SOCKET_ERROR)
    {
        goto Done;
    }
    status = OE_OK;

Done:
    if (s != INVALID_SOCKET)
    {
        printf("Server closing socket\n");
        closesocket(s);
    }
    if (listener != INVALID_SOCKET)
    {
        printf("Server closing listener socket\n");
        closesocket(listener);
    }
    if (ai != NULL)
    {
        freeaddrinfo(ai);
    }
    return status;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    256,  /* HeapPageCount */
    256,  /* StackPageCount */
    1);   /* TCSCount */
