/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdarg.h>

typedef enum {
    OE_NETWORK_UNTRUSTED = 0,
    OE_NETWORK_SECURE_HARDWARE = 1
} oe_network_security_t;

//typedef void* oe_socket_t;
typedef int oe_socket_t;

#ifndef FD_SETSIZE
#define FD_SETSIZE 64
#endif /* FD_SETSIZE */

typedef struct oe_fd_set
{
    unsigned int fd_count;            /* how many are SET? */
    oe_socket_t fd_array[FD_SETSIZE]; /* an array of SOCKETs */
} oe_fd_set;

typedef uint16_t oe_sa_family_t;
typedef int oe_socklen_t;

//================================================================
// forward declaration for OE  socket  functions
int oe_getaddrinfo(
    oe_network_security_t network_security,
    const char* node,
    const char* service,
    const struct addrinfo* hints,
    struct addrinfo** res);

oe_socket_t oe_socket(
    oe_network_security_t network_security,
    int domain,
    int type,
    int protocol);

oe_socket_t oe_accept(
    oe_socket_t s,
    struct sockaddr* addr,
    int* addrlen);

int oe_connect(
    oe_socket_t s,
    const struct sockaddr* name,
    int namelen);

int oe_getsockopt(
    oe_socket_t s,
    int level,
    int optname,
    char* optval,
    int* optlen);

int oe_bind(
    oe_socket_t s,
    const struct sockaddr* name,
    int namelen);

 int oe_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);

 void oe_freeaddrinfo(struct addrinfo* ailist);
 int oe_listen(oe_socket_t s, int backlog);

 int oe_getpeername(
    oe_socket_t s,
    struct sockaddr* addr,
    int* addrlen);

int oe_getsockname(
    oe_socket_t s,
    struct sockaddr* addr,
    int* addrlen);
int oe_select(
    int nfds,
    oe_fd_set* readfds,
    oe_fd_set* writefds,
    oe_fd_set* exceptfds,
    const struct timeval* timeout);
ssize_t oe_recv(
    oe_socket_t s,
    void* buf,
    size_t len,
    int flags);
ssize_t oe_recvfrom( oe_socket_t sockfd, void* buf, size_t len, int flags,
                    struct sockaddr *src_addr, oe_socklen_t addrlen);
int oe_send(
    oe_socket_t s,
    const char* buf,
    int len,
    int flags);
int oe_ioctlsocket(oe_socket_t s, long cmd, u_long* argp);
int oe_closesocket(oe_socket_t s);
int oe_shutdown(oe_socket_t s, int how);
int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints,
                struct addrinfo **res)
{
    return oe_getaddrinfo(OE_NETWORK_UNTRUSTED, node, service, hints, res);
}

int socket(int domain, int type, int protocol)
{
    return (int)oe_socket(OE_NETWORK_UNTRUSTED, domain, type, protocol);
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    return (int)(oe_accept((oe_socket_t)sockfd, addr, (int *)addrlen));
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    return oe_connect((oe_socket_t)sockfd, addr, addrlen);    
}

int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
    return oe_getsockopt((oe_socket_t)sockfd, level, optname, optval, (int *)optlen);
}
            
int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
{
    return oe_setsockopt((oe_socket_t)sockfd, level, optname, optval, (int)optlen);
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    return oe_bind((oe_socket_t)sockfd, (const struct sockaddr*)addr, addrlen);
}

void freeaddrinfo(struct addrinfo *res)
{
    oe_freeaddrinfo((struct addrinfo*)res);
}

int listen(int sockfd, int backlog)
{
    return oe_listen((oe_socket_t)sockfd, backlog);
}

int oe_getpeername(
    oe_socket_t s,
    struct sockaddr* addr,
    int* addrlen);

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    return oe_getsockname((oe_socket_t) sockfd, (struct sockaddr*)addr, (int*)addrlen);
}

int select(int nfds, fd_set *readfds, fd_set *writefds,
            fd_set *exceptfds, struct timeval *timeout)
{
     return oe_select(nfds, (oe_fd_set*)readfds,
    (oe_fd_set*) writefds,
    (oe_fd_set*) exceptfds,
    (const struct timeval*) timeout);
}

ssize_t read(int sockfd, void *buf, size_t count)
{
    return oe_recv((oe_socket_t) sockfd, buf, count, 0);
}

ssize_t write(int sockfd, const void *buf, size_t count)
{
   return (ssize_t)oe_send((oe_socket_t)sockfd, (const char*) buf, (int)count, 0);   
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
    return oe_recv((oe_socket_t) sockfd, buf, len, flags);
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen)
{
    return oe_recvfrom((oe_socket_t)sockfd,
                        buf, len, flags,
                        (struct sockaddr *)src_addr,
                        (oe_socklen_t)(*addrlen));
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    return (ssize_t)oe_send((oe_socket_t)sockfd, (const char*) buf, (int)len,flags);
}

int fcntl(int sockfd, int cmd, ...)
{
	unsigned long argp;

    // retrive arg
	va_list ap;
	va_start(ap, cmd);
	argp = va_arg(ap, unsigned long);
	va_end(ap);

    // forward to oe_call
    return oe_ioctlsocket((oe_socket_t)sockfd, (long)cmd, & argp);
}

int close(int sockfd)
{
    return oe_closesocket((oe_socket_t)sockfd);
}

int shutdown(int socket, int how)
{
    return oe_shutdown((oe_socket_t)socket, how);
}

typedef void (*sighandler_t)(int);
sighandler_t signal(int signum, sighandler_t handler)
{
    // TODO: find out how to handle this signal
    (void)signum;
    (void)handler;
}


