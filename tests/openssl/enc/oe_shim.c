#include "openssl/x509.h"
#include <stdlib.h>

X509_REQ* X509_REQ_new()
{
    return malloc(sizeof(X509_REQ));
}

void X509_REQ_free(X509_REQ* req)
{
    free(req);
}
