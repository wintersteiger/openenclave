// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <mbedtls/pk.h>
// #include <mbedtls/rsa.h>
// #include <mbedtls/entropy.h>
// #include <mbedtls/ctr_drbg.h>
//#include <mbedtls/certs.h>
//#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>

#include <stdio.h>
// #include <string.h>

// #include <stdlib.h>
// #include <string.h>

// Consider to move this function into a shared directory
oe_result_t generate_certificate_and_pkey(mbedtls_x509_crt *cert, mbedtls_pk_context *private_key)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* host_cert_buf = NULL;
    uint8_t* output_cert = NULL;
    size_t output_cert_size = 0;
    uint8_t* pkey_buf = NULL;
    size_t pkey_buf_size = 0;
	int ret = 0;

    result = oe_gen_x509cert_for_TLS(OE_CERT_FORMAT_DER,
                                     &output_cert,
                                     &output_cert_size,
									 &pkey_buf,
									 &pkey_buf_size);
    if (result != OE_OK)
    {
        printf(" failed with %s\n", oe_result_str(result));
        goto exit;
    }

	// create mbedtls_x509_crt from output_cert
	ret = mbedtls_x509_crt_parse_der(cert, output_cert, output_cert_size);
    if (ret != 0)
    {
        printf(" failed with ret = %d\n", ret);
		result = OE_FAILURE;
        goto exit;
    }

	// create mbedtls_pk_context from private key data
	ret = mbedtls_pk_parse_key(	private_key,
								(const unsigned char *)pkey_buf,
								pkey_buf_size, NULL, 0);
    if (ret != 0)
    {
        printf(" failed with ret = %d\n", ret);
		result = OE_FAILURE;
        goto exit;
    }

exit:

    oe_free_key(pkey_buf, pkey_buf_size, NULL, 0);
    free(output_cert);
	return result;
}
