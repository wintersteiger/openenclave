// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <openenclave/bits/safecrt.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
#include <openenclave/internal/enclavelibc.h>

// Using mbedtls to create an extended X.509 certificate
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509.h>
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <mbedtls/oid.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>

#define PUBLIC_KEY_SIZE     512
#define SHA256_DIGEST_SIZE  32

static unsigned char oid_oe_report[] = {0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x8A, 0x39, 0x01};
static int _extract_x509_extension
(   uint8_t* ext3_data,
    size_t exts_data_len,
    const uint8_t* report_oid,
    size_t report_oid_len,
    uint8_t** report_data,
    size_t* report_data_size
)
{
    int ret = 1;
    unsigned char *p = NULL;
    const unsigned char *end = NULL;
    mbedtls_x509_buf oid = {0, 0, NULL};
    size_t len = 0;

 
//TODO: 
// Should make this extension a critical one!

    p = (unsigned char *)ext3_data + 83; // need to find out why it;s 83!
    end = p + exts_data_len;

    // Search for target report OID
    while (p < end)
    {
        // Get extension OID ID
        if( ( ret = mbedtls_asn1_get_tag( &p, end, &oid.len,
                                            MBEDTLS_ASN1_OID ) ) != 0 )
            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );

        if (oid.len == report_oid_len)
        {
            oid.tag = MBEDTLS_ASN1_OID;
            oid.p = p;

            if (0 == oe_memcmp(oid.p, report_oid, report_oid_len)) 
            {
                p += report_oid_len;
                // Read the octet string tag, length encoded in two bytes
                ret = mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_OCTET_STRING);
                if (ret)
                {
                    OE_TRACE_ERROR("ret=%d", ret);
                    goto done;
                }
                *report_data = p;
                *report_data_size = len;
                OE_TRACE_INFO("report_data_size = %d", *report_data_size);
                OE_TRACE_INFO("report_data = %p report_data[0]=0x%x  report_data_size=%d", *report_data, **report_data, *report_data_size);
                ret = 0;
                break;
            }
        }
        *p += oid.len;
    }
done:
    if (ret)
        OE_TRACE_ERROR("Expected x509 report extension not found");

    return ret;
}

static oe_result_t extract_x509_report_extension
(   mbedtls_x509_crt *crt,
    uint8_t** report_data,
    size_t* report_data_size
)
{
    oe_result_t result = OE_FAILURE;
    int ret = 0;

    ret = _extract_x509_extension(crt->v3_ext.p,
                                crt->v3_ext.len,
                                oid_oe_report,
                                sizeof(oid_oe_report),
                                report_data,
                                report_data_size);
    if (ret)
        OE_RAISE(OE_FAILURE, "ret = %d", ret);

    OE_TRACE_INFO("report_data = %p report_data[0]=0x%x report_data_size=%d", *report_data, **report_data, *report_data_size);
    result = OE_OK;

done:
    return result;
}

static int Sha256(const uint8_t* data, size_t data_size, uint8_t sha256[32])
{
    int ret = 0;
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);

    ret = mbedtls_sha256_starts_ret(&ctx, 0);
    if (ret)
        goto exit;

    ret = mbedtls_sha256_update_ret(&ctx, data, data_size);
    if (ret)
        goto exit;

    ret = mbedtls_sha256_finish_ret(&ctx, sha256);
    if (ret)
        goto exit;

exit:
    mbedtls_sha256_free(&ctx);
    return ret;
}

// verify report data against peer certificate
oe_result_t verify_report_user_data(mbedtls_x509_crt* crt, uint8_t*  report_data)
{
    oe_result_t result = OE_FAILURE;
    int ret = 0;
    uint8_t pk_buf[PUBLIC_KEY_SIZE];
    uint8_t sha256[SHA256_DIGEST_SIZE];

    oe_memset(pk_buf, 0, sizeof(pk_buf));
    ret  = mbedtls_pk_write_pubkey_pem(&crt->pk, pk_buf, sizeof(pk_buf));
    if (ret)
        OE_RAISE_MSG(OE_FAILURE, "ret = %d", ret);

    oe_memset(sha256, 0, SHA256_DIGEST_SIZE);
    Sha256(pk_buf, sizeof(pk_buf), sha256);

    OE_TRACE_VERBOSE("public key from the peer certificate =\n[%s]", pk_buf);
    for (size_t i=0; i<sizeof(sha256); i++)
    {
        OE_TRACE_VERBOSE("sha256[%d]=0x%x", i, sha256[i]);
    }

    // validate report's user data which contains hash(public key)
    if (oe_memcmp(report_data, sha256, SHA256_DIGEST_SIZE) != 0)
    {
        for (int i=0; i<SHA256_DIGEST_SIZE; i++)
            OE_TRACE_ERROR("[%d] report_data[0x%x] sha256=0x%x ", i, report_data[i], sha256[i]);
        OE_RAISE_MSG(OE_VERIFY_FAILED, "hash of peer certificate's public key does not match report data", NULL);
    }

    OE_TRACE_INFO("Report user data validation passed");
    result = OE_OK;
done:
    return result;
}

oe_result_t verify_cert_signature( mbedtls_x509_crt *crt)
{
    oe_result_t result = OE_FAILURE;

    (void)crt;


    result = OE_OK;
//done:
    return result;
}

oe_result_t oe_verify_tls_cert( uint8_t* cert_in_der, size_t cert_in_der_len, 
                                oe_enclave_identity_verify_callback_t enclave_identity_callback)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* report = NULL;
    size_t report_size = 0;
    oe_report_t parsed_report = {0};
    int ret;    
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);

    // create a mbedtls cert object from encoded cert data in DER format
    ret = mbedtls_x509_crt_parse(&crt, cert_in_der, cert_in_der_len);
    if (ret)
        OE_RAISE_MSG(OE_FAILURE, "ret = %d", ret);

    // validate the certificate signature
    //result = verify_cert_signature(cert);
    //OE_CHECK(result);

    OE_CHECK(extract_x509_report_extension(&crt, &report, &report_size));

    OE_TRACE_INFO("extract_x509_report_extension() succeeded");
    OE_TRACE_INFO("report = %p report[0]=0x%x report_size=%d", report, *report, report_size);

    // 1)  Validate the report's trustworthiness
    // Verify the remote report to ensure its authenticity.
    // set enclave to NULL because we are dealing only with remote report now

    result = oe_verify_report(report, report_size, &parsed_report);
    OE_CHECK(result);
    OE_TRACE_INFO("oe_verify_report() succeeded");

    // verify report size and type
    if (parsed_report.size != sizeof(oe_report_t))
        OE_RAISE_MSG(OE_VERIFY_FAILED, "Unexpected parsed_report.size: %d (expected value:%d) ", parsed_report.size, sizeof(oe_report_t));

    if (parsed_report.type != OE_ENCLAVE_TYPE_SGX)
        OE_RAISE_MSG(OE_VERIFY_FAILED, "Report type is not supported: parsed_report.type (%d)", parsed_report.type);

    // verify report's user data
    result = verify_report_user_data(&crt, parsed_report.report_data);
    OE_CHECK(result);

    // callback to the caller to verity enclave identity
    if (enclave_identity_callback)
    {
        result = enclave_identity_callback(&parsed_report.identity);
        OE_CHECK(result);
        OE_TRACE_INFO("enclave_identity_callback() succeeded");
    }
    else
    {
        OE_TRACE_WARNING("No enclave_identity_callback provided in oe_verify_tls_cert call", NULL);
    }
done:
    mbedtls_x509_crt_free(&crt);
    return result;
}