// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/utils.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

static unsigned char oid_oe_report[] = {0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x8A, 0x39, 0x01};

// Extract extensions from X509 and decode base64
// Given an X509 extension OID, return its data
// https://zakird.com/2013/10/13/certificate-parsing-with-openssl
static oe_result_t get_extension
(
    const X509* crt,            /* in */
    const unsigned char* oid,   /* in */
    int oid_len,                /* in */
    uint8_t** data,             /* out */
    size_t* data_len           /* out */
)
{
    oe_result_t result = OE_NOT_FOUND;
    STACK_OF(X509_EXTENSION) *exts = crt->cert_info->extensions;
    X509_EXTENSION *ex = NULL;
    ASN1_OBJECT *obj = NULL;
    int extension_count = 0;

    if (exts == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    extension_count = sk_X509_EXTENSION_num(exts);
    for (int i=0; i < extension_count; i++) {
        ex = sk_X509_EXTENSION_value(exts, i);
        if (ex == NULL)
        {
            goto done;
        }
        obj = X509_EXTENSION_get_object(ex);
        if (obj == NULL)
        {
            goto done;
        }
        if (oid_len != obj->length) continue;
        
        if (0 == memcmp(obj->data, oid, (size_t)(obj->length))) {
            *data = (uint8_t *)(ex->value->data);
            *data_len = (size_t)(ex->value->length);
            result = OE_OK;
            break;
        }
    }
done:
    return result;
}

// static void get_and_decode_ext
// (
//  const X509* crt,
//  const unsigned char* oid,
//  int oid_len,
//  unsigned char* data,
//  int data_max_len,
//  unsigned int* data_len
// )
// {
//     const unsigned char* ext;
//     int ext_len;
    
//     get_extension(crt, oid, oid_len, &ext, &ext_len);
//     assert(ext_len * 3 <= data_max_len * 4);
//     int ret = EVP_DecodeBlock_wrapper(data, ext, ext_len);
    
//     assert(ret != -1);
//     *data_len = ret;
// }

// #define OID(N) {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x8A, 0x39, (N)}

// const uint8_t ias_response_body_oid[]    = OID(0x02);
// const uint8_t ias_root_cert_oid[]        = OID(0x03);
// const uint8_t ias_leaf_cert_oid[]        = OID(0x04);
// const uint8_t ias_report_signature_oid[] = OID(0x05);

// const size_t ias_oid_len = sizeof(ias_response_body_oid);
static oe_result_t extract_x509_report_extension
(
    const X509* crt,
    uint8_t** ext_data,
    size_t* ext_data_size
)
{   
    oe_result_t result = OE_FAILURE;

    // get_and_decode_ext(crt,
    //                    oid_oe_report,
    //                    sizeof(oid_oe_report),
    //                    attn_report->ias_report, 
    //                    sizeof(attn_report->ias_report),
    //                    &attn_report->ias_report_len);

    result = get_extension(crt, oid_oe_report, sizeof(oid_oe_report), ext_data, ext_data_size);
    OE_CHECK(result);

    // not sure what the following check is:
    //assert(ext_len * 3 <= data_max_len * 4);
    //int ret = EVP_DecodeBlock_wrapper(data, ext, ext_len);
    
    //assert(ret != -1);
    //*data_len = ret;

    // Assert we got all of our extensions.
    // assert(attn_report->ias_report_signature_len != 0 &&
    //        attn_report->ias_sign_cert_len != 0 &&
    //        attn_report->ias_sign_ca_cert_len != 0 &&
    //        attn_report->ias_report_len != 0);

    if (*ext_data_size != 0)
        result = OE_OK;

done:
    return result;
}

oe_result_t oe_verify_tls_cert( uint8_t* cert_in_der, size_t cert_in_der_len, 
                                tls_cert_verify_callback_t verify_enclave_identity_info_callback)
{
    oe_result_t result = OE_FAILURE;
    const unsigned char* p = cert_in_der;
    X509* cert = NULL;
    uint8_t* report = NULL;
    size_t report_size = 0;

    // create a OpenSSL cert object from encoded cert data in DER format
    cert = d2i_X509(NULL, &p, (uint32_t)cert_in_der_len);
    if (cert == NULL)
        OE_RAISE(result, "d2i_X509 failed err=[%s]", ERR_error_string(ERR_get_error(), NULL));

    result = extract_x509_report_extension(cert, &report, &report_size);
    OE_CHECK(result);
    OE_TRACE_INFO("extract_x509_report_extension() succeeded");

    // 1)  Validate the report's trustworthiness
    // Verify the remote report to ensure its authenticity.
    // set enclave to NULL because we are dealing only with remote report now
    oe_report_t parsed_report = {0};
    result = oe_verify_report(NULL, report, report_size, &parsed_report);
    OE_CHECK(result);
    OE_TRACE_INFO("oe_verify_report() succeeded");

    if (verify_enclave_identity_info_callback)
    {
        result = verify_enclave_identity_info_callback(&parsed_report);
        OE_CHECK(result);
        OE_TRACE_INFO("verify_enclave_identity_info_callback() succeeded");
    }
    else
    {
        OE_TRACE_WARNING("No verify_enclave_identity_info_callback provided in oe_verify_tls_cert call", NULL);
    }

    // verify_report_data_against_server_cert

    // ret = verify_ias_certificate_chain(&attn_report);
    // assert(ret == 0);

    // ret = verify_ias_report_signature(&attn_report);
    // assert(ret == 0);

    // ret = verify_enclave_quote_status((const char*) attn_report.ias_report,
    //                                   attn_report.ias_report_len);
    // assert(ret == 0);
    
    // sgx_quote_t quote = {0, };
    // get_quote_from_report(attn_report.ias_report,
    //                       attn_report.ias_report_len,
    //                       &quote);
    // ret = verify_report_data_against_server_cert(cert, &quote);
    // assert(ret == 0);

done:
    if (cert)
        X509_free(cert);

    return result;
}