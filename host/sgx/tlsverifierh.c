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
#include <openssl/pem.h>
#include <openssl/x509.h>

#define PUBLIC_KEY_SIZE     512
#define SHA256_DIGEST_SIZE  32


// TODO: move this to shared library
// verify report data against peer certificate
oe_result_t verify_report_user_data(uint8_t *key_buff, uint8_t*  report_data);
oe_result_t get_public_key_from_cert(X509* cert, uint8_t *key_buff, size_t *key_size);
oe_result_t verify_cert(X509 *cert);

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

// #define OID(N) {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x8A, 0x39, (N)}
// const uint8_t ias_response_body_oid[]    = OID(0x02);
// const uint8_t ias_root_cert_oid[]        = OID(0x03);
// const uint8_t ias_leaf_cert_oid[]        = OID(0x04);
// const uint8_t ias_report_signature_oid[] = OID(0x05);

static oe_result_t extract_x509_report_extension
(
    const X509* crt,
    uint8_t** ext_data,
    size_t* ext_data_size
)
{   
    oe_result_t result = OE_FAILURE;

    result = get_extension(crt, oid_oe_report, sizeof(oid_oe_report), ext_data, ext_data_size);
    OE_CHECK(result);

    if (*ext_data_size != 0)
        result = OE_OK;

done:
    return result;
}

oe_result_t verify_cert(X509 *cert)
{
    oe_result_t result=OE_VERIFY_FAILED;
     int ret = 0;
     X509_STORE *store = 0;
     X509_STORE_CTX *ctx = 0;

     store = X509_STORE_new();
     //X590_STORE_add_cert(store, cacert);
     ctx = X509_STORE_CTX_new();
     X509_STORE_CTX_init(ctx, store, cert, NULL);

     ret = X509_verify_cert(ctx);
     if (ret != 1)
     {
        OE_TRACE_ERROR("X590_verify_cert failed", NULL);
        goto done;
     }
     result = OE_OK;
done:
    return result;
}

oe_result_t verify_report_user_data(uint8_t *key_buff, uint8_t*  report_data)
{
    oe_result_t result = OE_FAILURE;
    OE_SHA256 sha256;
    oe_sha256_context_t sha256_ctx = {0};

    OE_CHECK(oe_sha256_init(&sha256_ctx));
    OE_CHECK(oe_sha256_update(&sha256_ctx, key_buff, PUBLIC_KEY_SIZE));
    OE_CHECK(oe_sha256_final(&sha256_ctx, &sha256));

    if (memcmp(report_data, (uint8_t*)&sha256, SHA256_DIGEST_SIZE) != 0)
    {
       OE_RAISE_MSG(OE_VERIFY_FAILED, "hash of peer certificate's public key does not match report data", NULL);
    }
    OE_TRACE_INFO("report data validation passed", NULL);

    result = OE_OK;
done:
    return result;
}
oe_result_t get_public_key_from_cert(X509* cert, uint8_t *key_buff, size_t *key_size)
{
    oe_result_t result = OE_FAILURE;
    EVP_PKEY *pkey = NULL;
    BIO *bio_mem = BIO_new(BIO_s_mem());
    int bio_len = 0;
    int ret = 0;

    // Extract the certificate's public key
    if ((pkey = X509_get_pubkey(cert)) == NULL)
        OE_RAISE(result, "Error getting public key from certificate", NULL);

    OE_TRACE_INFO("extract_x509_report_extension() succeeded");

    /* ---------------------------------------------------------- *
    * Print the public key information and the key in PEM format *
    * ---------------------------------------------------------- */
    // display the key type and size  in PEM format
    if (pkey) {
        switch (pkey->type) {
        case EVP_PKEY_RSA:
            OE_TRACE_INFO("%d bit RSA Key\n\n", EVP_PKEY_bits(pkey));
            break;
        case EVP_PKEY_DSA:
            OE_TRACE_INFO("%d bit DSA Key\n\n", EVP_PKEY_bits(pkey));
            break;
        default:
            OE_TRACE_INFO("%d bit  non-RSA/DSA Key\n\n", EVP_PKEY_bits(pkey));
            break;
        }
    }

    if(!PEM_write_bio_PUBKEY(bio_mem, pkey))
        OE_RAISE(OE_FAILURE, "Error writing public key data in PEM format", NULL);

    bio_len = BIO_pending(bio_mem);
    ret = BIO_read(bio_mem, key_buff, bio_len);
    if (ret != bio_len)
    {
        // that no data was successfully read or written if the result is 0 or -1. If the return value is -2
        // then the operation is not implemented in the specific BIO type.
        OE_RAISE(result, "BIO_read key data failed ret = %d", ret);
    }
    // Insert the NUL terminator
    key_buff[bio_len] = '\0';

    OE_TRACE_INFO("public key from cert:\n[%s]\n", key_buff);
    *key_size = (size_t)bio_len;
    result = OE_OK;
done:
    BIO_free_all(bio_mem);
    EVP_PKEY_free(pkey);

    return result;
}
oe_result_t oe_verify_tls_cert( uint8_t* cert_in_der, size_t cert_in_der_len, 
                                oe_enclave_identity_verify_callback_t enclave_identity_callback)
{
    oe_result_t result = OE_FAILURE;
    const unsigned char* p = cert_in_der;
    X509* cert = NULL;
    uint8_t* report = NULL;
    size_t report_size = 0;
    uint8_t pub_key_buf[PUBLIC_KEY_SIZE];
    size_t pub_key_buf_size = 0;
    oe_report_t parsed_report = {0};

    //  OpenSSL_add_all_algorithms();
    //   ERR_load_BIO_strings();
    //   ERR_load_crypto_strings();

    // create a OpenSSL cert object from encoded cert data in DER format
    cert = d2i_X509(NULL, &p, (uint32_t)cert_in_der_len);
    if (cert == NULL)
        OE_RAISE(result, "d2i_X509 failed err=[%s]", ERR_error_string(ERR_get_error(), NULL));

    // validate the certificate signature

    //result = verify_cert(cert);
    //OE_CHECK(result);

    //------------------------------------------------------------------------
    // Validate the report's trustworthiness
    // Verify the remote report to ensure its authenticity.
    // set enclave to NULL because we are dealing only with remote report now
    //------------------------------------------------------------------------
    result = extract_x509_report_extension(cert, &report, &report_size);
    OE_CHECK(result);
    OE_TRACE_INFO("extract_x509_report_extension() succeeded");

    result = oe_verify_report(NULL, report, report_size, &parsed_report);
    OE_CHECK(result);
    OE_TRACE_INFO("oe_verify_report() succeeded");

    //--------------------------------------
    // verify report data: hash(public key)
    //--------------------------------------

    // extract public key from the cert
    oe_memset_s(pub_key_buf, sizeof(pub_key_buf), 0, sizeof(pub_key_buf));
    result = get_public_key_from_cert(cert, pub_key_buf, &pub_key_buf_size);
    OE_CHECK(result);

    // verify report data against peer certificate
    result = verify_report_user_data(pub_key_buf, parsed_report.report_data);
    OE_CHECK(result);
    OE_TRACE_INFO("verify_report_user_data passed", NULL);

    //---------------------------------------
    // call client to check enclave identity
    // --------------------------------------
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
    if (cert)
        X509_free(cert);

    return result;
}