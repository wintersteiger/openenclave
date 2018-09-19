// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "crypto.h"
#include <openenclave/enclave.h>
#include <stdlib.h>
#include <string.h>

Crypto::Crypto()
{
    m_initialized = InitializeMbedtls();
}

Crypto::~Crypto()
{
    CleanupMbedtls();
}

/**
 * InitializeMbedtls initializes the crypto module.
 * mbedtls initialization. Please refer to mbedtls documentation for detailed
 * information about the functions used.
 */
bool Crypto::InitializeMbedtls(void)
{
    bool ret = false;
    int res = -1;

    mbedtls_ctr_drbg_init(&m_ctr_drbg_context);
    mbedtls_entropy_init(&m_entropy_context);
    mbedtls_pk_init(&m_rsa_context);

    // Initialize entropy.
    res = mbedtls_ctr_drbg_seed(
        &m_ctr_drbg_context, mbedtls_entropy_func, &m_entropy_context, NULL, 0);
    if (res != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_ctr_drbg_seed failed.");
        goto exit;
    }

    // Initialize RSA context.
    res = mbedtls_pk_setup(
        &m_rsa_context, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (res != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_pk_setup failed (%d).", res);
        goto exit;
    }

    // Generate an ephemeral 2048-bit RSA key pair with
    // exponent 65537 for the enclave.
    res = mbedtls_rsa_gen_key(
        mbedtls_pk_rsa(m_rsa_context),
        mbedtls_ctr_drbg_random,
        &m_ctr_drbg_context,
        2048,
        65537);
    if (res != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_rsa_gen_key failed (%d)\n", res);
        goto exit;
    }

    // Write out the public key in PEM format for exchange with other enclaves.
    res = mbedtls_pk_write_pubkey_pem(
        &m_rsa_context, m_my_public_key, sizeof(m_my_public_key));
    if (res != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_pk_write_pubkey_pem failed (%d)\n", res);
        goto exit;
    }
    ret = true;
    ENC_DEBUG_PRINTF("mbedtls initialized.");
exit:
    return ret;
}

/**
 * mbedtls cleanup during shutdown.
 */
void Crypto::CleanupMbedtls(void)
{
    mbedtls_pk_free(&m_rsa_context);
    mbedtls_entropy_free(&m_entropy_context);
    mbedtls_ctr_drbg_free(&m_ctr_drbg_context);

    ENC_DEBUG_PRINTF("mbedtls cleaned up.");
}

/**
 * Get the public key for this enclave.
 */
void Crypto::RetrievePublicKey(uint8_t pem_public_key[512])
{
    memcpy(pem_public_key, m_my_public_key, sizeof(m_my_public_key));
}

/**
 * Compute the sha256 hash of given data.
 */
void Crypto::Sha256(const uint8_t* data, size_t data_size, uint8_t sha256[32])
{
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, data, data_size);
    mbedtls_sha256_finish_ret(&ctx, sha256);
}

/**
 * Encrypt encrypts the given data using the given public key.
 * Used to encrypt data using the public key of another enclave.
*/
bool Crypto::Encrypt(
    const uint8_t* pem_public_key,
    const uint8_t* data,
    size_t data_size,
    uint8_t* encrypted_data,
    size_t* encrypted_data_size)
{
    bool result = false;
    mbedtls_pk_context key;
    size_t key_size = 0;
    int res = -1;

    mbedtls_pk_init(&key);

    if (!m_initialized)
        goto done;

    // Read the given public key.
    key_size = strlen((const char*)pem_public_key) + 1; // Include ending '\0'.
    res = mbedtls_pk_parse_public_key(&key, pem_public_key, key_size);
    if (res != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_pk_parse_public_key failed.");
        goto done;
    }

    // Encrypt the data.
    res = mbedtls_rsa_pkcs1_encrypt(
        mbedtls_pk_rsa(key),
        mbedtls_ctr_drbg_random,
        &m_ctr_drbg_context,
        MBEDTLS_RSA_PUBLIC,
        data_size,
        data,
        encrypted_data);

    if (res != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_rsa_pkcs1_encrypt failed.");
        goto done;
    }

    *encrypted_data_size = mbedtls_pk_rsa(key)->len;

    result = true;
done:
    mbedtls_pk_free(&key);
    return result;
}

/**
 * Decrypt decrypts the given data using current enclave's private key.
 * Used to receive encrypted data from another enclave.
 */
bool Crypto::Decrypt(
    const uint8_t* encrypted_data,
    size_t encrypted_data_size,
    uint8_t* data,
    size_t* data_size)
{
    bool ret = false;
    size_t output_size = 0;
    int res = 0;

    if (!m_initialized)
        goto exit;

    mbedtls_pk_rsa(m_rsa_context)->len = encrypted_data_size;

    output_size = *data_size;
    res = mbedtls_rsa_pkcs1_decrypt(
        mbedtls_pk_rsa(m_rsa_context),
        mbedtls_ctr_drbg_random,
        &m_ctr_drbg_context,
        MBEDTLS_RSA_PRIVATE,
        &output_size,
        encrypted_data,
        data,
        output_size);
    if (res != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_rsa_pkcs1_decrypt failed.");
        goto exit;
    }
    *data_size = output_size;
    ret = true;

exit:
    return ret;
}