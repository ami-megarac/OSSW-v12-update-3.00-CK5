/****************************************************************************\
**
** fit_rsa.c
**
** Defines functionality for rsa verification process. 
** 
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

/* Required Includes ********************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#include <string.h>

#ifdef FIT_USE_RSA_SIGNING

#include "fit_rsa.h"
#include "fit_debug.h"
#include "fit_internal.h"
#include "fit_mem_read.h"
#include "fit_dm_hash.h"
#include "fit_abreast_dm.h"
#include "fit_parser.h"
#include "mbedtls/pk.h"
#ifdef FIT_USE_MULTI_THREAD
#include "fit_mutex.h"
#endif // #ifdef FIT_USE_MULTI_THREAD

#define LM_VERSION(major, minor) (((major << 8) | minor))


/* Global Data  *************************************************************/

/* This will contain data related to whether RSA verification is done or not.*/
//disable lint warning - we need exported in case of testing
fit_cache_data_t fit_cache = { FIT_FALSE,{ 0 } }; //lint !e765

#ifdef FIT_USE_MULTI_THREAD
extern fit_mutex_t fit_mutex;
#endif // #ifdef FIT_USE_MULTI_THREAD

/* Function Definitions *****************************************************/

/**
 *
 * fit_validate_rsa_signature
 *
 * This function is to validate rsa signature and hash against rsa public key.
 * Returns FIT_STATUS_INVALID_V2C or FIT_STATUS_OK
 *
 * @param   signature   --> fit_pointer to the signature (part of license)
 * @param   hash        --> RAM pointer to hash to be verified
 * @param   key         --> fit_pointer to RSA public key
 *
 */
fit_status_t fit_validate_rsa_signature(const fit_pointer_t *signature,
                                        const uint8_t       *hash,
                                        const fit_pointer_t *key,
                                        uint16_t required_lm_version)
{
#ifdef FIT_USE_RSA_SIGNING
    uint8_t *temp;
    uint16_t i;
    int  ret = 0;
    fit_status_t status = FIT_STATUS_OK;
    mbedtls_pk_context pk = {0};

    mbedtls_pk_init( &pk );

    /* read pubkey into RAM */
    temp = fit_calloc(1, key->length+1);
    if (NULL == temp) {
        status = FIT_STATUS_INSUFFICIENT_MEMORY;
		// footprint optimization - keep goto
        goto exit; //lint !e801
    }

    for (i = 0; i < key->length; i++)
    {
        temp[i] = key->read_byte(key->data + i);
    }

#ifdef FIT_USE_PEM
    ret = mbedtls_pk_parse_public_key( &pk, (const unsigned char *)temp,
                key->length + 1);
#else
    {
      uint8_t *p = temp;
      ret = mbedtls_pk_parse_subpubkey( &p, p + key->length, &pk );
    }
#endif

    fit_free(temp);
    if (ret)
    {
        DBG(FIT_TRACE_ERROR, "[fit_validate_rsa_signature] parsing public key "
            "FAILED -0x%04x\n", -ret);
        status = FIT_STATUS_INVALID_SIGNING_KEY;
		//footprint optimization - keep goto
        goto exit; //lint !e801
    }
    DBG(FIT_TRACE_INFO, "[fit_validate_rsa_signature] public key is accepted\n" );

    /* read signature from license memory */
    temp = fit_calloc(1, FIT_RSA_SIG_SIZE);
    if (NULL == temp) {
        status = FIT_STATUS_INSUFFICIENT_MEMORY;
		//footprint optimization - keep goto
		goto exit; //lint !e801
    }
    for (i = 0; i < FIT_RSA_SIG_SIZE; i++)
    {
        temp[i] = signature->read_byte(signature->data + i);
    }

    // if required lm version is less than 1.40, then use SHA256 as a hashing algorithm.
    // mbedtls signing/verification function does not perform hashing inside the sign/verification
    // function. FIT 1.3 specifies the wrong hashing algorithm information while signing, this leads
    // to a signature packed with wrong hashing algorithm and hence other standard crypto libraries
    // that performs hashing inside the sign verification function can't validate the FIT 1.3 signature.
    if (required_lm_version < LM_VERSION(1, 40)) {
        ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, FIT_ABREAST_DM_HASH_SIZE,
                temp, FIT_RSA_SIG_SIZE);
    }
    else {
        ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_NONE, hash, FIT_ABREAST_DM_HASH_SIZE,
                temp, FIT_RSA_SIG_SIZE);
    }
    fit_free(temp);
    if (ret)
    {
        DBG(FIT_TRACE_ERROR, "[fit_validate_rsa_signature] verify FAILED -0x%04x\n", -ret);
        status = FIT_STATUS_INVALID_SIGNATURE;
		//footprint optimization - keep goto
        goto exit; //lint !e801
    }

    DBG(FIT_TRACE_INFO, "[fit_validate_rsa_signature] verify OK\n" );

 exit:
    mbedtls_pk_free( &pk );
    return status;
#else
    return FIT_STATUS_OK;
#endif
}

/**
 *
 * \skip fit_verify_rsa_signature
 *
 * This function is used to validate following:
 *      1. RSA signature of new license.
 *      2. New license node lock verification.
 *
 * @param IN    license     \n Pointer to fit_pointer_t structure containing license
 *                             data. To access the license data in different types of
 *                             memory (FLASH, E2, RAM), fit_pointer_t is used.
 *
 * @param IN    key     \n Pointer to fit_pointer_t structure containing rsa public key.
 *                         To access the rsa key data in different types of memory
 *                         (FLASH, E2, RAM), fit_pointer_t is used.
 *
 * @param IN    sigdata \n license signature data.
 *
 * @param IN    check_cache \n FIT_TRUE if RSA verification is already done; FIT_FALSE
 *                             otherwise.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_verify_rsa_signature(fit_pointer_t *license,
                                      fit_pointer_t *key,
                                      const fit_pointer_t *sigdata,
                                      fit_boolean_t check_cache)
{
    fit_status_t status             = FIT_STATUS_UNKNOWN_ERROR;
    uint8_t dmhash[FIT_DM_HASH_SIZE] = {0};
    fit_pointer_t fitptr    = {0};

    DBG(FIT_TRACE_INFO, "[fit_verify_rsa_signature]: license=0x%p length=%hd\n",
        license->data, license->length);
    (void)fit_memset((uint8_t *)&fitptr, 0, sizeof(fit_pointer_t));
    (void)fit_memset(dmhash, 0, sizeof(dmhash));

    fitptr.read_byte = license->read_byte;

#ifdef FIT_USE_MULTI_THREAD
    (void)FIT_MUTEX_LOCK(&fit_mutex);
#endif // #ifdef FIT_USE_MULTI_THREAD

    /* Check validity of license data by RSA signature check.*/
    if ((fit_cache.rsa_check_done == FIT_TRUE) && (check_cache == FIT_TRUE))
    {
        /* Calculate Davies-Meyer-hash on the license. Write that hash into the
         * hash table.
         */
        fitptr.data = (uint8_t *) license->data;
        fitptr.length = license->length;
        /* Get the hash of data.*/
        status = fit_davies_meyer_hash(&fitptr, key, (uint8_t *)dmhash);
        if (status != FIT_STATUS_OK)
        {
            DBG(FIT_TRACE_ERROR, "Error in getting Davies Meyer hash with status"
                " %d\n", (unsigned int)status);
			//footprint optimization - keep goto
            goto bail; //lint !e801
        }
        /*
         * If calculated hash does not match with stored hash then perform license
         * validation again. 
         */
        if(fit_sec_memcmp(fit_cache.dm_hash, dmhash, FIT_DM_HASH_SIZE) != 0 )
        {
            status = fit_lic_do_rsa_verification(license, key, sigdata);
        }
    }
    else
    {
        status = fit_lic_do_rsa_verification(license, key, sigdata);
    }

    /* Check the result of license validation */
    if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_CRITICAL, "fit_verify_rsa_signature failed with error "
            "code %d\n", (unsigned int)status);
		//footprint optimization - keep goto
        goto bail; //lint !e801
    }
    else
    {
        DBG(FIT_TRACE_INFO, "fit_verify_rsa_signature successfully passed \n");
    }

    /* Validate fingerprint information present in the license */
    status = fit_validate_fp_data(license);
     if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_CRITICAL, "fit_validate_fp_data failed with error code %d\n",
            (unsigned int)status);
		//footprint optimization - keep goto
        goto bail; //lint !e801
    }

bail:
#ifdef FIT_USE_MULTI_THREAD
    (void)FIT_MUTEX_UNLOCK(&fit_mutex);
#endif // #ifdef FIT_USE_MULTI_THREAD

    if (status != FIT_STATUS_OK)
    {
        fit_cache.rsa_check_done = FIT_FALSE;
        (void)fit_memset(fit_cache.dm_hash, 0, sizeof(fit_cache.dm_hash));
    }
    return status;
}

/**
 *
 * fit_lic_do_rsa_verification
 *
 * This function will be used to validate license string. It will perform following
 * operations
 *
 * A) Check RSA signature:
 *      Calculate Hash of the license by Abreast-DM
 *      Validate RSA signature by RSA public key and license hash.
 * B) If the RSA signature has been verified, update the Hash table in RAM:
 *      Calculate Davies-Meyer-hash on the license
 *      Write that hash into the hash table.
 *
 * @param IN    license \n Pointer to fit_pointer_t structure that contains license
 *                         data that need to be validated for RSA decryption. To
 *                         access the license data in different types of memory
 *                         (FLASH, E2, RAM), fit_pointer_t is used.
 *
 * @param IN    rsakey  \n Pointer to fit_pointer_t structure that contains rsa
 *                         public key in binary format. To access the RSA public
 *                         key in different types of memory (FLASH, E2, RAM),
 *                         fit_pointer_t is used.
 *
 * @param IN    signature \n license signature data.
 *
 */
fit_status_t fit_lic_do_rsa_verification(fit_pointer_t* license,
                                         fit_pointer_t* rsakey,
                                         const fit_pointer_t *signature)
{
    fit_status_t status           = FIT_STATUS_UNKNOWN_ERROR;
    fit_pointer_t licaddr = {0};
    uint8_t abreasthash[FIT_ABREAST_DM_HASH_SIZE] = {0};
    uint8_t dmhash[FIT_DM_HASH_SIZE] = {0};
    uint16_t required_lm_version = 0;

    DBG(FIT_TRACE_INFO, "[fit_lic_do_rsa_verification]: Entry.\n");

    (void)fit_memset((uint8_t *)&licaddr, 0, sizeof(fit_pointer_t));
    (void)fit_memset(abreasthash, 0, sizeof(abreasthash));
    (void)fit_memset(dmhash, 0, sizeof(dmhash));

    licaddr.read_byte = license->read_byte;

    /*
     * Step 1:  Calculate Hash of the license by Abreast-DM
     * Get address and length of license part in binary.
     */
    status = fit_get_license_part_data(license,&licaddr.length,&licaddr.data);

    if (status != FIT_STATUS_OK)
    {
		//footprint optimization - keep goto
        goto bail; //lint !e801
    }

    /* Get Abreast DM hash of the license */
    status = fit_get_abreastdm_hash(&licaddr, abreasthash);

    if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_CRITICAL, "Error in getting AbreastDM hash, status = %d\n",
            (unsigned int)status);
		//footprint optimization - keep goto
        goto bail; //lint !e801
    }
    else
    {
        DBG(FIT_TRACE_INFO, "Got AbreastDM hash successfully. \n");
    }

    status = fit_read_word_safe(license->data+2, license->read_byte, license,
        &required_lm_version);
    if (status != FIT_STATUS_OK)
    {
		//footprint optimization - keep goto
        goto bail; //lint !e801
    }

    /* Step 2: Validate RSA signature by RSA public key and license hash.*/
    status = fit_validate_rsa_signature(signature, abreasthash, rsakey, required_lm_version);
    if (status != FIT_STATUS_OK) {  
		//footprint optimization - keep goto
        goto bail; //lint !e801
    }

    /* Calculate Davies-Meyer-hash on the license. Write that hash into the hash table.*/
    status = fit_davies_meyer_hash(license, rsakey, (uint8_t *)dmhash);
    if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_ERROR, "Error in getting Davies Meyer hash with status %d\n",
            (unsigned int)status);
		//footprint optimization - keep goto
        goto bail; //lint !e801
    }

    fit_cache.rsa_check_done = FIT_TRUE;
    if (fit_memcpy(fit_cache.dm_hash, FIT_DM_HASH_SIZE, dmhash, FIT_DM_HASH_SIZE) != 0)
    {
        return FIT_STATUS_BUFFER_OVERRUN;
    }

bail:
    DBG(FIT_TRACE_INFO, "[fit_lic_do_rsa_verification]: Exit.\n");

    return status;
}

#ifdef FIT_USE_UNIT_TESTS
void fit_clear_cache_data(void)
{
	(void)memset(&fit_cache, 0, sizeof(fit_cache_data_t));
}
#endif //#ifdef FIT_USE_UNIT_TESTS


#endif // #ifdef FIT_USE_RSA_SIGNING
