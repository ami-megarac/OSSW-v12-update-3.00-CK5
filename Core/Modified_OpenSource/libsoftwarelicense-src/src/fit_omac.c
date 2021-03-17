/****************************************************************************\
**
** fit_omac.c
**
** Defines functionality for implementation for OMAC algorithm
** 
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#ifdef FIT_USE_AES_SIGNING

#include <string.h> 
#include <stdio.h> 


#include "fit_omac.h"
#include "fit_debug.h"
#include "fit_internal.h"
#include "fit_parser.h"
#include "fit_mem_read.h"


static void done(uint8_t *skey)/*lint !e818 */
{
    (void)skey;
    return;
}

/**
 *
 * \skip fit_omac_init
 *
 * Initialize an OMAC state (One-key Message Authentication Code)
 * http://en.wikipedia.org/wiki/OMAC_%28cryptography%29
 *
 * @param IN    omac    \n The OMAC state to initialize.
 *
 * @param IN    aes     \n AES state.
 *
 * @param IN    cipher  \n The index of the desired cipher
 *
 * @param IN    key     \n Start address of the signing key in binary format.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
static fit_status_t fit_omac_init(omac_state_t *omac,
                           fit_aes_t *aes,
                           uint16_t blocklength,
                           const fit_pointer_t *key)
{
    fit_status_t result = FIT_STATUS_UNKNOWN_ERROR;
    uint8_t x = 0, y = 0, len;
    uint16_t mask = 0, msb = 0;

    if((key->read_byte == NULL) || (omac == NULL)) {
        return FIT_STATUS_INVALID_PARAM;
    }

    /* now setup the system */
    if (blocklength == 8) {
            mask = 0x1B;
            len = 8;
    } else if (blocklength == 16) {
            mask = 0x87;
            len = 16;
    } else {
            return FIT_STATUS_INVALID_PARAM;
    }

    result = fit_aes_setup(aes, key, omac->key);
    if (result != FIT_STATUS_OK)
    {
        return result;
    }

    (void)fit_memset((uint8_t *)omac->Lu[0], 0, blocklength);

    fit_aes_encrypt(aes, omac->Lu[0], omac->Lu[0], omac->key, (uint8_t*)(omac->state));

    /* now do the mults, whoopy! */
    for (x = 0; x < 2; x++)
    {
        /* if msb(L * u^(x+1)) = 0 then just shift, otherwise shift and xor constant mask */
        msb = omac->Lu[x][0] >> 7;

        /* shift left */
        for (y = 0; y < (len - 1); y++)
        {
            omac->Lu[x][y] = ((omac->Lu[x][y] << 1) | (omac->Lu[x][y + 1] >> 7)) & 255;
        }
        omac->Lu[x][len - 1] = ((omac->Lu[x][len - 1] << 1) ^ (msb ? mask : 0)) & 255;

        /* copy up as require */
        if (x == 0)
        {
            if (fit_memcpy(omac->Lu[1], sizeof(omac->Lu[1]), omac->Lu[0],
                sizeof(omac->Lu[0])) != 0)
            {
                return FIT_STATUS_BUFFER_OVERRUN;
            }
        }
    }

    /* setup state */
    omac->buflen = 0;
    omac->blklen = len;

    (void)fit_memset(omac->prev, 0, sizeof(omac->prev));
    (void)fit_memset(omac->block, 0, sizeof(omac->block));

    return FIT_STATUS_OK;

} /* fit_omac_init */

/**
 *
 * \skip fit_omac_process
 *
 * Process data through OMAC.
 *
 * @param IN    omac    \n The OMAC state obtained via fit_omac_init.
 *
 * @param IN    aes     \n AES state.
 *
 * @param IN    indata  \n Start address of the input data for which OMAC to be
 *                         calculated in binary format.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
static fit_status_t fit_omac_process(omac_state_t *omac,
                              const fit_aes_t *aes,
                              const fit_pointer_t *indata)
{
    uint32_t n = 0;
    uint8_t x = 0;
    fit_pointer_t input = {0};
    uint32_t inlen = indata->length;

    if ((omac->buflen > (uint8_t)sizeof(omac->block)) ||
        (omac->blklen > (uint8_t)sizeof(omac->block)) ||
        (omac->buflen > omac->blklen))
    {
        return FIT_STATUS_INVALID_PARAM;
    }

    input.data = indata->data;
    input.length = indata->length;
    input.read_byte = indata->read_byte;

    while (inlen != 0)
    {
        /* ok if the block is full we xor in prev, encrypt and replace prev */
        if (omac->buflen == omac->blklen)
        {
            for (x = 0; x < (uint8_t)omac->blklen; x++)
            {
                omac->block[x] ^= omac->prev[x];
            }

            fit_aes_encrypt(aes, omac->block, omac->prev, omac->key,
                (uint8_t*)(omac->state));
            omac->buflen = 0;
        }

        /* add bytes */

        n = fit_math_min(inlen, (uint8_t)(omac->blklen - omac->buflen));
        input.length = n;
        if (fit_fitptr_memcpy(omac->block + omac->buflen,
            OMAC_MAX_CIPHER_BLOCK_SIZE-omac->buflen, &input) != 0)/*lint !e732 */
        {
            return FIT_STATUS_BUFFER_OVERRUN;
        }

        omac->buflen  += (uint8_t)n;
        inlen -= n;
        input.data += n;
    }

    return FIT_STATUS_OK;
}

/**
 *
 * \skip fit_omac_done
 *
 * Terminate an OMAC stream.
 *
 * @param IN    omac    \n The OMAC state obtained via fit_omac_init.
 *
 * @param IN    aes     \n AES state.
 *
 * @param OUT   out     \n Contains OMAC value out of data.
 *
 * @param OUT   outlen  \n The max size and resulting size of the OMAC data.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
static fit_status_t fit_omac_done(omac_state_t *omac,
                           const fit_aes_t *aes,
                           uint8_t *out,
                           uint32_t *outlen)
{
    uint8_t mode        = 0;
    uint8_t x           = 0;
    
    if((omac->buflen > (uint8_t)sizeof(omac->block)) ||
      (omac->blklen > (uint8_t)sizeof(omac->block)) ||
      (omac->buflen > omac->blklen))
    {
        return FIT_STATUS_INVALID_PARAM;
    }

    /* figure out mode */
    if(omac->buflen != omac->blklen)
    {
        if (omac->buflen >= OMAC_MAX_CIPHER_BLOCK_SIZE)
        {
            return FIT_STATUS_BUFFER_OVERRUN;
        }
        /* add the 0x80 byte */
        omac->block[omac->buflen++] = 0x80;

        /* pad with 0x00 */
        while (omac->buflen < omac->blklen)
        {
            if (omac->buflen >= OMAC_MAX_CIPHER_BLOCK_SIZE)
            {
                return FIT_STATUS_BUFFER_OVERRUN;
            }
            omac->block[omac->buflen++] = 0x00;
        }
        mode = 1;
    }
    else
    {
        mode = 0;
    }

    /* now xor prev + Lu[mode] */
    for (x = 0; x < (uint8_t)omac->blklen; x++)
    {
        omac->block[x] ^= omac->prev[x] ^ omac->Lu[mode][x];/*lint !e732 */
    }

    /* encrypt it */
    fit_aes_encrypt(aes, omac->block, omac->block, omac->key, (uint8_t*)(omac->state));
    done((uint8_t *)omac->key);/*lint !e818 */

    /* output it */
    for (x = 0; x < ((uint8_t)omac->blklen) && (x < *outlen); x++)
    {
        out[x] = omac->block[x];
    }
    *outlen = x;

  return FIT_STATUS_OK;

}

/**
 *
 * \skip fit_omac_memory
 *
 * Get OMAC of data passed in. OMAC will internally use AES 128 encryption.
 *
 * @param IN    blocklength    \n The index of the desired cipher.
 *
 * @param IN    key     \n Start address of the signing key in binary format,
 *                         depending on your READ_LICENSE_BYTE definition
 *
 * @param IN    indata  \n Start address of the data for which OMAC to be calculated
 *                         in binary format, depending on your READ_LICENSE_BYTE
 *                         definition
 *
 * @param OUT   out     \n Pointer to buffer that will contain OMAC value.
 *
 * @param OUT   outlen  \n The max size and resulting size of the OMAC data.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_omac_memory(uint16_t blocklength,
                             const fit_pointer_t *key,
                             const fit_pointer_t *indata,
                             uint8_t *out, 
                             uint32_t *outlen)
{
    fit_status_t result = FIT_STATUS_UNKNOWN_ERROR;
    omac_state_t omac = {0};
    fit_aes_t aes = {0};

    /* omac process the data */
    result = fit_omac_init(&omac, &aes, blocklength, key);
    if (result != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_ERROR, "fit_omac_init fails with error code %ld", (unsigned int)result);
        return result;
    }

    result = fit_omac_process(&omac, (const fit_aes_t *)&aes, indata);
    if (result != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_ERROR, "fit_omac_process fails with error code %ld", (unsigned int)result);
        return result;
    }

    result = fit_omac_done(&omac, (const fit_aes_t *)&aes, out, outlen);
    if (result != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_ERROR, "fit_omac_done fails with error code %ld", (unsigned int)result);
        return result;
    }

    result = FIT_STATUS_OK;

    return result;
}

/**
 *
 * fit_verify_aes_key
 *
 * Do a "weak" verification of an AES key by checking:
 *   - key length is one of the supported ones
 *   - key is not all 00 (blank RAM)
 *   - key is not all FF (blank Flash/EEPROM)
 *
 * @param IN    aeskey      \n Start address of the signing key in binary format,
 *                             depending on your READ_LICENSE_BYTE definition
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_verify_aes_key( fit_pointer_t *aeskey )/*lint !e818 */
{
  fit_status_t status = FIT_STATUS_OK;
  uint32_t     i;
  uint8_t      b;
  uint8_t      all0 = 0, all1 = 0xFF;

  if ( (aeskey->length != FIT_AES_128_KEY_LENGTH) && (aeskey->length != FIT_AES_256_KEY_LENGTH) ) {
    status = FIT_STATUS_INVALID_KEYSIZE;
    DBG(FIT_TRACE_CRITICAL, "Invalid AES key size %d\n", (unsigned int)status);
  } else {
    for (i=0; i<aeskey->length; i++) {
      b = aeskey->read_byte(aeskey->data + i);
      all0 |= b;
      all1 &= b;
    }
    if ( (all0 == 0) || (all1 == 0xFF) ) {
      status = FIT_STATUS_INVALID_SIGNING_KEY;
      DBG(FIT_TRACE_CRITICAL, "Invalid AES signing key %d\n", (unsigned int)status);
    }
  }

  return status;
}

/**
 *
 * fit_validate_omac_signature
 *
 * This function will be used to validate omac value present in license binary
 * against calculated omac against license data. If caching is enabled then omac
 * value present in license data is compared against cached omac value.
 *
 * @param IN    license     \n Start address of the license in binary format,
 *                             depending on your READ_LICENSE_BYTE definition
 *                             e.g. in case of RAM, this can just be the memory
 *                             address of the license variable 
 *
 * @param IN    aeskey      \n Start address of the signing key in binary format,
 *                             depending on your READ_LICENSE_BYTE definition
 *
 * @param IN    signature \n license signature data.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_validate_omac_signature(fit_pointer_t* license,
                                         fit_pointer_t* aeskey,
                                         fit_pointer_t *sigdata)
{
    fit_status_t status             = FIT_STATUS_UNKNOWN_ERROR;
    uint8_t cmacdata[OMAC_SIZE]     = {0};
    uint32_t cmaclen                = OMAC_SIZE;
    fit_pointer_t licdata           = {0};

    DBG(FIT_TRACE_INFO, "[fit_validate_omac_signature]: Entry.\n");

    status = fit_verify_aes_key(aeskey);
    if (status) {
        DBG(FIT_TRACE_ERROR, "Invalid AES signature key %d\n", (unsigned int)status);
        return status;
    }

    licdata.read_byte = license->read_byte;

    // Get the OMAC of license binary and compare it with store OMAC.
    // Step 1: Get the data address in license binary where signature is stored
    // Step 2: Validate signature part if it contains omac data.
    // Step 3: Extract OMAC if omac is present.
    // Step 4. Calculate OMAC for license container data (except signature part) and compared
    //         it with stored OMAC.

    // Get address and length of license part in binary.
    status = fit_get_license_part_data(license,&licdata.length,&licdata.data);

    if (status != FIT_STATUS_OK)
    {
        return status;
    }

    // Get OMAC of license data.
    status = fit_omac_memory(OMAC_BLOCK_LENGTH, aeskey, &licdata,
        (uint8_t *)cmacdata, &cmaclen);
    if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_CRITICAL, "OMAC algorithm fails %d\n", (unsigned int)status);
        return status;
    }
    else
    {
        DBG(FIT_TRACE_INFO, "Got license OMAC value successfully \n");
    }

    /* Compare license OMAC value with calculated value. */
    if(fit_fitptr_sec_memcmp(sigdata, (const uint8_t *)cmacdata, OMAC_SIZE) != 0 )
    {
        DBG(FIT_TRACE_ERROR, "\nLicense OMAC does not match with calculated OMAC value.\n");
        status = FIT_STATUS_INVALID_SIGNATURE;
        return status;
    }
    else
    {
        DBG(FIT_TRACE_INFO, "\nLicense OMAC match with calculated OMAC value.\n");
        status = FIT_STATUS_OK;
    }

    /* Validate fingerprint information present in the license */
    status = fit_validate_fp_data(license);
     if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_CRITICAL, "fit_validate_fp_data failed with error code %d\n",
            (unsigned int)status);
        return status;
    }

    DBG(FIT_TRACE_INFO, "[fit_validate_omac_signature]: Exit.\n");

    return status;
}

#endif // ifdef FIT_USE_AES_SIGNING

