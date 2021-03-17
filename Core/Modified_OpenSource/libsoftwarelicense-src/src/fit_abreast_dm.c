/****************************************************************************\
**
** fit_abreast_dm.c
**
** Defines functionality for implementation for Abreast DM hash algorithm
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

#ifdef FIT_USE_SYSTEM_CALLS
#include <string.h>
#endif

#include "fit_types.h"
#include "fit_hwdep.h"
#include "fit_aes.h"
#include "fit_abreast_dm.h"
#include "fit_dm_hash.h"
#include "fit_debug.h"

/* Constants ****************************************************************/

/* Global Data **************************************************************/

static uint8_t fit_aes256key[FIT_AES_256_KEY_LENGTH] = {0};

/* Functions ****************************************************************/

/**
 *
 * fit_aes256_abreastdm_init
 *
 * This function will initialize hash data to default initial value.
 *
 * @param IN    hash    \n Pointer to hash data to initialize
 *
 */
static void fit_aes256_abreastdm_init(uint8_t *hash)
{
    /* Start Hash with 0xFF */
    (void)fit_memset(hash,0xff,32);
}

/**
 *
 * fit_aes_ecb_encrypt
 *
 * This function will encrypt the data passed in based on global aes key.
 *
 * @param IN    in  \n Pointer to data that needs to be encrypted.
 *
 * @param  IN   blk_num     \n Block number in case this function is called message
 *                             greater than 16 bytes.
 *
 */
static fit_status_t fit_aes_ecb_encrypt(uint8_t *in, size_t inlen)
{
    uint8_t aes_state[16] = {0};
    fit_status_t status = FIT_STATUS_UNKNOWN_ERROR;
    fit_aes_t aes = {0};
    uint8_t out[FIT_AES_OUTPUT_DATA_SIZE] = {0};
    fit_pointer_t fitkey = {0,0,0};
    uint8_t skey[FIT_ROUNDS_256BIT_KEY_LENGTH] = {0};

    fitkey.read_byte = (fit_read_byte_callback_t) FIT_READ_BYTE_RAM;
    fitkey.data = (uint8_t *)fit_aes256key;
    fitkey.length = FIT_AES_256_KEY_LENGTH;

    /* Initialize the aes context */
    status = fit_aes_setup(&aes, &fitkey, skey);
    if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_ERROR, "failed to initialize aes setup error =%d\n",
            (unsigned int)status);
        return status;
    }

    fit_aes_encrypt(&aes, in, out, skey, (uint8_t*)aes_state);
    if (fit_memcpy(in, inlen, out, 16) != 0)
    {
        return FIT_STATUS_BUFFER_OVERRUN;
    }

    return status;
}

/**
 *
 * fit_aes256_abreastdm_update_blk
 *
 * This function will update the hash of the license data (for one block of data)
 *
 * @param IN    indata  \n Buffer to hold data
 *
 * @param IO    hash    \n Hash Buffer to hold thye hash value
 *
 */
static fit_status_t fit_aes256_abreastdm_update_blk(uint8_t *indata, uint8_t *hash)
{
    fit_status_t status = FIT_STATUS_UNKNOWN_ERROR;
    uint8_t  tempbuf[FIT_AES_OUTPUT_DATA_SIZE] = {0};
    uint8_t *msg = indata;
    uint8_t *hashg = hash;
    uint8_t *hashh = hash + 16;
    uint8_t  i = 0;

    /* Gi = Gi-1 XOR AES(Gi-1 || Hi-1Mi) */
    if (fit_memcpy(fit_aes256key, FIT_AES_256_KEY_LENGTH, hashh, FIT_AES_256_KEY_LENGTH/2) != 0)
    {
        return FIT_STATUS_BUFFER_OVERRUN;
    }
    if (fit_memcpy(fit_aes256key+FIT_AES_256_KEY_LENGTH/2, FIT_AES_256_KEY_LENGTH, msg,
        FIT_AES_256_KEY_LENGTH/2) != 0)
    {
        return FIT_STATUS_BUFFER_OVERRUN;
    }

    if (fit_memcpy(tempbuf, FIT_AES_OUTPUT_DATA_SIZE, hashg, 16) != 0)
    {
        return FIT_STATUS_BUFFER_OVERRUN;
    }
    status = fit_aes_ecb_encrypt(tempbuf, FIT_AES_OUTPUT_DATA_SIZE);
    if (status != FIT_STATUS_OK)
    {
        return status;
    }
    for(i=0;i<16;i++)
    {
        hashg[i] ^= tempbuf[i];
    }

    /* Hi = Hi-1 XOR AES(~ Hi-1 || Mi Gi-1) */
    if (fit_memcpy(fit_aes256key, FIT_AES_256_KEY_LENGTH, msg, FIT_AES_256_KEY_LENGTH/2) != 0)
    {
        return FIT_STATUS_BUFFER_OVERRUN;
    }
    if (fit_memcpy(fit_aes256key+FIT_AES_256_KEY_LENGTH/2, FIT_AES_256_KEY_LENGTH, hashg,
        FIT_AES_256_KEY_LENGTH/2) != 0)
    {
        return FIT_STATUS_BUFFER_OVERRUN;
    }

    if (fit_memcpy(tempbuf, FIT_AES_OUTPUT_DATA_SIZE, hashh, 16) != 0)
    {
        return FIT_STATUS_BUFFER_OVERRUN;
    }
    for(i=0; i<16; i++)
    {
        tempbuf[i] ^= 0xFF;
    }
    status = fit_aes_ecb_encrypt(tempbuf, FIT_AES_OUTPUT_DATA_SIZE);
    if (status != FIT_STATUS_OK)
    {
        return status;
    }
    for(i=0;i<16;i++)
    {
        hashh[i] ^= tempbuf[i];
    }

    return status;
}

/**
 *
 * fit_aes256_abreastdm_finalize
 *
 * This function will perform final update on hash of the license data
 *
 * @param IO    hash    \n Hash Buffer to hold the hash value
 *
 */
static fit_status_t fit_aes256_abreastdm_finalize(uint8_t *hash)
{
    uint8_t i;
    uint8_t tempbuf[FIT_AES_OUTPUT_DATA_SIZE] = {0};
    fit_status_t status = FIT_STATUS_UNKNOWN_ERROR;

    /* update the aes key (AES algorithm) used in encryption of license data. */
    if (fit_memcpy(fit_aes256key, FIT_AES_256_KEY_LENGTH, hash, FIT_AES_256_KEY_LENGTH) != 0)
    {
        return FIT_STATUS_BUFFER_OVERRUN;
    }
    /* hash[0-15] */
    if (fit_memcpy(tempbuf, FIT_AES_OUTPUT_DATA_SIZE, hash, 16) != 0)
    {
        return FIT_STATUS_BUFFER_OVERRUN;
    }
    status = fit_aes_ecb_encrypt(tempbuf, FIT_AES_OUTPUT_DATA_SIZE);
    if (status != FIT_STATUS_OK)
    {
        return status;
    }
    for(i =0; i< 16; i++)
    {
        hash[i] ^= tempbuf[i];
    }
    /* hash[16-32] */
    if (fit_memcpy(tempbuf, FIT_AES_OUTPUT_DATA_SIZE, hash+16, 16) != 0)
    {
        return FIT_STATUS_BUFFER_OVERRUN;
    }
    status = fit_aes_ecb_encrypt(tempbuf, FIT_AES_OUTPUT_DATA_SIZE);
    if (status != FIT_STATUS_OK)
    {
        return status;
    }
    for(i =0; i< 16; i++)
    {
        hash[i+16] ^= tempbuf[i];
    }

   return status;
}

/**
 *
 * fit_get_abreastdm_hash
 *
 * This function will get the abreast dm hash of the data passed in.
 *
 * @param IN    msg     \n Pointer to data passed in for which hash needs to be
 *                         calculated.
 *
 * @param IO    hash    \n Hash Buffer to hold thye hash value
 *
 */
fit_status_t fit_get_abreastdm_hash(fit_pointer_t *msg, uint8_t *hash)
{
    uint32_t cntr           = 0;
    uint8_t tempmsg[32] = {0};
    uint32_t msglen         = 0;
    fit_pointer_t fitptr = {0,0,0};
    fit_status_t status = FIT_STATUS_UNKNOWN_ERROR;


    (void)fit_memset((uint8_t *)&fitptr, 0, sizeof(fit_pointer_t));
    /* Initialize the read pointer.*/
    fitptr.read_byte = msg->read_byte;

    /* Initialize hash value;*/
    fit_aes256_abreastdm_init(hash);

    /* Break data in blocks (16 bytes each) and hash the data.*/
    for (cntr = 0; cntr < msg->length; cntr+=16)
    {
        if ((cntr+16) < msg->length)
        {
            fitptr.data = msg->data+cntr;
            fitptr.length = 16;
            if (fit_fitptr_memcpy(tempmsg, sizeof(tempmsg), &fitptr) != 0)
            {
                return FIT_STATUS_BUFFER_OVERRUN;
            }
            status = fit_aes256_abreastdm_update_blk(tempmsg, hash);
            if (status != FIT_STATUS_OK)
            {
                return status;
            }
        }
    }
    cntr -= 16;

    fitptr.data = msg->data+cntr;
    fitptr.length = msg->length-cntr;
    msglen = fitptr.length;
    if (fit_fitptr_memcpy(tempmsg, sizeof(tempmsg), &fitptr) != 0)
    {
        return FIT_STATUS_BUFFER_OVERRUN;
    }

    fit_dm_hash_init(tempmsg, &msglen, msg->length);
    for (cntr = 0; cntr < msglen; cntr+=16)
    {
        status = fit_aes256_abreastdm_update_blk(tempmsg+cntr, hash);
        if (status != FIT_STATUS_OK)
        {
            return status;
        }
    }

    status = fit_aes256_abreastdm_finalize(hash);
    if (status != FIT_STATUS_OK)
    {
        return status;
    }

    return status;
}


/**
 *
 * fit_abreastDM_init
 *
 * This function will initialize hash data to default initial value.
 *
 * @param IO    ctx    \n Pointer to AbreastDM context data.
 *
 */
void fit_abreastDM_init (fit_abdm_ctx_t* ctx)
{
    /* Start Hash with 0xFF */
    (void)fit_memset(ctx, 0, sizeof(fit_abdm_ctx_t));
    (void)fit_memset(ctx->hash, 0xff, FIT_ABREAST_DM_HASH_SIZE);
    (void)fit_memset(ctx->data, 0x00, 16);
    ctx->length = 0;
}

/**
 *
 * fit_abreastDM_update
 *
 * This function will update the ABreastDM hash for incoming data 
 *
 * @param IO    ctx    \n Pointer to AbreastDM context data.
 *
 * @param IN    indata  \n Buffer to hold data
 *
 * @param IN    len    \n length of above data
 *
 */
fit_status_t fit_abreastDM_update(fit_abdm_ctx_t* ctx, uint8_t* indata, uint32_t len)
{
    fit_status_t status = FIT_STATUS_OK;
    uint32_t cntr           = 0;
    uint8_t tempmsg[16] = {0};

    if (ctx == NULL)
    {
        return FIT_STATUS_INVALID_PARAM_1;
    }

    if (ctx->index > 0)
    {
        if (ctx->index + len > FIT_ABREAST_DM_BLK_SIZE)
        {
            /* calculate and update the hash for 16 bytes */
            (void)fit_memcpy(tempmsg, sizeof(tempmsg), ctx->data, ctx->index);
            if ((FIT_ABREAST_DM_BLK_SIZE - ctx->index) > 0)
            {
                (void)fit_memcpy(tempmsg + ctx->index, sizeof(tempmsg), indata,
                    (size_t)FIT_ABREAST_DM_BLK_SIZE - ctx->index);
                len = len - (uint32_t)(FIT_ABREAST_DM_BLK_SIZE - ctx->index);

                indata = indata + (FIT_ABREAST_DM_BLK_SIZE - ctx->index);/*lint !e679 */
            }

            /* update the hash for the incoming data */
            status = fit_aes256_abreastdm_update_blk(tempmsg, ctx->hash);
            if (status != FIT_STATUS_OK)
            {
                return status;
            }

            /* updated the total length that was used for hash calculation */
            ctx->length += FIT_ABREAST_DM_BLK_SIZE;
        }
        else
        {
            /* Add data to context if combined length is less than FIT_ABREAST_DM_BLK_SIZE,
             * otherwise update the hash 
             */
            (void)fit_memcpy(ctx->data + ctx->index, FIT_ABREAST_DM_BLK_SIZE, indata, len);
            ctx->index += (uint8_t)len; /* index value would always be <= FIT_ABREAST_DM_BLK_SIZE */
            return FIT_STATUS_OK;
        }
    }
    /* Break data in blocks (16 bytes each) and hash the data.*/
    for (cntr = 0; cntr <len; cntr+=16)
    {
        if ((cntr+16) < len)
        {
            if(fit_memcpy(tempmsg, sizeof(tempmsg), indata+cntr, FIT_ABREAST_DM_BLK_SIZE) != 0)
            {
                return FIT_STATUS_BUFFER_OVERRUN;
            }

            /* update the hash for the incoming data */
            status = fit_aes256_abreastdm_update_blk(tempmsg, ctx->hash);
            if (status != FIT_STATUS_OK)
            {
                return status;
            }
            /* updated the total length that was used for hash calculation */
            ctx->length += FIT_ABREAST_DM_BLK_SIZE;
        }
    }

    cntr -= 16;
    if (fit_memcpy(ctx->data, FIT_ABREAST_DM_BLK_SIZE, indata+cntr, len-cntr) != 0)
    {
        return FIT_STATUS_BUFFER_OVERRUN;
    }

    /* index value would always be less than equal to 16 */
    ctx->index = (uint8_t)(len-cntr);

    return status;
}

/**
 *
 * fit_abreastDM_final
 *
 * This function will perform final update on hash of the data
 *
 * @param IO    ctx    \n Pointer to AbreastDM context data.
 *
 */
fit_status_t fit_abreastDM_final(fit_abdm_ctx_t* ctx)
{
    fit_status_t status = FIT_STATUS_INTERNAL_ERROR;
    uint8_t tempmsg[32] = {0};
    uint32_t msglen         = 0;
    uint32_t cntr = 0;

    if (ctx == NULL)
    {
        return FIT_STATUS_INVALID_PARAM_1;
    }
    if (ctx->index == 0)
    {
        return FIT_STATUS_INTERNAL_ERROR;
    }

    if (fit_memcpy(tempmsg, sizeof(tempmsg), ctx->data, ctx->index) != 0)
    {
        return FIT_STATUS_BUFFER_OVERRUN;
    }
    /* updated the total length that was used for hash calculation */
    ctx->length += ctx->index;

    /* calculate and update the hash for remaining data */
    msglen = ctx->index;
    fit_dm_hash_init(tempmsg, &msglen, ctx->length);
    for (cntr = 0; cntr < msglen; cntr+=16)
    {
        status = fit_aes256_abreastdm_update_blk(tempmsg+cntr, ctx->hash);
        if (status != FIT_STATUS_OK)
        {
            return status;
        }
    }

    /* perform final update on hash of the data */
    status = fit_aes256_abreastdm_finalize(ctx->hash);
    if (status != FIT_STATUS_OK)
    {
        return status;
    }
    /* reset the index as no more data to compute */
    ctx->index = 0;

    return status;
}

