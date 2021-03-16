/****************************************************************************\
**
** fit_dm_hash.c
**
** Defines functionality for implementation for davies meyer hash function.
** 
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

/* Required Includes ******************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#ifdef FIT_USE_SYSTEM_CALLS
#include <string.h>
#endif

#include "fit_dm_hash.h"
#include "fit_aes.h"
#include "fit_internal.h"
#include "fit_debug.h"
#include "fit_hwdep.h"

/* Constants ****************************************************************/

#define FIT_DM_CIPHER_BLOCK_SIZE            0x10
#define FIT_ROUNDS_128BIT_KEY_LENGTH        0xB0
#define FIT_BITS_PER_BYTE                   8

/* Global variables *********************************************************/

/* Function Definitions *****************************************************/

/**
 *
 * \skip fit_dm_hash_init
 *
 * This function will be used to pad the data to make it’s length be an even multiple
 * of the block size and include a length encoding. This is done by padding with zeros
 * to the next size which is an odd multiple of 64 bits and then appending a 64-bit
 * big-endian encoding of the number of bits of license data length.
 *
 * @param IN    pdata   \n Pointer to data that needs to be hashed.
 *
 * @param IO    pdatalen    \n Length of last data part after data is padded and encoded.
 *
 * @param IN    msgfulllen  \n Message length for which hash needs to be calculated.
 *                             This is different than pdatalen as this function is
 *                             called for only last block of data (to avoid overuse
 *                             of stack size for long messages)
 *
 */
void fit_dm_hash_init(uint8_t *pdata, uint32_t *pdatalen, uint32_t msgfulllen)
{
    uint32_t length;
    uint32_t sizeinbits;
    uint32_t cntr;
    uint8_t  zeropads;

    DBG(FIT_TRACE_INFO, "\nfit_dm_hash_init..\n");

    length = *pdatalen;
    sizeinbits= msgfulllen*FIT_BITS_PER_BYTE;
    zeropads = ((FIT_DM_CIPHER_BLOCK_SIZE/sizeof(uint16_t)) - 
        (length%(FIT_DM_CIPHER_BLOCK_SIZE/sizeof(uint16_t))));

    /* Pad with zeros to the next size which is an odd multiple of 64 bits */
    for(cntr=0; cntr < zeropads; cntr++)
    {
        pdata[length++] = 0x00;
    }
    if ((length%FIT_DM_CIPHER_BLOCK_SIZE) == 0)
    {
        for(cntr=0; cntr < FIT_DM_CIPHER_BLOCK_SIZE/sizeof(uint16_t); cntr++)
        {
            pdata[length++] = 0x00;
        }
    }

    /* Append a 64-bit big-endian encoding of the number of bits to the license data */
    pdata[length++] = 0x00;
    pdata[length++] = 0x00;
    pdata[length++] = 0x00;
    pdata[length++] = 0x00;
    pdata[length++] = 0x00;
    pdata[length++] = 0x00;
    pdata[length++] = (uint8_t)(sizeinbits >> 8);
    pdata[length++] = (uint8_t)(sizeinbits & 0xff);

    *pdatalen = length;
}

/**
 *
 * \skip fit_davies_meyer_hash
 *
 * This function will be used to get the davies meyer hash of the data passed in.
 * This is performed by first splitting the data (message m) into 128 bits (m1 … mn)
 * For each of the 128 bit sub-block, calculate
 *      Hi = AES (Hi-1, mi)  XOR Hi-1
 * The final Hash is calculated as:
 *      H = AES (Hn, Hn) XOR Hn
 *
 * @param IN    pdata   \n Pointer to data for which davies meyer hash to be calculated
 *
 * @param IN    mdata   \n Pointer to data(in case we need to merge two data pointers
 *                         or calculate davies meyer hash of two different data) for
 *                         which davies meyer hash to be calculated
 *
 * @param OUT   dmhash  \n On return this will contain the davies mayer hash of data
 *                         passed in.
 *
 */
fit_status_t fit_davies_meyer_hash(fit_pointer_t *pdata,
                                   fit_pointer_t *mdata,
                                   uint8_t *dmhash)
{
    fit_status_t  status            = FIT_STATUS_OK;
    uint8_t aes_state[4][4]         = {{0}};
    uint32_t cntr                   = 0;
    uint32_t cntr2                  = 0;
    uint32_t cntry                  = 0;
    uint32_t total_len              = 0;
    uint8_t output[FIT_AES_OUTPUT_DATA_SIZE]    = {0};
    uint8_t prev_hash[FIT_DM_HASH_SIZE]         = {0};
    fit_aes_t aes = {0};
    uint8_t tempmsg[32]     = {0};
    uint16_t tempsize       = (uint16_t)sizeof(tempmsg);
    uint8_t diffval         = {0};
    uint32_t msglen         = 0;
    fit_pointer_t fitptr    = {0};
    fit_pointer_t fitkey    = {0};
    fit_pointer_t fittempptr = {0};
    uint8_t skey[FIT_ROUNDS_128BIT_KEY_LENGTH] = {0};

    (void)fit_memset(prev_hash, 0xFF, FIT_DM_HASH_SIZE);
    /* Initialize the read pointer.*/
    fitptr.read_byte = pdata->read_byte;
    fitkey.read_byte = (fit_read_byte_callback_t) FIT_READ_BYTE_RAM;

    total_len = pdata->length;
    if (mdata != NULL)
    {
        total_len += mdata->length;
    }
    /*
     * For each of the 128 bit sub-block, calculate
     *      Hi = AES (Hi-1, mi)  XOR Hi-1
     */
    for (cntr = 0; cntr < total_len; cntr+=16)
    {
        /* First consume first data pointer */
        if ((cntr+16) < total_len)
        {
            if ((cntr+16) <= pdata->length)
            {
                fittempptr.data = (pdata->data)+cntr;
                fittempptr.length = FIT_AES_128_KEY_LENGTH;
                fittempptr.read_byte = pdata->read_byte;
                if (fit_fitptr_memcpy(tempmsg, tempsize, &fittempptr) != 0)
                {
                    return FIT_STATUS_BUFFER_OVERRUN;
                }
            }
            else if (mdata != NULL && (cntr+16) < total_len)
            {
                /* If additional data is provided then add this data to hash. */
                if (cntr < pdata->length)
                {
                    fittempptr.data = (pdata->data)+cntr;
                    fittempptr.length = pdata->length - cntr;
                    fittempptr.read_byte = pdata->read_byte;
                    if (fit_fitptr_memcpy(tempmsg, tempsize, &fittempptr) != 0)
                    {
                        return FIT_STATUS_BUFFER_OVERRUN;
                    }

                    fittempptr.data = mdata->data;
                    fittempptr.length = FIT_AES_128_KEY_LENGTH - (pdata->length - cntr);
                    fittempptr.read_byte = mdata->read_byte;
                    // disable lint warning - we add offset to ptr
                    if (fit_fitptr_memcpy(tempmsg+(pdata->length - cntr), tempsize-(uint16_t)(pdata->length - cntr),//lint !e732 !e679
                        &fittempptr) != 0)
                    {
                        return FIT_STATUS_BUFFER_OVERRUN;
                    }
                    diffval = (uint8_t)fittempptr.length;
                }
                else
                {
                    // disable lint warning - we add offset to ptr
                    fittempptr.data = (mdata->data+diffval)+((cntry++) * 16); //lint !e679
                    fittempptr.length = FIT_AES_128_KEY_LENGTH;
                    fittempptr.read_byte = mdata->read_byte;
                    if (fit_fitptr_memcpy(tempmsg, tempsize, &fittempptr) != 0)
                    {
                        return FIT_STATUS_BUFFER_OVERRUN;
                    }
                }
            }

            /* Initialize the aes context */
            fitkey.data = (uint8_t *)tempmsg;
            fitkey.length = FIT_AES_128_KEY_LENGTH;
            status = fit_aes_setup(&aes, &fitkey, skey);
            if (status != FIT_STATUS_OK)
            {
                DBG(FIT_TRACE_ERROR, "failed to initialize aes setup error =%d\n",
                    (unsigned int)status);
                return status;
            }

            (void)fit_memset((uint8_t*)aes_state, 0, sizeof(aes_state));
            (void)fit_memset((uint8_t*)output, 0, FIT_AES_OUTPUT_DATA_SIZE);
            /* Encrypt data (AES 128) */
            fit_aes_encrypt(&aes, prev_hash, output, skey, (uint8_t*)aes_state);
            for (cntr2 = 0; cntr2 < 16; cntr2++)
            {
                dmhash[cntr2] = output[cntr2] ^ prev_hash[cntr2];/*lint !e732*/
            }
            if (fit_memcpy(prev_hash, FIT_DM_HASH_SIZE, dmhash, 16) != 0)
            {
                return FIT_STATUS_BUFFER_OVERRUN;
            }
        }
    }
    cntr -= 16;
    (void)fit_memset(tempmsg, 0, tempsize);

    /*
     * Pad the last block of data (last block will always be less than 16 bytes)
     * and calculate Hi = AES (Hi-1, mi)  XOR Hi-1 
     */
    if (mdata == NULL)
    {
        fitptr.data = pdata->data+cntr;
    }
    else
    {
        // disable lint warning - we add offset to ptr
        fitptr.data = mdata->data+diffval+(cntry * 16); //lint !e679
    }
    fitptr.length = total_len-cntr;
    msglen = fitptr.length;
    if (fit_fitptr_memcpy(tempmsg, tempsize, &fitptr) != 0)
    {
        return FIT_STATUS_BUFFER_OVERRUN;
    }

    /* Do padding for the last block of data.*/
    fit_dm_hash_init(tempmsg, &msglen, total_len);
    /*
     * For each of the 128 bit sub-block, calculate
     *      Hi = AES (Hi-1, mi)  XOR Hi-1
     */
    for (cntr = 0; cntr < msglen; cntr+=16)
    {
        /* Initialize the aes context */
        fitkey.data = tempmsg+cntr;
        fitkey.length = FIT_AES_128_KEY_LENGTH;
        status = fit_aes_setup(&aes, &fitkey, skey);
        if (status != FIT_STATUS_OK)
        {
            DBG(FIT_TRACE_ERROR, "failed to initialize aes setup error =%d\n",
                (unsigned int)status);
            return status;
        }

        (void)fit_memset((uint8_t*)aes_state, 0, sizeof(aes_state));
        (void)fit_memset((uint8_t*)output, 0, FIT_AES_OUTPUT_DATA_SIZE);
        /* Encrypt data (AES 128) */
        fit_aes_encrypt(&aes, prev_hash, output, skey, (uint8_t*)aes_state);
        for (cntr2 = 0; cntr2 < 16; cntr2++)
        {
            dmhash[cntr2] = output[cntr2] ^ prev_hash[cntr2];/*lint !e732*/
        }
        if (fit_memcpy(prev_hash, FIT_DM_HASH_SIZE, dmhash, 16) != 0)
        {
            return FIT_STATUS_BUFFER_OVERRUN;
        }
    }

    /*
     * The final Hash is calculated as:
     *      H = AES (Hn, Hn) XOR Hn
     * Initialize the aes context
     */
    fitkey.data = prev_hash;
    fitkey.length = FIT_AES_128_KEY_LENGTH;
    status = fit_aes_setup(&aes, &fitkey, skey);
    if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_ERROR, "failed to initialize aes setup error =%d\n",
            (unsigned int)status);
        return status;
    }

    (void)fit_memset((uint8_t*)aes_state, 0, sizeof(aes_state));
    (void)fit_memset((uint8_t*)output, 0, sizeof(output));
    /* Encrypt data (AES 128) */
    fit_aes_encrypt(&aes, prev_hash, output, skey, (uint8_t*)aes_state);
    for (cntr2 = 0; cntr2 < 16; cntr2++)
    {
        dmhash[cntr2] = output[cntr2] ^ prev_hash[cntr2];/*lint !e732*/
    }

    return status;
}

