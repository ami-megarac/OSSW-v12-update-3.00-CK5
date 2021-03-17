/****************************************************************************\
**
** fit_node_locking.c
**
** Defines functionality for fetching fingerprint information for embedded devices.
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

#include "fit_dm_hash.h"
#include "fit_internal.h"
#include "fit_debug.h"
#include "fit_hwdep.h"
#include "fit_mem_read.h"
#include "fit_parser.h"
#include "mbedtls/base64.h"

/* Function Definitions *****************************************************/

/**
 *
 * \skip fit_validate_fp_data
 *
 * This function is used to validate the fingerprint information present in license
 * data.
 *
 * @param IN    license     \n Pointer to fit_pointer_t structure containing license
 *                             data. To access the license data in different types of
 *                             memory (FLASH, E2, RAM), fit_pointer_t is used.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_validate_fp_data(fit_pointer_t *license)
{
    fit_status_t status             = FIT_STATUS_UNKNOWN_ERROR;
    fit_op_data_t opdata = {0x00};
#ifdef FIT_USE_NODE_LOCKING
    fit_boolean_t valid_fp_present  = FIT_FALSE;
    fit_fingerprint_t licfp = {0x00};
    fit_fingerprint_t devicefp = {0x00};
    fit_fp_callback callback_fn     = FIT_DEVICE_ID_GET;
#endif /* #ifdef FIT_USE_NODE_LOCKING */

    DBG(FIT_TRACE_INFO, "[fit_validate_fp_data]: license=0x%p length=%hd\n",
        license->data, license->length);

    /* Check the presence of fingerprint in the license data.*/
    opdata.tagid = FIT_FP_TAG_ID;
    opdata.operation = (uint8_t)FIT_OP_GET_DATA_ADDRESS;
    opdata.status = FIT_STATUS_OK;
    status = fit_license_parser(license, &opdata);
    if (status != FIT_STATUS_OK)
    {
        return status;
    }

    if ((opdata.parserstatus == FIT_INFO_STOP_PARSE) &&
        (opdata.status == FIT_STATUS_LIC_FIELD_PRESENT))
    {
#ifndef FIT_USE_NODE_LOCKING
        DBG(FIT_TRACE_ERROR, "Fit core was not compiled with node locking macro \n");
        return FIT_STATUS_NODE_LOCKING_NOT_SUPP;
#else
        fit_pointer_t fitptr = {(void *)0};
        DBG(FIT_TRACE_INFO, "Fingerprint information is found in license string.\n");
        /* get the fingerprint data in licfp structure.*/
        fitptr.data = opdata.parserdata.addr;
        fitptr.read_byte = license->read_byte;
        status = fit_get_fingerprint(&fitptr, &licfp, license);
        
        if (status != FIT_STATUS_OK)
        {
            return status;
        }

        /* License string contains the fingerprint data. Check the magic value.*/
        if (licfp.magic == FIT_FP_MAGIC)
        {
            DBG(FIT_TRACE_INFO, "Magic number found in license string.\n");
            valid_fp_present = FIT_TRUE;
            status = FIT_STATUS_OK;
        }
        else
        {
            DBG(FIT_TRACE_ERROR, "Invalid Magic number in license string.\n");
            return FIT_STATUS_INVALID_V2C;
        }
        /* Validate algorithm used */
        if (licfp.algid != FIT_AES_FP_ALGID)
        {
            return FIT_STATUS_UNKNOWN_FP_ALGORITHM;
        }
#endif /* #ifndef FIT_USE_NODE_LOCKING */
   }

#ifdef FIT_USE_NODE_LOCKING
    if (valid_fp_present == (fit_boolean_t)FIT_TRUE)
    {
        DBG(FIT_TRACE_INFO, "Get fingerprint information from respective hardware.\n");
        /*
         * Get fingerprint data of the device and then compare it data present in
         * the license.
         */
        status = fit_get_device_fpblob(&devicefp, callback_fn);
        if (status != FIT_STATUS_OK)
        {
            DBG(FIT_TRACE_INFO, "Error in getting fingerprint data with status "
                "%d \n", (unsigned int)status);
            return status;
        }
        if (devicefp.algid != FIT_AES_FP_ALGID)
        {
            return FIT_STATUS_UNKNOWN_FP_ALGORITHM;
        }
#if 0
        if(fit_sec_memcmp(licfp.hash, devicefp.hash, FIT_DM_HASH_SIZE) != 0 )
        {
            DBG(FIT_TRACE_ERROR, "Fingerprint hash does not match with stored "
                "hash in license \n");
            return FIT_STATUS_FP_MISMATCH_ERROR;
        }
        else
        {
            DBG(FIT_TRACE_INFO, "Device fingerprint match with stored fingerprint "
                "data in license string\n");
        }
#endif
    }
#endif /* #ifdef FIT_USE_NODE_LOCKING */

    return status;
}

#ifdef FIT_USE_NODE_LOCKING
/**
 *
 * \skip fit_get_fingerprint
 *
 * Get fingerprint data from fit_pointer_t structure and put into fit_fingerprint_t
 * structure.
 *
 * @param IN    fpdata  \n Pointer to fit_pointer_t structure that contains
 *                         fingerprint data.
 *
 * @param OUT   fpstruct    \n Pointer to fit_fingerprint_t that needs to be
 *                             initialized.
 *
 */
fit_status_t fit_get_fingerprint(fit_pointer_t *fpdata, fit_fingerprint_t *fpstruct, fit_pointer_t *license)/*lint !e818*/
{
    fit_status_t status  = FIT_STATUS_UNKNOWN_ERROR;
    fit_pointer_t fitptr = {(void *)0};

    /* Get first four bytes of fingerprint data. This will represent magic id.*/
    status = fit_read_dword_safe(fpdata->data, fpdata->read_byte, license, &fpstruct->magic);
    if(status != FIT_STATUS_OK)
    {
        return status;
    }

    /* Read algorith id value.*/
    status = fit_read_dword_safe(fpdata->data + sizeof(uint32_t), fpdata->read_byte,
        license, &fpstruct->algid);
    if(status != FIT_STATUS_OK)
    {
        return status;
    }    

    /* Get device id hash value*/
    fitptr.data = fpdata->data+sizeof(uint32_t)+sizeof(uint32_t);
    fitptr.length = FIT_DM_HASH_SIZE;
    fitptr.read_byte = fpdata->read_byte;
    if (fit_fitptr_memcpy(fpstruct->hash, FIT_DM_HASH_SIZE, &fitptr) != 0)
    {
        status = FIT_STATUS_BUFFER_OVERRUN;
    }

    return status;
}

/**
 * get_fp_str
 *
 * This Function can be used to get fingerprint string that is associated with a device fingerprint info
 *
 * @param IN  \b  fp_info   \n  Contains the pointer to the fingerprint data and it's corresponding length
 *
 * @param OUT  \b  fpstr    \n  Pointer to the buffer where fingerprint string out would be copied
 *
 */
static fit_status_t get_fp_str(const fit_fingerprint_t* fp_blob, char *fp, uint32_t *fp_length)
{
	int status = 0;
	size_t fp_blob_length = 0;
	

	status = mbedtls_base64_encode(NULL, 0, &fp_blob_length, (uint8_t *) fp_blob, sizeof(fit_fingerprint_t));

	if(fp == NULL)
	{
                *fp_length = (uint32_t)fp_blob_length;
        
		return FIT_STATUS_BUFFER_OVERRUN;
	}

	status = mbedtls_base64_encode((unsigned char *) fp, fp_blob_length, &fp_blob_length, (uint8_t *) fp_blob, sizeof(fit_fingerprint_t));
    
        if(status != 0)
	{
	    return FIT_STATUS_BUFFER_OVERRUN;
	}


        *fp_length = (uint32_t)(fp_blob_length + 1);

	return FIT_STATUS_OK;
} 

#endif /* ifdef FIT_USE_NODE_LOCKING */

/**
 *
 * \skip fit_get_device_fpblob
 *
 * This function will fetch fingerprint/deviceid for the respective board. This will
 * call the hardware implemented callback function which will give raw data that would
 * be unique to each device. Raw data would be then hash with Daview Meyer hash function.
 *
 * @param OUT   fp  \n Pointer to fingerprint data that need to be filled in.
 *
 * @param IN    callback_fn     \n hardware implemented callback function that will
 *                                 return raw fingerprint data and its length.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_get_device_fpblob(fit_fingerprint_t *fp, fit_fp_callback callback_fn)
{
    uint8_t rawdata[FIT_DEVID_MAXLEN] = {0}; /* Maximum length of device id is 64 bytes.*/
    uint8_t dmhash[FIT_DM_HASH_SIZE] = {0x00};
    fit_pointer_t fitptr = {(void *)0};
    fit_status_t status = FIT_STATUS_UNKNOWN_ERROR;
    uint16_t datalen    = 0;
    uint16_t cntr       = 0;

    if( callback_fn == NULL ) {
        return FIT_STATUS_INVALID_PARAM;
    }

    /* Initialize read pointer function.*/
    fitptr.read_byte = (fit_read_byte_callback_t )fit_read_ram_u8;

    /* Get the hardware fingerprint data.*/
    status = callback_fn(rawdata, sizeof(rawdata), &datalen);
    if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_ERROR, "Error in getting fingerprint data with status %d\n",
            (unsigned int)status);
        return status;
    }
    /* device id length should be in range 4-64 characters. */
    if ((datalen < FIT_DEVID_MINLEN) || (datalen > FIT_DEVID_MAXLEN)) {
        return FIT_STATUS_INVALID_DEVICE_ID_LEN;
    }

    /* Print fingerprint raw data */
    for (cntr=0; cntr<datalen; cntr++)
    {
        DBG(FIT_TRACE_INFO, "%X ", rawdata[cntr]);
    }
    DBG(FIT_TRACE_INFO, "\n");

    fitptr.length = datalen;
    fitptr.data = (uint8_t *)rawdata;
    /* Get the Davies Meyer hash of fingerprint data.*/
    status = fit_davies_meyer_hash(&fitptr, NULL, (uint8_t *)dmhash);
    if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_ERROR, "Error in getting Davies Meyer hash with status %d\n",
            (unsigned int)status);
        return status;
    }

    /* Print fingerprint hash data (Davies Meyer Hash) */
    DBG(FIT_TRACE_INFO, "\nDavies Meyer hash of fingerprint data: ");
    for (cntr=0; cntr<FIT_DM_HASH_SIZE; cntr++)
    {
        DBG(FIT_TRACE_INFO, "%X ", dmhash[cntr]);
    }
    DBG(FIT_TRACE_INFO, "\n");

    /* Fill fingerprint data.*/
    fp->algid = FIT_AES_FP_ALGID; /* AES algorithm used for davies meyer hash function.*/
    fp->magic = FIT_FP_MAGIC; /* 'fitF' Magic no.*/
    if (fit_memcpy(fp->hash, FIT_DM_HASH_SIZE, dmhash, FIT_DM_HASH_SIZE) != 0) /* copy fingerprint hash data.*/
    {
        return FIT_STATUS_BUFFER_OVERRUN;
    }

    return status;
}

/**
 *
 * \skip fit_licenf_get_fingerprint
 *
 * This function will fetch fingerprint/deviceid for the respective device.
 *
 *@param OUT \b  fp  		\n  Input buffer pointer. On success the base64 encoded fingerprint 
 *                              as 0 terminated string will be written in this buffer.
 *
 * @param IO  \b  length    \n  Contains input buffer length pointed by *fp.
 *                              On success will return the length of buffer written.
 *                              On failure will return the required buffer length.
 *                              if NULL function will return FIT_STATUS_BUFFER_OVERRUN and required
 *                              buffer length.
 *
 * @return                   \n FIT_STATUS_BUFFER_OVERRUN - if fp is NULL or length to small
 *                              FIT_STATUS_NODE_LOCKING_NOT_SUPP - in case FIT_USE_NODE_LOCKING not defineds
 *                              FIT_STATUS_OK on success
 */

fit_status_t fit_licenf_get_fingerprint(char*  fp,
                                        uint32_t* length)
{
#ifdef FIT_USE_NODE_LOCKING

    fit_status_t status = FIT_STATUS_UNKNOWN_ERROR;
    fit_fingerprint_t fp_blob = {0};
    uint32_t fp_blob_length = 0;

    if(length == NULL)
    {
        return FIT_STATUS_INVALID_PARAM_2;
    }

    /* check the init flag. fit_licenf_init should be called before use of any fit api */
    status = fit_check_init_status();
    if (status != FIT_STATUS_OK)
    {
        return status;
    }

    status = fit_get_device_fpblob(&fp_blob, FIT_DEVICE_ID_GET);

    if(status != FIT_STATUS_OK)
    {
        *length = 0;
        return status;
    }

    status = get_fp_str(&fp_blob, fp, &fp_blob_length);

    if(status != FIT_STATUS_OK)
    {
        *length = fp_blob_length;
        return status;
    }

    if((fp_blob_length > (*length)))
    {
        *length = fp_blob_length;
        return FIT_STATUS_BUFFER_OVERRUN;
    }

    *length = fp_blob_length;

    return FIT_STATUS_OK;

#else

    return FIT_STATUS_NODE_LOCKING_NOT_SUPP;

#endif /* ifdef FIT_USE_NODE_LOCKING */

}
