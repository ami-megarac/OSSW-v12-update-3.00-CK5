/****************************************************************************\
**
** fit_capabilities.c
**
** Defines functionality for checking core capabilities against license requirements.
** 
** Copyright (C) 2017-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

/* Constants ****************************************************************/

/* Required Includes ********************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#include "fit_capabilities.h"
#include "fit_debug.h"
#include "fit.h"
#include "fit_internal.h"
#include "fit_parser.h"
#include "fit_mem_read.h"
#include "fit_hwdep.h"
#include "fit_alloc.h"
#include "fit_internal.h"
#include <string.h>

/* hard coded values for all possible types of core capabilities combination */
static fit_pre_def_base64_str_t base64_table[] = {
    {"AQAAAAAAAAA=", {0x01,0x00}}, /*lint !e784 RSA only */
    {"CQAAAAAAAAA=", {0x09,0x00}}, /*lint !e784 RSA and CLOCK */
    {"IQAAAAAAAAA=", {0x21,0x00}}, /*lint !e784 RSA and NODELOCK */
    {"KQAAAAAAAAA=", {0x29,0x00}}, /*lint !e784 RSA, CLOCK and NODELOCK */
    {"BAAAAAAAAAA=", {0x04,0x00}}, /*lint !e784 AES only */
    {"DAAAAAAAAAA=", {0x0c,0x00}}, /*lint !e784 AES and CLOCK */
    {"JAAAAAAAAAA=", {0x24,0x00}}, /*lint !e784 AES and NODELOCK */
    {"LAAAAAAAAAA=", {0x2c,0x00}}, /*lint !e784 AES, CLOCK and NODELOCK */
};


/* Forward Declarations *****************************************************/

static uint64_t fit_get_pow_2(int16_t in);


/* Function Definitions *****************************************************/

/**
 *
 * get_dec_str_from_enc_str
 *
 * Returns decoded value of encoded core capabilities string.
 *
 * @param IN    enc_str   \n base64 encoded core capabilities string
 *
 * @param IN    enc_len   \n length of above base64 encoded string.
 *
 * @param OUT   dec_str   \n On return it will contain the decoded value of passed
 *                           in encoded string.
 *
 * @param IO    dec_len   \n length of decoded string.
 *
 */
fit_status_t get_dec_str_from_enc_str (const uint8_t *enc_str,
                                       uint16_t enc_len,
                                       uint8_t *dec_str,
                                       uint16_t *dec_len)
{
    /* Contains success or error code.*/
    fit_status_t status = FIT_STATUS_ITEM_NOT_FOUND;
    uint16_t cntr       = 0;

    if ( *dec_len < FIT_CAPB_DECODED_LEN)
    {
        return FIT_STATUS_INSUFFICIENT_MEMORY;
    }

    for(cntr = 0; cntr < (sizeof(base64_table)/sizeof(struct fit_pre_def_base64_str)); cntr++)
    {
        if( fit_memcmp(enc_str, (const uint8_t *)base64_table[cntr].base64encstr, enc_len) == 0 )
        {
            (void)fit_memcpy((void *)dec_str, *dec_len,
                (void *)(base64_table[cntr].base64decstr), FIT_CAPB_DECODED_LEN);
            *dec_len = FIT_CAPB_DECODED_LEN;
            status = FIT_STATUS_OK;
            break;
        }
    }

    return status;
}
/**
 *
 * \skip fit_get_core_capabilities
 *
 * This function is used to know what all capabilities fit core supports.
 *
 * @param OUT   capbstr \n On return will contain fit core capabilities in form of binary data
 *
 * @param IO    len     \n length of above fit core capabilities.
 *
 * @return Fit core capabilities in form of binary string and its length
 *
 */
fit_status_t fit_get_core_capabilities(uint8_t *capbstr, uint16_t *len)
{
    uint64_t core_capabilities = 0;

#if defined (FIT_USE_RSA_SIGNING)
        core_capabilities |= (fit_get_pow_2((uint64_t)FIT_CAPB_RSA_SIGNING));
#endif

#if defined (FIT_USE_PEM)
        core_capabilities |= (fit_get_pow_2(FIT_CAPB_PEM));
#endif

#if defined (FIT_USE_AES_SIGNING)
        core_capabilities |= (fit_get_pow_2(FIT_CAPB_AES_SIGNING));
#endif

#if defined (FIT_USE_CLOCK)
        core_capabilities |= (fit_get_pow_2(FIT_CAPB_CLOCK));
#endif

#if defined (FIT_USE_NODE_LOCKING)
        core_capabilities |= (fit_get_pow_2(FIT_CAPB_NODE_LOCKING));
#endif

#if defined (FIT_USE_PERSISTENT)
        core_capabilities |= (fit_get_pow_2(FIT_CAPB_USE_PERSISTENCE));
#endif

    if (core_capabilities <= 0xFFFF)
    {
        if (*len < sizeof(uint16_t))
        {
            return FIT_STATUS_INSUFFICIENT_MEMORY;
        }
        *len = sizeof(uint16_t);
        (void)fit_memcpy((uint8_t *)capbstr, sizeof(uint16_t),
            (uint8_t *)&core_capabilities, sizeof(uint16_t));
    }
    else if (core_capabilities <= 0xFFFFFFFF)
    {
        if (*len < sizeof(uint32_t))
        {
            return FIT_STATUS_INSUFFICIENT_MEMORY;
        }
        *len = sizeof(uint32_t);
        (void)fit_memcpy((uint8_t *)capbstr, sizeof(uint32_t),
            (uint8_t *)&core_capabilities, sizeof(uint32_t));
    }
    else
    {
        if (*len < sizeof(uint64_t))
        {
            return FIT_STATUS_INSUFFICIENT_MEMORY;
        }
        *len = sizeof(uint64_t);
        (void)fit_memcpy((uint8_t *)capbstr, sizeof(uint64_t),
            (uint8_t *)&core_capabilities, sizeof(uint64_t));
    }

    return FIT_STATUS_OK;
}

/**
 *
 * \skip fit_check_core_capabilities
 *
 * This function will check the core capabilities against the requirements of the
 * license string.
 *
 * @param IN    license     \n Pointer to fit_pointer_t structure containing license
 *                             data. To access the license data in different types of
 *                             memory (FLASH, E2, RAM), fit_pointer_t is used.
 *
 * @return FIT_STATUS_OK if core supports license requirements; otherwise appropriate
 *         error code.
 *
 */
fit_status_t fit_check_core_capabilities(fit_pointer_t *license)
{
    fit_status_t status     = FIT_STATUS_UNKNOWN_ERROR;
    fit_op_data_t opdata    = {0};
    uint16_t capb64len      = 0;
    /* contains fit core capabilities value */
    uint8_t corecapb[sizeof(uint64_t)*2] = {0};
    uint16_t cntr           = 0;
    uint8_t licbuff[16]     = {0};
    uint8_t licbuffenc[12]  = {0};
    uint16_t licbuffsize    = sizeof(licbuff);
    uint32_t lm_version     = 0;
    fit_pointer_t capbdata  = {(void*)0};
    fit_lic_scope_t lic_scope_item  = {0};

    DBG(FIT_TRACE_INFO, "[fit_check_core_capabilities]: license=0x%p length=%hd\n",
        license->data, license->length);

    /* find the LM verison in the license string */
    (void)fit_memset((uint8_t *)&opdata, 0, (int)sizeof(fit_op_data_t));
    (void)fit_memset(&lic_scope_item, 0, sizeof(fit_lic_scope_t));
    status = fit_licenf_initialize_scope(&lic_scope_item);
    if(status != FIT_STATUS_OK)
    {
        return status;
    }

    opdata.flags = FIT_FIND_ITEM_FIRST;
    opdata.tagid = FIT_LM_VERSION_TAG_ID;
    opdata.type = FIT_INTEGER;
    opdata.operation = (uint8_t)FIT_OP_GET_DATA_ADDRESS;
    opdata.status = FIT_STATUS_OK;
    status = fit_license_parser_execute(license, FIT_LICENF_LICENSE_SCOPE_GLOBAL, &lic_scope_item,
                FIT_FIND_ITEM_FIRST, &opdata);
    if (status == FIT_STATUS_OK && (opdata.parserstatus == FIT_INFO_STOP_PARSE))
    {
        if (opdata.length == sizeof(uint16_t))
        {
            uint16_t temp1                  = 0;

            status = fit_read_word_safe(opdata.parserdata.addr, license->read_byte,
                license, (uint16_t *)&temp1);
            if(status != FIT_STATUS_OK)
            {
                return status;
            }
            lm_version = (uint32_t)((temp1 / 2) - 1);
        }
        else if (opdata.length == sizeof(uint32_t))
        {
            uint32_t temp1 = 0;

            /* This represents integer data in form of string, so need to do calculations.*/
            status = fit_read_dword_safe(opdata.parserdata.addr, license->read_byte,
                license, (uint32_t *)&temp1);
            if(status != FIT_STATUS_OK)
            {
                return status;
            }

            lm_version = temp1;
        }
    }
    else
    {
        return status;
    }


    /* find licgen version using the next flag; it should return error */
    (void)fit_memset((uint8_t *)&opdata, 0, (int)sizeof(fit_op_data_t));
    opdata.flags = FIT_FIND_ITEM_NEXT;
    opdata.tagid = FIT_REQUIREMENTS_TAG_ID;
    opdata.type = FIT_BINARY;
    opdata.operation = (uint8_t)FIT_OP_GET_DATA_ADDRESS;
    opdata.status = FIT_STATUS_OK;

    status = fit_license_parser_execute(license, FIT_LICENF_LICENSE_SCOPE_GLOBAL, &lic_scope_item,
            FIT_FIND_ITEM_NEXT, &opdata);
    if (status != FIT_STATUS_OK || (status == FIT_STATUS_OK && opdata.parserstatus != FIT_INFO_STOP_PARSE))
    {
        /* Requirements string is not present in the license string. */
        if (lm_version < 296)
        {
            return FIT_STATUS_OK;
        }
        else
        {
            return FIT_STATUS_LIC_REQ_NOT_SUPP;
        }
    }

    capbdata.data = opdata.parserdata.addr;
    capbdata.length = opdata.length;
    capbdata.read_byte = license->read_byte;

    if (lm_version <= 296)
    {
        (void)fit_fitptr_memcpy(licbuffenc, sizeof(licbuffenc), &capbdata);

        status = get_dec_str_from_enc_str(licbuffenc,
            (uint16_t)opdata.length, licbuff, &licbuffsize);
        if (status != FIT_STATUS_OK)
        {
            return FIT_STATUS_OK;
        }
    }
    else
    {
	/*
	* safety check
	*/
	if( sizeof(licbuff ) <= opdata.length )
	    return FIT_STATUS_BUFFER_OVERRUN;

        (void)fit_fitptr_memcpy(licbuff, sizeof(licbuff), &capbdata);
        licbuffsize = (uint16_t)opdata.length;
    }

    /* Get core capabilities */
    capb64len = sizeof(corecapb);
    (void)fit_get_core_capabilities(corecapb, &capb64len);

    for (cntr = 0; cntr < licbuffsize; ++cntr)
    {
	/*
	 * check if requirements length is beyond length of capabilities and return error
	 */
        if( cntr >= capb64len ) 
        {
            /*
             * we check if upper bytes have a bit of 1 set and then we return error
	     * disable pclint false positive warning 661
             */
		
            if( (0xff & licbuff[cntr]) != 0) //lint !e661
                return FIT_STATUS_LIC_REQ_NOT_SUPP;
            else    
                continue;
        }

       /* Check whether fit core supports the license requirements. If not return error */
        if ((corecapb[cntr] & licbuff[cntr]) == licbuff[cntr])
        {
            status = FIT_STATUS_OK;
        }
        else
        {
            return FIT_STATUS_LIC_REQ_NOT_SUPP;
        }
    }

    DBG(FIT_TRACE_INFO, "[fit_check_core_capabilities]: return %d\n",(unsigned int)status);

    return status;/*lint !e438 */
}

/**
 *
 * \skip fit_get_lic_capb_str
 *
 * This function will get the license requirement in the form of string.
 *
 * @param IN    pdata     \n Pointer to license data where license requirement are stored.
 *
 * @param OUT   string     \n On return it will contain the license requirements in
 *                            form of string.
 *
 * @param IN    strlen     \n Length of above string.
 *
 * @return FIT_STATUS_OK if license requirements are fetched properly; otherwise appropriate
 *         error code.
 *
 */
fit_status_t fit_get_lic_capb_str(fit_pointer_t *pdata, 
                                  char *string, 
                                  uint16_t stringlen,/*lint !e715 */
                                  fit_pointer_t *license)
{
    uint64_t liccapb        = 0;
    uint32_t len            = 0;
    char str[32] = {0};
    fit_status_t status     = FIT_STATUS_OK;
    uint8_t licbuff[32]    = {0};
    uint16_t capblen        = 0;
    uint8_t *licbuffptr     = NULL;
    fit_op_data_t opdata    = {0};
    uint32_t lm_version     = 0;
    fit_lic_scope_t lic_scope_item  = {0};

    status = fit_read_dword_safe(pdata->data-4, pdata->read_byte, license, &len);
    if(status != FIT_STATUS_OK)
        return status;

    /* find the LM verison in the license string */
    (void)fit_memset((uint8_t *)&opdata, 0, (int)sizeof(fit_op_data_t));
    (void)fit_memset(&lic_scope_item, 0, sizeof(fit_lic_scope_t));
    status = fit_licenf_initialize_scope(&lic_scope_item);
    if(status != FIT_STATUS_OK)
    {
        return status;
    }

    opdata.flags = FIT_FIND_ITEM_FIRST;
    opdata.tagid = FIT_LM_VERSION_TAG_ID;
    opdata.type = FIT_INTEGER;
    opdata.operation = (uint8_t)FIT_OP_GET_DATA_ADDRESS;
    opdata.status = FIT_STATUS_OK;
    status = fit_license_parser_execute(license, FIT_LICENF_LICENSE_SCOPE_GLOBAL, &lic_scope_item,
                FIT_FIND_ITEM_FIRST, &opdata);
    if (status == FIT_STATUS_OK && (opdata.parserstatus == FIT_INFO_STOP_PARSE))
    {
        if (opdata.length == sizeof(uint16_t))
        {
            uint16_t temp1                  = 0;

            status = fit_read_word_safe(opdata.parserdata.addr, license->read_byte,
                license, (uint16_t *)&temp1);
            if(status != FIT_STATUS_OK)
            {
                return status;
            }
            lm_version = (uint32_t)((temp1 / 2) - 1);
        }
        else if (opdata.length == sizeof(uint32_t))
        {
            uint32_t temp1 = 0;

            /* This represents integer data in form of string, so need to do calculations.*/
            status = fit_read_dword_safe(opdata.parserdata.addr, license->read_byte,
                license, (uint32_t *)&temp1);
            if(status != FIT_STATUS_OK)
            {
                return status;
            }

            lm_version = temp1;
        }
    }
    else
    {
        return status;
    }

    if (lm_version <= 296)
    {
        capblen = sizeof(licbuff);
        status = get_dec_str_from_enc_str(pdata->data, (uint16_t)len,
            licbuff, &capblen);
        if (status != FIT_STATUS_OK)
        {
            return FIT_STATUS_OK;
        }
        licbuffptr = licbuff;
    }
    else
    {
        licbuffptr = pdata->data;
        capblen = (uint16_t)len;
    }

    /* Get license requirement from license string and compare against core
     * capabilities. Core compares in multiple of 8 bytes 
     */
    if (fit_memcpy((uint8_t*)&liccapb, sizeof(liccapb), licbuffptr, capblen) != 0)
    {
        return FIT_STATUS_BUFFER_OVERRUN;
    }
    (void)fit_utoa(liccapb, str);
    (void)fit_strcat(string, stringlen, str);

    return status;
}

/**
 *
 * \skip fit_get_pow_2
 *
 * This function is used to calculate 2 pow in.
 *
 * @return 2^in
 *
 */
static uint64_t fit_get_pow_2(int16_t in)
{
    uint64_t    out     = 1;

    return out << (in%64);
}

