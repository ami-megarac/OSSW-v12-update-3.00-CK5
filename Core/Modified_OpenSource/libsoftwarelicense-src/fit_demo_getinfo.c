/****************************************************************************\
**
** fit_demo_getinfo.c
**
** Defines functionality for get info API on sentinel fit based licenses for 
** embedded devices.
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

#ifdef FIT_USE_LEGACY_API

#ifdef FIT_USE_SYSTEM_CALLS
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#endif

#include "fit_internal.h"
#include "fit_debug.h"
#include "fit_mem_read.h"
#include "fit_capabilities.h"
#include "fit_consume.h"

/* Constants ****************************************************************/

// #define TEMP_BUF_LEN 41

/* Global Data **************************************************************/

static int feature_count = 0;

/* Function Prototypes ******************************************************/

/* Functions ****************************************************************/

static uint32_t  buffer_offset;
static uint32_t  buffer_size;
static char     *buffer;

static uint32_t  pp_feature_count;
static fit_boolean_t  ppart_id = FIT_FALSE;
static fit_tag_id_t my_last_tag = FIT_END_TAG_ID;

#ifdef FIT_USE_COMX
#include "comx.h"
#include "comx_dev_api.h"
static void     *ctx = NULL;
#endif // FIT_USE_COMX

static void pr_getinfo(const char *format, ...)
{
#ifdef FIT_USE_COMX
    uint16_t len = 0;
#endif
    va_list arg;

    va_start (arg, format);

#if defined(FIT_USE_COMX) && !(defined(FIT_USE_LINUX))
    (void)buffer_size;
    len = vsprintf(buffer, format, arg);
    if(len)
    {
        comx_dev_rt_data((uint8_t *) buffer, len, (comx_session*) ctx);
    }
#else
    if (buffer_offset < buffer_size) {
        buffer_offset += (uint32_t)vsprintf(buffer + buffer_offset, format, arg);
    }
#endif

    va_end (arg);
}

static uint32_t read_val (uint32_t length, fit_pointer_t *pdata)
{
	uint32_t x;
    switch (length) {
        case 2:  x = (uint16_t) fit_read_word(pdata->data, pdata->read_byte)/2 - 1; break;/*lint !e732 */
        case 4:  x = fit_read_dword(pdata->data, pdata->read_byte);      break;
        case 8:  x = (uint32_t) fit_read_ulonglong(pdata->data, pdata->read_byte);  break;
        default: x = 0; break;
    }
    return x;
}

/**
 *
 * fit_getlicensedata_cb
 *
 * This function will get complete license information for embedded devices like
 * license header information, license signature data, vendor information, and like
 * license property information i.e. license is perpetual or not, start date, end date,
 * counter information etc.
 *
 * @param IN  \b  tagid         \n  identifier of the value being returned in pdata
 *
 * @param IN  \b  pdata         \n  pointer to data corresponding to passed in tag id.
 *
 * @param IN  \b  length        \n  length of data
 *
 * @param IO  \b  stop_parse    \n  set to value FIT_TRUE to stop further calling the callback fn,
 *                                  otherwise set to value FIT_FALSE.
 *
 * @param IN  \b  opdata       \n  pointer to opdata parameter given in get info 
 *
 * @param IN  \b  license       \n  Start address of the license in binary format.
 *
 */
fit_status_t fit_getlicensedata_cb (fit_tag_id_t tagid,
                                    fit_pointer_t *pdata,
                                    uint32_t length,
                                    fit_boolean_t *stop_parse,/*lint !e715 */
                                    void *opdata,/*lint !e715 */
                                    fit_pointer_t *license)
{
    uint32_t x;
    char str[32] = {0};
    fit_status_t status = FIT_STATUS_OK;

    if (((tagid == FIT_END_DATE_TAG_ID) || (tagid == FIT_START_DATE_TAG_ID) ||
        (tagid == FIT_CUSTOM_ATTR_KEY_TAG_ID) || (tagid == FIT_PERPETUAL_TAG_ID)) && (!pp_feature_count)) {
        pr_getinfo("\n");
        pr_getinfo(LM_FEAT_COUNT_TAG"%u\n", feature_count);
        feature_count = 0;
        pp_feature_count = 1;
    }


    switch (tagid) {/*lint !e788 */
    case FIT_LICENSE_TAG_ID:                    feature_count = 0;
                                                break;
    case FIT_ALGORITHM_ID_TAG_ID:               x = read_val(length, pdata);
                                                pr_getinfo(LM_ALGORITHM_ID_TAG"%lu\n", x);
                                                /*
	                                            switch (x) {
                                                    case FIT_RSA_2048_ADM_PKCS_V15_ALG_ID: pr_getinfo("RSA_2048"); break;
                                                    case FIT_AES_128_OMAC_ALG_ID:          pr_getinfo("AES_OMAC"); break;
                                                    default:  pr_getinfo("%llu", x);
                                                }
                                                */
                                                break;

    case FIT_LICGEN_VERSION_TAG_ID:             x = read_val(length, pdata);
                                                pr_getinfo(LM_LICGEN_VER_INFO_TAG"%lu\n", x);
                                                break;

    case FIT_LM_VERSION_TAG_ID:                 x = read_val(length, pdata);
                                                pr_getinfo(LM_LM_VER_INFO_TAG"%lu\n", x);
                                                break;

    case FIT_UID_TAG_ID:                        pr_getinfo(LM_UID_INFO_TAG"\n");
                                                /* Get the license unique UID value.*/
//    											fitptr.data = pdata->data;
//    											fitptr.length = FIT_UID_LEN;
//    											fitptr_memcpy(v2c->lic.header.uid, &fitptr);
                                                //*stop_parse = FIT_FALSE;
                                                break;

    case FIT_REQUIREMENTS_TAG_ID:               status = fit_get_lic_capb_str(pdata, str,
                                                    (uint16_t)sizeof(str), license);
                                                if (status == FIT_STATUS_OK)
                                                {
                                                    pr_getinfo(LM_REQR_ID_TAG"%s\n", str);
                                                }
                                                break;

    case FIT_UPDATE_COUNTER_TAG_ID:             x = read_val(length, pdata);
                                                pr_getinfo(LM_UPDATE_COUNTER_TAG"%lu\n", x);
                                                break;

#ifdef FIT_USE_NODE_LOCKING
	case FIT_FP_TAG_ID:                         {
    	                                            fit_fingerprint_t fp = {0};
    	                                            int i;

                                                    status = fit_get_fingerprint(pdata, &fp, license);
                                                    if (status == FIT_STATUS_OK && fp.magic == 0x666D7446) {  /* 'fitF' */
                                                        pr_getinfo(LM_FP_ALG_ID_TAG"%u\n"LM_FP_HASH_TAG, fp.algid);
                                                        for (i = 0; i < FIT_DM_HASH_SIZE; i++) {
                                                            pr_getinfo("%02X ", fp.hash[i]);
                                                        }
                                                    }
                                                    pr_getinfo("\n");
                                                    break;
                                                }
#endif /* ifdef FIT_USE_NODE_LOCKING */

    case FIT_ID_LC_TAG_ID:                      /* tag for license container ID. */
                                                x  = fit_read_dword(pdata->data, pdata->read_byte)/2 - 1;
                                                pr_getinfo(LM_CONTAINER_INFO_TAG"%lu\n", x);
                                                break;

    case FIT_LIC_CONT_UUID_TAG_ID:              /* tag for uuid (license container 16 byte id) */
                                                {
                                                    uint32_t i;
                                                    pr_getinfo(LM_CONTAINER_UUID_TAG"");
                                                    for (i = 0; i < length; i++) {
                                                        pr_getinfo("%02X ", fit_read_byte((pdata->data)+i, pdata->read_byte));
                                                    }
                                                    pr_getinfo("\n");
                                                    break;
                                                }

    case FIT_LICGEN_SEQ_UID_TAG_ID:             /* tag for license container ID. */
                                                x = read_val(length, pdata);
                                                pr_getinfo(LM_LICGEN_UID_TAG"%lu\n", x);
                                                break;

    case FIT_LICGEN_SEQ_TXUID_TAG_ID:           /* tag for license container ID. */
                                                x = read_val(length, pdata);
                                                pr_getinfo(LM_LICGEN_TXN_UID_TAG"%lu\n", x);
                                                break;

    case FIT_LICGEN_SEQ_TXUPT_CNT_TAG_ID:       /* tag for license container ID. */
                                                x = read_val(length, pdata);
                                                pr_getinfo(LM_LICGEN_TXN_UPTCNT_TAG"%lu\n", x);
                                                break;

    case FIT_VENDOR_ID_TAG_ID:                  x = read_val(length, pdata);
                                                pr_getinfo(LM_VENDOR_INFO_TAG"%lu\n", x);
                                                break;

    case FIT_PRODUCT_ARRAY_TAG_ID:              //PRINT("FIT_PRODUCT_TAG_ID");
                                                break;

    case FIT_PRODUCT_ID_TAG_ID:                 x = read_val(length, pdata);
                                                pr_getinfo(LM_PRODUCT_ID_TAG"%lu\n", x);
                                                break;

    case FIT_PRODUCT_PART_TAG_ID:               pp_feature_count = 1;
                                                break;

    case FIT_PRODUCT_PART_ID_TAG_ID:            x = read_val(length, pdata);
                                                pr_getinfo(LM_PRODUCT_PART_ID_TAG"%lu\n", x);
                                                ppart_id = FIT_TRUE;
                                                break;

    case FIT_LIC_PROP_TAG_ID:                   if(ppart_id == FIT_FALSE)
                                                {
                                                    pp_feature_count = 1;
                                                }
                                                break;

    case FIT_CUSTOM_ATTR_KEY_TAG_ID:
    case FIT_SYSTEM_ATTR_KEY_TAG_ID:
    case FIT_PROD_CUSTOM_ATTR_KEY_TAG_ID:       pdata->length = length;
                                                if (fit_fitptr_memcpy((uint8_t*)str, sizeof(str), pdata) != 0)
                                                {
                                                    return FIT_STATUS_BUFFER_OVERRUN;
                                                }
                                                pr_getinfo(LM_CUSTOM_ATTR_KEY_ID_TAG"%s\n", str);
                                                break;

    case FIT_CUSTOM_ATTR_KEY_VALUE_TAG_ID:
    case FIT_SYSTEM_ATTR_KEY_VALUE_TAG_ID:
    case FIT_PROD_CUSTOM_ATTR_KEY_VALUE_TAG_ID: pdata->length = length;
                                                if (fit_fitptr_memcpy((uint8_t*)str,  sizeof(str), pdata) != 0)
                                                {
                                                    return FIT_STATUS_BUFFER_OVERRUN;
                                                }
                                                pp_feature_count = 1;
                                                pr_getinfo(LM_CUSTOM_ATTR_KEY_VAL_TAG"%s\n", str);
                                                break;

    case FIT_PERPETUAL_TAG_ID:                  x = read_val(length, pdata);
                                                pr_getinfo(LM_PERPETUAL_TAG"%lu\n", x);
                                                break;

    case FIT_START_DATE_TAG_ID:                 x = read_val(length, pdata);
                                                pr_getinfo(LM_START_DATE_TAG"%lu\n", x);
                                                break;

    case FIT_END_DATE_TAG_ID:                   x = read_val(length, pdata);
                                                pr_getinfo(LM_END_DATE_TAG"%lu\n", x);
                                                break;

    case FIT_FEATURE_ID_TAG_ID:                 if ((my_last_tag != FIT_FEATURE_ID_TAG_ID) && (pp_feature_count))
                                                {
                                                    pr_getinfo(LM_FEATURE_ID_TAG);
                                                }
                                                x = read_val(length, pdata);
                                                pr_getinfo("%lu,", x);
                                                ++feature_count;
                                                pp_feature_count = 0;
                                                ppart_id = FIT_FALSE;
                                                break;

    case FIT_CONCURRENCY_LIMIT_ID:              x = read_val(length, pdata);
                                                if (x ==0)
                                                {
                                                    pr_getinfo(LM_CONCUR_LIMIT_TAG"unlimited\n");
                                                }
                                                else
                                                {
                                                    pr_getinfo(LM_CONCUR_LIMIT_TAG"%lu\n", x);
                                                }
                                                break;
    default:
        break;

    }

    my_last_tag = tagid;
    return status;

}

/**
 *
 * fit_testgetinfodata
 *
 * This function will test get license info API. It will try to fetch license
 * information like licgen version, list of product ID's and each product license
 * property information. Then with license information it will create a string of
 * license info and passed this string to calling function.
 *
 * @param IN    licenseData \n Pointer to license data for which information is
 *                             sought.
 *
 * @param OUT   pgetinfo    \n On return will contain the information sought in
 *                             form of string.
 *
 * @param OUT   getinfolen  \n On return this will contain length of data contained
 *                             in pgetinfo
 *
 */
fit_status_t fit_testgetinfodata(fit_pointer_t *licenseData,
                                 uint8_t       *pgetinfo,
                                 uint32_t      *getinfolen,
                                 void          *context)/*lint !e715 */
{
    fit_status_t status = FIT_STATUS_OK;

    DBG(FIT_TRACE_INFO, "\nTest case:Get Info ---------\n");

    if (pgetinfo == NULL || *getinfolen == 0)
        return FIT_STATUS_INSUFFICIENT_MEMORY;

    buffer_offset = 0;
    buffer_size   = *getinfolen;
    buffer        = (char*)pgetinfo;
    feature_count = 0;
#ifdef FIT_USE_COMX
    ctx = context;
#endif // #ifdef FIT_USE_COMX
    /* Parse license data and get requested license data */
    status = fit_licenf_get_info(licenseData, (fit_get_info_callback) fit_getlicensedata_cb, pgetinfo);
    if (status != FIT_STATUS_OK)
    {
        *getinfolen = 0;
    } else {
        *getinfolen = buffer_offset;
    }

    return status;
}
#endif // #ifdef FIT_USE_LEGACY_API
