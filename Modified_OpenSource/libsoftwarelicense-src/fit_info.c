/****************************************************************************\
**
** fit_info.c
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

#ifdef FIT_USE_SYSTEM_CALLS
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#endif

#include "fit_internal.h"
#include "fit_debug.h"
#include "fit_mem_read.h"
#include "fit_capabilities.h"
#include "fit_parser.h"
#include "fit_info.h"

/* Constants ****************************************************************/

/* Global Data **************************************************************/

/* Function Prototypes ******************************************************/

/* Functions ****************************************************************/

#ifdef FIT_USE_COMX
#include "comx.h"
#include "comx_dev_api.h"
static void     *ctx = NULL;
#endif // FIT_USE_COMX


uint8_t fit_info_suppress_output = 0; //lint !e765

#define FIT_PRINTF_BUFFER_SIZE 256
static char write_buffer[FIT_PRINTF_BUFFER_SIZE];

static void pr_info(const char *format, ...)
{
    char *s;
    int len = 0;
    va_list arg;

    if (0 == fit_info_suppress_output)
    {
        s = write_buffer;
        va_start (arg, format);
        len = vsnprintf(write_buffer, FIT_PRINTF_BUFFER_SIZE, format, arg);
        va_end (arg);

        if (len > FIT_PRINTF_BUFFER_SIZE) {
            len = FIT_PRINTF_BUFFER_SIZE;
        }

        if(len)
        {
            while (*s)
            {
                fit_putc(*s++);
            }
        }
    }
}

/***********************************************************************************************************************/

static void get_one (char *tag_name, fit_license_t *lic, fit_lic_scope_t *scope,
                     fit_tag_id_t tag_id, fit_wire_type_t tag_type,
                     int ignore_not_found)
{
    fit_status_t status = FIT_STATUS_UNKNOWN_ERROR;
    fit_info_item_t item;

    item.tag_id = tag_id;   //FIT_LIC_CONT_UUID_TAG_ID;
    item.type   = tag_type; //FIT_BINARY;
    item.object.intval = 0;

    status = fit_licenf_find_item(lic, NULL, scope, FIT_FIND_ITEM_FIRST, &item);

    if (FIT_STATUS_OK != status) {
        if ( (ignore_not_found) && (status == FIT_STATUS_ITEM_NOT_FOUND) ) {
            return;
        }
        pr_info("%s=error %d: %s\n", tag_name, (unsigned int)status, fit_get_error_str(status));
        return;
    }

    switch (tag_type) {
    case FIT_BINARY : {
                        uint32_t length, i;
                        char str[256];

                        length = item.object.data_ptr.length;
                        if (tag_id == FIT_REQUIREMENTS_TAG_ID) {
                            str[0] = 0;
                            status = fit_get_lic_capb_str(&item.object.data_ptr, str, sizeof(str),lic->license);
                            if (FIT_STATUS_OK == status) {
                                pr_info("%s=%s\n", tag_name, str);
                            }
                        }
                        else
                        {
                            // PRINT("BIN length: %u, data: ", length);
                            pr_info("%s=", tag_name);
                            for (i = 0; i < length; i++) {
                                pr_info("%02X ", fit_read_byte((item.object.data_ptr.data)+i, item.object.data_ptr.read_byte));
                            }
                            pr_info("\n");
                        }
                        break;
                     }

    case FIT_INTEGER: {
                          char str[64];

                          pr_info("%s=%s\n", tag_name, fit_utoa(item.object.intval, str));
                          break;
                      }

    case FIT_STRING:  {
                         char str[256];

                         status = FIT_STATUS_OK;
                         if (fit_fitptr_memcpy((uint8_t*)str,  sizeof(str), &item.object.data_ptr)!=0) {
                             status = FIT_STATUS_BUFFER_OVERRUN;
                         }
                         if (status != FIT_STATUS_OK) {
                             pr_info("%s=[error %i]\n", tag_name, (int)status);
                         }
                         break;
                      }

    default:          pr_info("unknown object type\n");
                      // br eak;
    }

}

/****************************************************************************************************************************************/

static void enum_globals (fit_license_t *license)
{
    fit_lic_scope_t lic_scope_item    = {0};

    get_one("LicVer",   license, &lic_scope_item, FIT_LICGEN_VERSION_TAG_ID, FIT_INTEGER, 0);
    get_one("LMVer",    license, &lic_scope_item, FIT_LM_VERSION_TAG_ID, FIT_INTEGER, 0);
    get_one("VID",      license, &lic_scope_item, FIT_VENDOR_ID_TAG_ID, FIT_INTEGER, 0);
    get_one("UUID",     license, &lic_scope_item, FIT_LIC_CONT_UUID_TAG_ID, FIT_BINARY, 1);
    get_one("Lic_reqr", license, &lic_scope_item, FIT_REQUIREMENTS_TAG_ID, FIT_BINARY, 1);
    get_one("Upd_cntr", license, &lic_scope_item, FIT_UPDATE_COUNTER_TAG_ID, FIT_INTEGER, 1);
    get_one("AlgID",    license, &lic_scope_item, FIT_ALGORITHM_ID_TAG_ID, FIT_INTEGER, 0);
}

/****************************************************************************************************************************************/

static fit_status_t fit_get_feature_info (fit_license_t *license, uint32_t feat, uint32_t prod_id)
{
    fit_status_t status = FIT_STATUS_UNKNOWN_ERROR;
    fit_feature_ctx_t feature_h = {0};

    /* Look for feature id and fill the path for that feature id in context */
    status = fit_licenf_find_feature(license, feat, FIT_FIND_FEATURE_FIRST, &feature_h);

    if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_ERROR, "fit_licenf_find_feature error status %d\n",
            (unsigned int)status);
        return status;
    }

    if (prod_id != feature_h.feature_info.product_id)
    {
        while (FIT_STATUS_OK == status && prod_id != feature_h.feature_info.product_id) {

            status = fit_licenf_find_feature(license, feat, FIT_FIND_FEATURE_NEXT, &feature_h);
            if (FIT_STATUS_FEATURE_NOT_FOUND == status) break;

            if (status != FIT_STATUS_OK) {
                DBG(FIT_TRACE_ERROR, "fit_licenf_find_feature error status %d: %s\n",
                    (unsigned int)status, fit_get_error_str(status));
                break;
            }
        }
    }

    if (status != FIT_STATUS_OK && prod_id != feature_h.feature_info.product_id)
    {
        return(status);
    }

    pr_info("  FID=%u, ", feat);
    pr_info("PID=%u, ", feature_h.feature_info.product_id);

    if (feature_h.feature_info.license_model.isperpetual) {
        pr_info("Perpetual=1, ");
    } else {
        pr_info("Start=%u, ", feature_h.feature_info.license_model.startdate);
        pr_info("End=%u, ", feature_h.feature_info.license_model.enddate);
    }

    if (FIT_INVALID_CONCURRENCY_VALUE != feature_h.feature_info.license_model.concurrency.limit) {
      pr_info("Concurrency=%u, ", feature_h.feature_info.license_model.concurrency.limit);
    }

    pr_info("\n");
    return status;
}

/****************************************************************************************************************************************/

static fit_status_t enum_features (fit_license_t *license)
{
    fit_status_t status = FIT_STATUS_UNKNOWN_ERROR;
    fit_info_item_t item;
    fit_lic_scope_t lic_scope_item    = {0};
    fit_lic_scope_t lic_scope_prod  = {0};
    fit_lic_scope_t lic_scope_ref   = {0};
    uint32_t prod_id = 0;

    /* find the first product id in the license string*/
    (void)fit_memset((uint8_t *)&item, 0, sizeof(fit_info_item_t));
    item.tag_id = FIT_PRODUCT_ID_TAG_ID;
    item.type = FIT_INTEGER;
    status = fit_licenf_find_item(license, FIT_LICENF_LICENSE_SCOPE_GLOBAL, &lic_scope_prod,
        FIT_FIND_ITEM_FIRST, &item);
    if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_ERROR, "fit_licenf_find_item error status %d\n",
            (unsigned int)status);
        return status;
    }
    prod_id = (uint32_t)item.object.intval;

    do {

        if (fit_memcpy((uint8_t *)&lic_scope_item, sizeof(fit_lic_scope_t),
            (uint8_t *)&lic_scope_prod, sizeof(fit_lic_scope_t)) != 0)
        {
            return FIT_STATUS_BUFFER_OVERRUN;
        }

        /* use last lic path as an reference path */
        if (fit_memcpy((uint8_t *)&lic_scope_ref, sizeof(fit_lic_scope_t),
            (uint8_t *)&lic_scope_item, sizeof(fit_lic_scope_t)) != 0)
        {
            return FIT_STATUS_BUFFER_OVERRUN;
        }

        /* get first feature id of product */
        (void)fit_memset((uint8_t *)&item, 0, sizeof(fit_info_item_t));
        item.tag_id = FIT_FEATURE_ID_TAG_ID;
        item.type = FIT_INTEGER;
        status = fit_licenf_find_item(license, &lic_scope_ref, &lic_scope_item,
            FIT_FIND_ITEM_FIRST, &item);
        if (status != FIT_STATUS_OK)
        {
            DBG(FIT_TRACE_ERROR, "fit_licenf_find_item error status %d\n",
                (unsigned int)status);
            return status;
        }

        status = fit_get_feature_info(license, (uint32_t)item.object.intval, prod_id);
        if (status != FIT_STATUS_OK)
        {
            DBG(FIT_TRACE_ERROR, "fit_get_feature_info error status %d\n",
                (unsigned int)status);
            return status;
        }
        do {
            status = fit_licenf_find_item(license, &lic_scope_ref, &lic_scope_item,
                FIT_FIND_ITEM_NEXT, &item);

            if (status == FIT_STATUS_OK)
            {
                status = fit_get_feature_info(license, (uint32_t)item.object.intval, prod_id);
                if (status != FIT_STATUS_OK)
                {
                    DBG(FIT_TRACE_ERROR, "fit_get_feature_info error status %d\n",
                        (unsigned int)status);
                    return status;
                }
            }

        } while (status != FIT_STATUS_ITEM_NOT_FOUND);

        /* find next product id */
        (void)fit_memset((uint8_t *)&item, 0, sizeof(fit_info_item_t));
        item.tag_id = FIT_PRODUCT_ID_TAG_ID;
        item.type = FIT_INTEGER;
        status = fit_licenf_find_item(license, FIT_LICENF_LICENSE_SCOPE_GLOBAL, &lic_scope_prod,
            FIT_FIND_ITEM_NEXT, &item);
        prod_id = (uint32_t)item.object.intval;

    } while (status != FIT_STATUS_ITEM_NOT_FOUND);

    return FIT_STATUS_OK;
}

/***********************************************************************************************************************************/

static void print_string_getinfo (fit_info_item_t *item)
{
   if (item->type == FIT_STRING) {
     char str[256];
     uint32_t len;

     if (fit_fitptr_memcpy((uint8_t*)str,  sizeof(str), &item->object.data_ptr) == 0) {
       len = item->object.data_ptr.length;
       //pr_info("len: %u, ", len);
       if ( (len > 0) && (len < 255)) {
         str[len] = 0;
         pr_info("\"%s\"", str);
       }
     } else {
       pr_info("FIT_STATUS_BUFFER_OVERRUN\n");
     }
   } else {
     pr_info("Unexpected item type %u\n", item->type);
   }
}

/****************************************************************************************************************************************/

static void enum_custom_attr (fit_license_t *license)
{
    fit_status_t status = FIT_STATUS_UNKNOWN_ERROR;
    fit_lic_scope_t lic_scope_item    = {0};
    fit_info_item_t item;

    (void)fit_memset((uint8_t *)&item, 0, sizeof(fit_info_item_t));
    item.tag_id = FIT_CUSTOM_ATTR_KEY_TAG_ID;
    item.type = FIT_STRING;
    item.object.intval = 0;
    status = fit_licenf_find_item(license, NULL, &lic_scope_item,  FIT_FIND_ITEM_FIRST,  &item);
    if (status != FIT_STATUS_OK) return;

    while (FIT_STATUS_OK == status) {
        pr_info("key=");
        print_string_getinfo(&item);

        pr_info(", val=");

        item.tag_id = FIT_CUSTOM_ATTR_KEY_VALUE_TAG_ID ;
        status = fit_licenf_find_item(license, NULL, &lic_scope_item,  FIT_FIND_ITEM_NEXT,  &item);
        print_string_getinfo(&item);
        pr_info("\n");

        item.tag_id = FIT_CUSTOM_ATTR_KEY_TAG_ID;
        status = fit_licenf_find_item(license, NULL, &lic_scope_item,  FIT_FIND_ITEM_NEXT,  &item);
    }
}

/***********************************************************************************************************************************/

/**
 *
 * fit_info
 *
 * This function will try to fetch license information like licgen version,
 * features, and feature property information.
 *
 * @param IN    licenseData \n Pointer to license data for which information is
 *                             sought.
 *
 */
fit_status_t fit_info( fit_pointer_t *licenseData ) //lint !e765
{
    fit_status_t  status  = FIT_STATUS_OK;
    fit_license_t license = {0};

    status = fit_licenf_construct_license(licenseData, &fit_keys, &license);
    if (status != FIT_STATUS_OK) return status;

    enum_globals(&license);
    (void)enum_features(&license);
    enum_custom_attr(&license);

    return status;
}
