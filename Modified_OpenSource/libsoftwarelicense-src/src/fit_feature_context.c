/****************************************************************************\
**
** fit_feature_context.c
**
** Defines functionality for fit_find_feature and fit_find_item API for embedded devices.
** 
** Copyright (C) 2018, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#include "fit_types.h"
#include "fit_debug.h"
#include "fit_consume.h"
#include "fit_api.h"
#include "fit.h"
#include "fit_mem_read.h"
#include "fit_internal.h"
#include "fit_hwdep.h"
#include <string.h>

/* Constants ****************************************************************/
#define FIT_FEATURE_FIELD                   0u
#define FIT_PERPETUAL_FIELD                 1u
#define FIT_START_DATE_FIELD                2u
#define FIT_END_DATE_FIELD                  3u
#define FIT_CONCURRENCY_FIELD               7u

/* Forward Declarations *****************************************************/

/* Functions ****************************************************************/

/**
 *
 * \skip fit_get_lic_prop_data
 *
 * This function is used for parse license property present in data passed in and
 * fill in fit_licensemodel_t structure.
 *
 * @param IN    pdata   \n Pointer to license property structure data.
 *
 * @param OUT   licmodel    \n Pointer to structure that will contain license property
 *                             data against data passed in.
 *
 */
fit_status_t fit_get_lic_prop_data(fit_pointer_t *pdata,
                                   fit_licensemodel_t *licmodel,
                                   fit_pointer_t *license)/*lint !e818*/
{
    uint16_t cntr       = 0;
    /*
     * Skip_fields represents number of fields to skip or number of fields that
     * does not have any data in license binary.
     */
    uint8_t skip_fields = 0;
    uint8_t cur_index   = 0;
    uint8_t ndx         = 0;
    uint8_t *temp       = pdata->data;
    /* Get the number of fields present in license property data */
    uint16_t num_fields = 0;
    uint16_t field_data = 0;
    uint32_t struct_offset  = 0; 
    fit_status_t status = FIT_STATUS_OK;

    DBG(FIT_TRACE_INFO, "[fit_get_lic_prop]: pdata=%08p # \n", pdata);

    status = fit_read_word_safe(pdata->data, pdata->read_byte, license, &num_fields);
    if(status != FIT_STATUS_OK)
    {
        return status;
    }

    struct_offset  = (num_fields+1)*FIT_PFIELD_SIZE;

    if (licmodel == (void *)0)
    {
        return FIT_STATUS_INVALID_PARAM_2;
    }

    licmodel->concurrency.limit = FIT_INVALID_CONCURRENCY_VALUE;
    licmodel->startdate = FIT_INVALID_START_DATE;
    licmodel->enddate = FIT_INVALID_END_DATE;

    /* Move data pointer to next field.*/
    pdata->data   = pdata->data + FIT_PFIELD_SIZE;

    /* Parse all fields data in a structure.*/
    for( cntr = 0; cntr < num_fields; cntr++)
    {   
        status = fit_read_word_safe(pdata->data, pdata->read_byte, license, &field_data);
        if(status != FIT_STATUS_OK)
        {
            return status;
        }

        /* If field_data is zero, that means the field data is encoded in data part.*/
        if( (field_data == 0) || (field_data%2 == 0))
        {
            ndx   = cur_index;
            /* Go to next index value.*/
            cur_index++;
        }
        /*
         * If value of field_data is odd, that means the tags is not continuous i.e.
         * we need to skip fields by (field_data+1)/2 .
         */
        else if( field_data & 1)
        {
            skip_fields  = (uint8_t)((field_data+1))/2;
            /* skip the fields as it does not contain any data in V2C.*/
            cur_index    = cur_index + skip_fields;

            /* Move data pointer to next field.*/
            pdata->data = pdata->data + FIT_PFIELD_SIZE;
            continue;
        }
        /* field_data contains the field value */
        else
        {
            return FIT_STATUS_INVALID_V2C;
        }

        if (ndx   == FIT_FEATURE_FIELD)
        {
            uint32_t temp1 = 0;

            /* Skip the data part as we are not interested in feature data here */
            status = fit_read_dword_safe(temp+struct_offset, pdata->read_byte, license, &temp1);
            if(status != FIT_STATUS_OK)
            {
                return status;
            }

            struct_offset   = (struct_offset + temp1 + sizeof(uint32_t));
        }
        else if (ndx   == FIT_PERPETUAL_FIELD)
        {
            uint16_t temp1 = 0;

            /* Get the perpetual value */
            status = fit_read_word_safe(pdata->data, pdata->read_byte, license, &temp1);
            if(status != FIT_STATUS_OK)
            {
                return status;
            }
            
            licmodel->isperpetual = (fit_boolean_t) ((temp1 / 2) - 1);
        }
        else if (ndx   == FIT_START_DATE_FIELD)
        {
            uint32_t temp1 = 0;

            /* Get the start time, i.e. date when license becomes valid */
            status = fit_read_dword_safe((temp+struct_offset)+sizeof(uint32_t),
                pdata->read_byte, license, &temp1);
            if(status != FIT_STATUS_OK)
            {
                return status;
            }

            licmodel->startdate = temp1;

            /* 
             * Get to next field data value (for those fields for which field data
             * is encoded in data part.
             */
            status = fit_read_dword_safe(temp+struct_offset, pdata->read_byte, license, &temp1);
            if(status != FIT_STATUS_OK)
            {
                return status;
            }

            struct_offset = (struct_offset + temp1 + sizeof(uint32_t));
        }
        else if (ndx   == FIT_END_DATE_FIELD)
        {
            uint32_t temp1 = 0;

            /* Get the expiration time, i.e time by which license would get expired. */
            status = fit_read_dword_safe((temp+struct_offset)+sizeof(uint32_t),
                pdata->read_byte, license, &temp1);
            if(status != FIT_STATUS_OK)
            {
                return status;
            }

            licmodel->enddate = temp1;

            /* 
             * Get to next field data value (for those fields for which field data
             * is encoded in data part.
             */
            status = fit_read_dword_safe(temp+struct_offset, pdata->read_byte, license, &temp1);
            if(status != FIT_STATUS_OK)
            {
                return status;
            }

            struct_offset = (struct_offset + temp1 + sizeof(uint32_t));
        }
        else if (ndx   == FIT_CONCURRENCY_FIELD)
        {
            uint16_t temp1 = 0;
            uint32_t temp2 = 0;

            /* Get the concurrency count. Since fit 1.4 supports only concurrency limit,
             * so will extract only that field and all other fields would be ignored.
             */
            status = fit_read_word_safe(temp+struct_offset+FIT_POBJECT_SIZE+FIT_PFIELD_SIZE,
                pdata->read_byte, license, &temp1);
            if(status != FIT_STATUS_OK)
            {
                return status;
            }

            licmodel->concurrency.limit = (uint16_t)((temp1 / 2) - 1);

            /* 
             * Get to next field data value (for those fields for which field data
             * is encoded in data part.
             */
            status = fit_read_dword_safe(temp+struct_offset, pdata->read_byte, license, &temp2);
            if(status != FIT_STATUS_OK)
            {
                return status;
            }

            struct_offset   = (struct_offset + temp2 + sizeof(uint32_t));
        }
        else
        {
            /* To be added in case more license model are added */
        }

        /* Move data pointer to next field.*/
        pdata->data = pdata->data + FIT_PFIELD_SIZE;
    }

    pdata->data = temp;

    return status;
}

/**
 *
 * \skip fit_internal_find_feature
 *
 * Find a feature with the specified feature ID in the license
 *
 * @param IN  \b  license   \n Pointer to fit_license_t structure containing license data
 *                             and keys to read data part. To access the license data in
 *                             different types of memory (FLASH, E2, RAM), fit_license_t is used.
 *
 * @param IN  \b  feature_id    \n  feature id which to be looked in license string..
 *
 * @param IN  \b  flags     \n  Tells from which location to start looking for a feature
 *                              in context.
 *
 * @param IN  \b  feature_h \n Structure containing the feature context. Used as a handle for
 *                             a feature.
 *
 */
fit_status_t fit_internal_find_feature(fit_license_t *license_t,
                                       uint32_t feature_id,
                                       uint32_t flags,
                                       fit_feature_ctx_t* feature_h)
{
    fit_status_t status             = FIT_STATUS_UNKNOWN_ERROR;
    fit_pointer_t fitptr            = {0};
    uint8_t *lic_addr               = NULL;
    uint32_t item_flags             = 0;
    fit_info_item_t item            = {0};
    fit_lic_scope_t lic_scope_item  = {0};

    /* Validate input parameters.*/
    if (license_t == NULL || license_t->license == NULL || license_t->keys == NULL || 
        license_t->license->read_byte == NULL || license_t->keys->read_byte == NULL)
    {
        return FIT_STATUS_INVALID_PARAM_1;
    }

    if (license_t->license != NULL && license_t->license->length == 0)
    {
        return FIT_STATUS_INVALID_PARAM_1;
    }
    if (feature_h == NULL)
    {
        return FIT_STATUS_INVALID_PARAM_4;
    }
    if ((flags & FIT_FIND_FEATURE_FIRST) && (flags & FIT_FIND_FEATURE_NEXT))
    {
        return FIT_STATUS_INVALID_PARAM_3;
    }
    if (flags > (FIT_FIND_FEATURE_FIRST | FIT_FIND_FEATURE_NEXT))
    {
        return FIT_STATUS_INVALID_PARAM_3;
    }
    if ((flags & FIT_FIND_FEATURE_NEXT) && feature_h->feature_info.feature_id != feature_id)
    {
        return FIT_STATUS_INVALID_PARAM_4;
    }
    /* if flag is FIT_FIND_FEATURE_NEXT then depth should be a valid value */
    if ((flags & FIT_FIND_FEATURE_NEXT) &&
        feature_h->lic_scope.depth > FIT_MAX_LEVEL)
    {
        return FIT_STATUS_INVALID_PARAM_4;
    }

    if (flags & FIT_FIND_FEATURE_FIRST)
    {
        (void)fit_memset((uint8_t *)&(feature_h->lic_scope), 0, (int)sizeof(fit_lic_scope_t));
        (void)fit_memset((uint8_t *)&(feature_h->feature_info), 0, (int)sizeof(fit_feature_info_t));
        feature_h->lic_scope.depth = 0xFF;
    }

    /* check the init flag. fit_licenf_init should be called before use of any fit api */
    status = fit_check_init_status();
    if (status != FIT_STATUS_OK)
    {
        return status;
    }

    /* Verify the license string against signing key data present in keys array */
    status = fit_check_license_validity(license_t, FIT_TRUE);
    if (status != FIT_STATUS_OK)
    {
        return status;
    }

    feature_h->lic_data.keys = license_t->keys;
    feature_h->lic_data.license = license_t->license;
    feature_h->lic_data.sig_verified_marker = license_t->sig_verified_marker;

    /*
     * Parse the license data to look for Feature id that will be used for
     * login type operation. On return fetaure_h will contain the path to feature id
     */
    if (flags & FIT_FIND_FEATURE_FIRST)
    {
        feature_h->lic_scope.depth = 0xFF;
        item_flags = FIT_FIND_ITEM_FIRST|FIT_FIND_ITEM_MATCH;
    }
    if (flags & FIT_FIND_FEATURE_NEXT)
    {
        item_flags = FIT_FIND_ITEM_NEXT|FIT_FIND_ITEM_MATCH;
    }
    item.tag_id = FIT_FEATURE_ID_TAG_ID;
    item.type = FIT_INTEGER;
    item.object.intval = feature_id;
    status = fit_internal_find_item(license_t, FIT_LICENF_LICENSE_SCOPE_GLOBAL, &feature_h->lic_scope, /*lint !e655*/
        item_flags, &item); /*lint !e655*/
    /* See if feature id present in license binary.*/
    if (status == FIT_STATUS_ITEM_NOT_FOUND)
    {
        DBG(FIT_TRACE_ERROR, "Requested Feature ID NOT found error = %d\n",
            (unsigned int)status);
        return FIT_STATUS_FEATURE_NOT_FOUND;
    }
    else if (status == FIT_STATUS_OK)
    {
        lic_addr = feature_h->lic_scope.node[feature_h->lic_scope.depth - 2].data;
        if (lic_addr == NULL)
        {
            return FIT_STATUS_INVALID_V2C;
        }
        feature_h->feature_info.feature_id = feature_id;
        /* context is valid and all feature related information has been correctly parsed. */
        feature_h->lic_verified_marker = FIT_LIC_VERIFIED_MAGIC_NUM;
    }
    else
    {
        /*
         *If there is any error during lookup of feature ID then license string is
         * not valid.
         */
        return FIT_STATUS_INVALID_V2C;
    }

    /* Get the product id associated with found feature id */
    (void)fit_memset(&item, 0, (int)sizeof(fit_info_item_t));
    item.tag_id = FIT_PRODUCT_ID_TAG_ID;
    item.type = FIT_INTEGER;
    status = fit_internal_find_item(license_t, &(feature_h->lic_scope), &lic_scope_item,
        FIT_FIND_ITEM_FIRST, &item);
    if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_ERROR, "Test Case: fit_internal_find_item error status %d\n",
            (unsigned int)status);
        return status;
    }
    else
    {
        /* fill the product id in feature info */
        feature_h->feature_info.product_id = (uint32_t)item.object.intval;
    }

    /* Get the license property information for feature ID found in license string.*/
    (void)fit_memset(&(feature_h->feature_info.license_model), 0, sizeof(fit_licensemodel_t));
    fitptr.data = lic_addr;
    fitptr.read_byte = license_t->license->read_byte;
    status = fit_get_lic_prop_data(&fitptr, &(feature_h->feature_info.license_model), license_t->license);
    if (status != FIT_STATUS_OK)
    {
        return FIT_STATUS_INVALID_VALUE;
    }

    return status;
}

/**
 *
 * \skip fit_licenf_find_feature
 *
 * Find a feature with the specified feature ID in the license
 *
 * @param IN  \b  license   \n Pointer to fit_license_t structure containing license data
 *                             and keys to read data part. To access the license data in
 *                             different types of memory (FLASH, E2, RAM), fit_license_t is used.
 *
 * @param IN  \b  feature_id    \n  feature id which to be looked in license string..
 *
 * @param IN  \b  flags     \n  Tells from which location to start looking for a feature
 *                              in context.
 *
 * @param IN  \b  feature_h \n Structure containing the feature context. Used as a handle for
 *                             a feature.
 *
 */
fit_status_t fit_licenf_find_feature(fit_license_t *license_t,
                                     uint32_t feature_id,
                                     uint32_t flags,
                                     fit_feature_ctx_t* feature_h)
{
    fit_status_t status             = FIT_STATUS_UNKNOWN_ERROR;

#ifdef FIT_USE_MULTI_THREAD
    fit_status_t threadret          = FIT_STATUS_UNKNOWN_ERROR;

    /* acquire read lock on read/write lock */
    threadret = FIT_ACQUIRE_SHARED_LOCK();
    if (threadret != FIT_STATUS_OK)
    {
        return threadret;
    }
#endif // #ifdef FIT_USE_MULTI_THREAD

    /* call internal find feature api that will do actual api task */
    status = fit_internal_find_feature(license_t, feature_id, flags, feature_h);

#ifdef FIT_USE_MULTI_THREAD
    /* release read lock on read/write lock */
    threadret = FIT_RW_UNLOCK();
    if (threadret != FIT_STATUS_OK)
    {
        return threadret;
    }
#endif // #ifdef FIT_USE_MULTI_THREAD

    return status;
}

/**
 *
 * \skip fit_internal_find_item
 *
 * Find a item with the specified properties in the license.
 *
 * @param IN  \b  license   \n Pointer to fit_license_t structure containing license data
 *                             and keys to read data part. To access the license data in
 *                             different types of memory (FLASH, E2, RAM), fit_license_t is used.
 *
 * @param IN  \b  lic_scope_ref  \n  If FIT_LICENF_LICENSE_SCOPE_GLOBAL(null) search
 *                                   for an item is global otherwise search is limited
 *                                   to the related tree branches specified in lic_scope_ref.
 *
 * @param OUT \b  lic_scope_item \n  When a item is found, "lic_scope_item" is updated with the
 *                                   path to the found item.
 *
 * @param IN  \b  flags     \n  Tells from which location to start looking for a item.
 *                              If the "FIT_FIND_ITEM_FIRST" flag is specified, the search
 *                              will start from the beginning. If the "FIT_FIND_ITEM_NEXT"
 *                              flag is set, then search will start from the last found
 *                              item (presented in lic_scope_item).
 *
 * @param IO  \b  item      \n Structure containing the license item information. The target
 *                             item is specified by the item tag id (needs to be set in the
 *                             "item" structure). If the type (in item.type) is specified,
 *                             it will check agains the specified type - otherwise it will
 *                             set the type according to the object
 *
 */
fit_status_t fit_internal_find_item(fit_license_t *license_t,
                                    fit_lic_scope_t* lic_scope_ref,
                                    fit_lic_scope_t* lic_scope_item,
                                    uint32_t flags,
                                    fit_info_item_t* item)
{
    fit_status_t status = FIT_STATUS_UNKNOWN_ERROR;
    fit_op_data_t opdata = { 0 };
    fit_wire_type_t type = FIT_INVALID_VALUE;

    /* Validate input parameters.*/
    if (license_t == NULL || license_t->license == NULL || license_t->keys == NULL ||
        license_t->license->read_byte == NULL || license_t->keys->read_byte == NULL)
    {
        return FIT_STATUS_INVALID_PARAM_1;
    }
    if (license_t->license != NULL && license_t->license->length == 0)
    {
        return FIT_STATUS_INVALID_PARAM_1;
    }

    if ((lic_scope_ref != FIT_LICENF_LICENSE_SCOPE_GLOBAL) &&
        (lic_scope_ref->depth > FIT_MAX_LEVEL))
    {
        return FIT_STATUS_INVALID_PARAM_2;
    }
    if (lic_scope_item == NULL)
    {
        return FIT_STATUS_INVALID_PARAM_3;
    }
    if (item == NULL)
    {
        return FIT_STATUS_INVALID_PARAM_5;
    }
    if ((flags & FIT_FIND_ITEM_FIRST) && (flags & FIT_FIND_ITEM_NEXT))
    {
        return FIT_STATUS_INVALID_PARAM_4;
    }
    if (flags > (FIT_FIND_ITEM_FIRST | FIT_FIND_ITEM_NEXT | FIT_FIND_ITEM_MATCH))
    {
        return FIT_STATUS_INVALID_PARAM_4;
    }
    if ((flags & FIT_FIND_ITEM_MATCH) &&
        (!((flags & FIT_FIND_ITEM_FIRST) || (flags & FIT_FIND_ITEM_NEXT))))
    {
        return FIT_STATUS_INVALID_PARAM_4;
    }
    if ((flags & FIT_FIND_ITEM_NEXT) &&
        lic_scope_ref != FIT_LICENF_LICENSE_SCOPE_GLOBAL &&
        lic_scope_ref->depth > lic_scope_item->depth)
    {
        return FIT_STATUS_INVALID_PARAM_3;
    }
    /* if flag is FIT_FIND_ITEM_NEXT then depth should be a valid value */
    if ((flags & FIT_FIND_ITEM_NEXT) &&
        lic_scope_ref != FIT_LICENF_LICENSE_SCOPE_GLOBAL &&
        lic_scope_ref->depth > FIT_MAX_LEVEL)
    {
        return FIT_STATUS_INVALID_PARAM_3;
    }

    if ((flags & FIT_FIND_ITEM_NEXT) &&
        lic_scope_ref != FIT_LICENF_LICENSE_SCOPE_GLOBAL &&
        lic_scope_item->tag_id != item->tag_id)
    {
        return FIT_STATUS_INVALID_FIND_NEXT_TAGID;
    }

    /** validate that scope ref is correctly initialized */
    if (lic_scope_ref != FIT_LICENF_LICENSE_SCOPE_GLOBAL && lic_scope_ref->magic != FIT_SCOPE_INITIALIZED_MAGIC)
    {
        return FIT_STATUS_SCOPE_NOT_INITIALIZED;
    }
    /** validate that scope item is correctly initialized */
    if ((flags & FIT_FIND_ITEM_NEXT) && (lic_scope_item->magic != FIT_SCOPE_INITIALIZED_MAGIC))
    {
        return FIT_STATUS_SCOPE_NOT_INITIALIZED;
    }

    /* Validate tag id */
    if (!(item->tag_id > FIT_BASE_TAG_ID_VALUE && item->tag_id < FIT_END_TAG_ID))
    {
        return FIT_STATUS_INVALID_TAGID;
    }
    /* Validate wire type */
    if (!(item->type >= FIT_INTEGER && item->type <= FIT_BINARY))
    {
        return FIT_STATUS_INVALID_WIRE_TYPE;
    }
    /* Get the wire type (data type) from the tag id. */
    fit_get_field_type_from_tagid(item->tag_id, &type);
    if (type != item->type)
    {
        return FIT_STATUS_WIRE_TYPE_MISMATCH;
    }

    if (type == FIT_STRING && (flags & FIT_FIND_ITEM_MATCH))
    {
        if (item->object.string == NULL)
        {
            return FIT_STATUS_INVALID_PARAM_5;
        }
    }

    /* check the init flag. fit_licenf_init should be called before use of any fit api */
    status = fit_check_init_status();
    if (status != FIT_STATUS_OK)
    {
        return status;
    }

    if (item->tag_id != FIT_ALGORITHM_ID_TAG_ID && item->tag_id != FIT_SIGNATURE_STR_TAG_ID) {
        /* Verify the license string against signing key data present in keys array */
        status = fit_check_license_validity(license_t, FIT_TRUE);
        if (status != FIT_STATUS_OK)
        {
            return status;
        }
    }

    /* fill the requested operation type and its related data.*/
    (void)fit_memset((uint8_t *)&opdata, 0, (int)sizeof(fit_op_data_t));
    opdata.flags = flags;
    opdata.tagid = item->tag_id;
    opdata.type = type;
    opdata.operation = (uint8_t)FIT_OP_GET_DATA_ADDRESS;
    opdata.status = FIT_STATUS_OK;
    if (flags & FIT_FIND_ITEM_MATCH)
    {
        if (item->type == FIT_STRING)
        {
            opdata.string = item->object.string;
        }
        else if (item->type == FIT_INTEGER)
        {
            opdata.intval = item->object.intval;
        }
    }

    /* If "lic_scope_ref" is specified, then search is limited to the related tree branches.
     * If "lic_scope_ref" is NULL, then the search is global.
     * If the "FIT_FIND_ITEM_FIRST" flag is specified, the search will start from
     * the beginning.
     * If the "FIT_FIND_ITEM_NEXT" flag is set, then search will start from the last found item.
     * Parse the license data to look for address of item tag id. On return will get the
      * path to found tag id.
     */
    DBG(FIT_TRACE_INFO, "Finding requested item in license string.\n");
    if (flags & FIT_FIND_ITEM_FIRST)
    {
        status = fit_licenf_initialize_scope(lic_scope_item);
        if(status != FIT_STATUS_OK)
        {
            return status;
        }
    }

    status = fit_license_parser_execute(license_t->license, lic_scope_ref, lic_scope_item,
            flags, &opdata);

    if ((status == FIT_STATUS_OK) && ((opdata.parserstatus == FIT_INFO_STOP_PARSE) ||
        (opdata.parserstatus == FIT_INFO_CONTINUE_PARSE)))
    {
        item->type = type;

        if (opdata.length == sizeof(uint16_t) && (type == FIT_INTEGER || type == FIT_BOOLEAN))
        {
            uint64_t temp1 = 0;

            status = fit_read_word_safe(opdata.parserdata.addr, license_t->license->read_byte,
                license_t->license, (uint16_t *)&temp1);
            if(status != FIT_STATUS_OK)
            {
                return status;
            }

            item->object.intval = (temp1 / 2) - 1;
        }
        /* Get the 32 bit field value.*/
        else if (opdata.length == sizeof(uint32_t) && type == FIT_INTEGER)
        {
            uint32_t temp1 = 0;

            /* This represents integer data in form of string, so need to do calculations.*/
            status = fit_read_dword_safe(opdata.parserdata.addr, license_t->license->read_byte,
                license_t->license, &temp1);
            if(status != FIT_STATUS_OK)
            {
                return status;
            }
            
            item->object.intval = (uint32_t)temp1;
        }
        else if (type == FIT_STRING || type == FIT_OBJECT || type == FIT_ARRAY || type == FIT_BINARY)
        {
            /* This represents integer data in form of string, so need to do calculations.*/
            item->object.data_ptr.data = opdata.parserdata.addr;
            item->object.data_ptr.length = opdata.length;
            item->object.data_ptr.read_byte = license_t->license->read_byte;
        }
        lic_scope_item->tag_id = item->tag_id;
        DBG(FIT_TRACE_INFO, "Found requested item in license string \n");
    }
    else
    {
        DBG(FIT_TRACE_ERROR, "Requested item cound not be found in license string \n");

        if( status != FIT_STATUS_INVALID_LICGEN_VER )
        {
            status = FIT_STATUS_ITEM_NOT_FOUND;
        }
    }

    return status;
}

/**
 *
 * \skip fit_licenf_find_item
 *
 * Find a item with the specified properties in the license.
 *
 * @param IN  \b  license   \n Pointer to fit_license_t structure containing license data
 *                             and keys to read data part. To access the license data in
 *                             different types of memory (FLASH, E2, RAM), fit_license_t is used.
 *
 * @param IN  \b  lic_scope_ref  \n  If FIT_LICENF_LICENSE_SCOPE_GLOBAL(null) search
 *                                   for an item is global otherwise search is limited
 *                                   to the related tree branches specified in lic_scope_ref.
 *
 * @param OUT \b  lic_scope_item \n  When a item is found, "lic_scope_item" is updated with the
 *                                   path to the found item.
 *
 * @param IN  \b  flags     \n  Tells from which location to start looking for a item.
 *                              If the "FIT_FIND_ITEM_FIRST" flag is specified, the search
 *                              will start from the beginning. If the "FIT_FIND_ITEM_NEXT"
 *                              flag is set, then search will start from the last found
 *                              item (presented in lic_scope_item).
 *
 * @param IO  \b  item      \n Structure containing the license item information. The target
 *                             item is specified by the item tag id (needs to be set in the
 *                             "item" structure). If the type (in item.type) is specified,
 *                             it will check agains the specified type - otherwise it will
 *                             set the type according to the object
 *
 */
fit_status_t fit_licenf_find_item(fit_license_t *license_t,
                                  fit_lic_scope_t* lic_scope_ref,
                                  fit_lic_scope_t* lic_scope_item,
                                  uint32_t flags,
                                  fit_info_item_t* item)
{
    fit_status_t status             = FIT_STATUS_UNKNOWN_ERROR;

#ifdef FIT_USE_MULTI_THREAD
    fit_status_t threadret          = FIT_STATUS_UNKNOWN_ERROR;

    /* acquire read lock on read/write lock */
    threadret = FIT_ACQUIRE_SHARED_LOCK();
    if (threadret != FIT_STATUS_OK)
    {
        return threadret;
    }
#endif // #ifdef FIT_USE_MULTI_THREAD

    /* call internal find feature api that will do actual api task */
    status = fit_internal_find_item(license_t, lic_scope_ref, lic_scope_item, flags, item);

#ifdef FIT_USE_MULTI_THREAD
    /* release read lock on read/write lock */
    threadret = FIT_RW_UNLOCK();
    if (threadret != FIT_STATUS_OK)
    {
        return threadret;
    }
#endif // #ifdef FIT_USE_MULTI_THREAD

    return status;
}

/**
 *
 * \skip fit_internal_get_license_info
 *
 * Functions to retrieve information from item(s) from the license.
 *
 * @param IN  \b  license   \n Pointer to fit_license_t structure containing license data
 *                             and keys to read data part. To access the license data in
 *                             different types of memory (FLASH, E2, RAM), fit_license_t is used.
 *
 * @param IN  \b  lic_scope_ref  \n  If FIT_LICENF_LICENSE_SCOPE_GLOBAL(null) search
 *                                   for an item is global otherwise search is limited
 *                                   to the related tree branches specified in lic_scope_ref.
 *
 * @param IO  \b  item      \n Structure containing the license item information. The target
 *                             item is specified by the item tag id (needs to be set in the
 *                             "item" structure). If the type (in item.type) is specified,
 *                             it will check agains the specified type - otherwise it will
 *                             set the type according to the object
 *
 */
fit_status_t fit_internal_get_license_info(fit_license_t *license_t,
                                           fit_lic_scope_t* lic_scope_ref,
                                           fit_info_item_t* item)
{
    fit_status_t status             = FIT_STATUS_UNKNOWN_ERROR;
    fit_wire_type_t type                = FIT_INVALID_VALUE;
    fit_lic_scope_t lic_scope_item  = {0};

    /* Validate input parameters.*/
    if (license_t == NULL || license_t->license == NULL || license_t->keys == NULL || 
        license_t->license->read_byte == NULL || license_t->keys->read_byte == NULL)
    {
        return FIT_STATUS_INVALID_PARAM_1;
    }
    if (license_t->license != NULL && license_t->license->length == 0)
    {
        return FIT_STATUS_INVALID_PARAM_1;
    }
    if (item == NULL)
    {
        return FIT_STATUS_INVALID_PARAM_3;
    }
    if ((lic_scope_ref != FIT_LICENF_LICENSE_SCOPE_GLOBAL) &&
            (lic_scope_ref->depth > FIT_MAX_LEVEL))
    {
        return FIT_STATUS_INVALID_PARAM_2;
    }

    /* Validate tag id */
    if (!(item->tag_id > FIT_BASE_TAG_ID_VALUE &&
        item->tag_id < FIT_END_TAG_ID))
    {
        return FIT_STATUS_INVALID_TAGID;
    }
    /* Validate wire type */
    if (!(item->type >= FIT_INTEGER && item->type <= FIT_BINARY))
    {
        return FIT_STATUS_INVALID_WIRE_TYPE;
    }
    /* Get the wire type (data type) from the tag id. */
    fit_get_field_type_from_tagid(item->tag_id, &type);
    if (type != item->type)
    {
         return FIT_STATUS_WIRE_TYPE_MISMATCH;
    }

    /* check the init flag. fit_licenf_init should be called before use of any fit api */
    status = fit_check_init_status();
    if (status != FIT_STATUS_OK)
    {
        return status;
    }

    /* Verify the license string against signing key data present in keys array */
    status = fit_check_license_validity(license_t, FIT_TRUE);
    if (status != FIT_STATUS_OK)
    {
        return status;
    }

    /* Look for item in given reference path */
    status = fit_internal_find_item(license_t, lic_scope_ref, &lic_scope_item,
        FIT_FIND_ITEM_FIRST, item);

    return status;
}

/**
 *
 * \skip fit_licenf_get_license_info
 *
 * Functions to retrieve information from item(s) from the license.
 *
 * @param IN  \b  license   \n Pointer to fit_license_t structure containing license data
 *                             and keys to read data part. To access the license data in
 *                             different types of memory (FLASH, E2, RAM), fit_license_t is used.
 *
 * @param IN  \b  lic_scope_ref  \n  If FIT_LICENF_LICENSE_SCOPE_GLOBAL(null) search
 *                                   for an item is global otherwise search is limited
 *                                   to the related tree branches specified in lic_scope_ref.
 *
 * @param IO  \b  item      \n Structure containing the license item information. The target
 *                             item is specified by the item tag id (needs to be set in the
 *                             "item" structure). If the type (in item.type) is specified,
 *                             it will check agains the specified type - otherwise it will
 *                             set the type according to the object
 *
 */
fit_status_t fit_licenf_get_license_info(fit_license_t *license_t,
                                         fit_lic_scope_t* lic_scope_ref,
                                         fit_info_item_t* item)
{
    fit_status_t status             = FIT_STATUS_UNKNOWN_ERROR;

#ifdef FIT_USE_MULTI_THREAD
    fit_status_t threadret          = FIT_STATUS_UNKNOWN_ERROR;

    /* acquire read lock on read/write lock */
    threadret = FIT_ACQUIRE_SHARED_LOCK();
    if (threadret != FIT_STATUS_OK)
    {
        return threadret;
    }
#endif // #ifdef FIT_USE_MULTI_THREAD

    /* call internal find feature api that will do actual api task */
    status = fit_internal_get_license_info(license_t, lic_scope_ref, item);

#ifdef FIT_USE_MULTI_THREAD
    /* release read lock on read/write lock */
    threadret = FIT_RW_UNLOCK();
    if (threadret != FIT_STATUS_OK)
    {
        return threadret;
    }
#endif // #ifdef FIT_USE_MULTI_THREAD

    return status;
}

/**
 *
 * \skip fit_licenf_initialize_scope
 *
 * Functions to initialize a fit_lic_scope_t structure.
 *
 * @param IN  \b  lic_scope_item   \n Pointer to fit_scope_t structure.
 *
 */
fit_status_t fit_licenf_initialize_scope(fit_lic_scope_t* lic_scope_item)
{
    fit_status_t status = FIT_STATUS_INTERNAL_ERROR;

    /* check the init flag. fit_licenf_init should be called before use of any fit api */
    status = fit_check_init_status();
    if (status != FIT_STATUS_OK)
    {
        return status;
    }

    (void)fit_memset(lic_scope_item, 0, sizeof(fit_lic_scope_t));
    lic_scope_item->depth = 0xFF;
    lic_scope_item->magic = FIT_SCOPE_INITIALIZED_MAGIC;

    return status;
}
