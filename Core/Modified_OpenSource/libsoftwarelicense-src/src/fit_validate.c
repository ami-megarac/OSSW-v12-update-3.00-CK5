/****************************************************************************\
**
** fit_validate.c
**
** Defines functionality for validate license for embedded devices.
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

#include "stddef.h"
#include "string.h"

#include "fit_debug.h"
#include "fit_internal.h"
#include "fit_version.h"
#include "fit_capabilities.h"
#include "fit_parser.h"
#include "fit_alloc.h"
#include "fit_hwdep.h"
#ifdef FIT_USE_PERSISTENT
#include "fit_persist.h"
#include "fit_persistent.h"
#endif // #ifdef FIT_USE_PERSISTENT

/* Function Definitions *****************************************************/

/**
 *
 * \skip fit_internal_prepare_license_update
 *
 * This function will validate and prepare license update. Checks the new license,
 * compares the Container ID with the old license, and executes the update script.
 * Note: It does not install or update the new license to the NVM memory - this
 * needs to be handled externally.
 *
 * @param IN    license_old     \n Pointer to fit_license_t structure containing old
 *                                 license data.
 *
 * @param IN    license_new     \n Pointer to fit_license_t structure containing new
 *                                 license data.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_internal_prepare_license_update(fit_license_t* license_old,
                                                 fit_license_t* license_new)
{
    fit_status_t status             = FIT_STATUS_UNKNOWN_ERROR;
    fit_info_item_t base_item;
    fit_info_item_t update_item;
    fit_lic_scope_t lic_scope_item  = {0};
    uint8_t cntr                    = 0;
    uint32_t old_upt_cntr           = 0;
    uint32_t new_upt_cntr           = 0;
#ifdef FIT_USE_PERSISTENT
    uint8_t cont_id[FIT_CONT_ID_LEN]    = {0};
    uint32_t prst_upt_cntr          = 0;
    uint32_t prst_size              = 0;
    fit_prst_size_t items[3]        = {0};
#endif

    DBG(FIT_TRACE_INFO, "[fit_licenf_prepare_license_update]: Entry \n");

    (void)fit_memset(&base_item, 0, sizeof(base_item));
    (void)fit_memset(&update_item, 0, sizeof(update_item));

    if (license_new == NULL || license_new->license->read_byte == NULL ||
        license_new->keys->read_byte == NULL)
    {
        return FIT_STATUS_INVALID_PARAM_2;
    }
    if (license_new->license != NULL && license_new->license->length == 0)
    {
        return FIT_STATUS_INVALID_PARAM_2;
    }

    /* check the init flag. fit_licenf_init should be called before use of any fit api */
    status = fit_check_init_status();
    if (status != FIT_STATUS_OK)
    {
        return status;
    }

    /** Verify the new license string  and old license string against signing key data
      * present in keys array and node locking  This function internally will also
      * verify license requirements against core capabilities, fingerprint data and
      * required LM version.
      */
    if (license_old != NULL)
    {
        status = fit_check_license_validity(license_old, FIT_TRUE);
        if (status != FIT_STATUS_OK)
        {
            DBG(FIT_TRACE_ERROR, "License verification fails for old license data "
                "status=%d\n", (unsigned int)status);
            return status;
        }
    }

    status = fit_check_license_validity(license_new, FIT_FALSE);
    if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_ERROR, "License verification fails for new license data "
            "status=%d\n", (unsigned int)status);
        return status;
    }

    if (license_old != NULL)
    {
        /* Compare if container ID of old license matches with the Container ID of the
         * new one 
         */

        /* Get container id of old license.*/
        base_item.tag_id = FIT_LIC_CONT_UUID_TAG_ID;
        base_item.type = FIT_BINARY;
        status = fit_internal_find_item(license_old, FIT_LICENF_LICENSE_SCOPE_GLOBAL,
            &lic_scope_item, FIT_FIND_ITEM_FIRST, &base_item);
        if (status != FIT_STATUS_OK)
        {
            DBG(FIT_TRACE_ERROR, "Not able to get container id for old license data "
                "status=%d\n", (unsigned int)status);
            return status;
        }

        (void)fit_memset((uint8_t *)&lic_scope_item, 0, sizeof(fit_lic_scope_t));
        /* Get container id of new license.*/
        update_item.tag_id = FIT_LIC_CONT_UUID_TAG_ID;
        update_item.type = FIT_BINARY;
        status = fit_internal_find_item(license_new, FIT_LICENF_LICENSE_SCOPE_GLOBAL,
            &lic_scope_item, FIT_FIND_ITEM_FIRST, &update_item);
        if (status != FIT_STATUS_OK)
        {
            DBG(FIT_TRACE_ERROR, "Not able to get container id for new license data "
                "status=%d\n", (unsigned int)status);
            return status;
        }

        if (base_item.object.data_ptr.length != update_item.object.data_ptr.length)
        {
            DBG(FIT_TRACE_ERROR, "Container id (uuid) data length mismatch ");
            return FIT_STATUS_CONTAINER_ID_MISMATCH;
        }
        for (cntr = 0; cntr < base_item.object.data_ptr.length; ++cntr)
        {
            if ((base_item.object.data_ptr.read_byte(base_item.object.data_ptr.data + cntr)) != 
                    (update_item.object.data_ptr.read_byte(update_item.object.data_ptr.data + cntr)))
            {
                DBG(FIT_TRACE_ERROR, "Container id (uuid) data mismatch ");

                return FIT_STATUS_CONTAINER_ID_MISMATCH;
            }
#ifdef FIT_USE_PERSISTENT
            cont_id[cntr] = base_item.object.data_ptr.read_byte(base_item.object.data_ptr.data + cntr);
#endif // #ifdef FIT_USE_PERSISTENT
        }

        /* Get update counter value for old license */
        base_item.tag_id = FIT_UPDATE_COUNTER_TAG_ID;
        base_item.type = FIT_INTEGER;
        status = fit_internal_find_item(license_old, FIT_LICENF_LICENSE_SCOPE_GLOBAL,
            &lic_scope_item, FIT_FIND_ITEM_FIRST, &base_item);
        if (status != FIT_STATUS_OK)
        {
            DBG(FIT_TRACE_ERROR, "Not able to get update counter value for old license data "
                "status=%d\n", (unsigned int)status);
            return status;
        }
        old_upt_cntr = (uint32_t)base_item.object.intval;
    }
#ifdef FIT_USE_PERSISTENT
    else
    {
        /* Get container id of new license.*/
        update_item.tag_id = FIT_LIC_CONT_UUID_TAG_ID;
        update_item.type = FIT_BINARY;
        status = fit_internal_find_item(license_new, FIT_LICENF_LICENSE_SCOPE_GLOBAL,
            &lic_scope_item, FIT_FIND_ITEM_FIRST, &update_item);
        if (status != FIT_STATUS_OK)
        {
            DBG(FIT_TRACE_ERROR, "Not able to get container id for new license data "
                "status=%d\n", (unsigned int)status);
            return status;
        }
        for (cntr = 0; cntr < update_item.object.data_ptr.length; ++cntr)
        {
            cont_id[cntr] = update_item.object.data_ptr.read_byte(update_item.object.data_ptr.data + cntr);
        }
    }
#endif // #ifdef FIT_USE_PERSISTENT

    /* Get update counter value for update license */
    update_item.tag_id = FIT_UPDATE_COUNTER_TAG_ID;
    update_item.type = FIT_INTEGER;
    status = fit_internal_find_item(license_new, FIT_LICENF_LICENSE_SCOPE_GLOBAL,
        &lic_scope_item, FIT_FIND_ITEM_FIRST, &update_item);
    if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_ERROR, "Not able to get update counter value for new license data "
            "status=%d\n", (unsigned int)status);
        return status;
    }
    new_upt_cntr = (uint32_t)update_item.object.intval;

#ifdef FIT_USE_PERSISTENT

    items[0].num_of_items = 1;
    items[0].size_of_item = FIT_CONT_ID_LEN;
    items[1].num_of_items = 1;
    items[1].size_of_item = sizeof(uint32_t);
    items[2].num_of_items = 0;
    items[2].size_of_item = 0;

    status = fit_persist_container_check_size((const uint8_t *)cont_id, items,1);
    if (status != FIT_STATUS_OK)
    {
        return status;
    }

    if (license_old == NULL)
    {
        old_upt_cntr = 0;
    }
    /* check if update counter exists in persistence */
    prst_size = sizeof(prst_upt_cntr);
    status = fit_persist_element_get(cont_id, FIT_PRST_UPDATE_COUNT_REF_ID,
            (uint8_t *)&prst_upt_cntr, &prst_size);
    if (status == FIT_STATUS_PRST_ID_NOT_FOUND)
    {
        /* Check for 1.4 Update: If both old and new Update counters are '0', and no
         * Update counter exist in persistence skip the update counter check 
         */
        if (new_upt_cntr == 0 && old_upt_cntr == 0)
        {
            /* skip the update counter check */
            return FIT_STATUS_OK;
        }
        /* create update counter in persistence and initialize it with 0 */
        status = fit_persist_element_create(cont_id, FIT_PRST_UPDATE_COUNT_REF_ID, sizeof(uint32_t));
        if (status != FIT_STATUS_OK)
        {
            return status;
        }
    }
    else
    {
        if (status != FIT_STATUS_OK)
        {
            return status;
        }
        /* Check if Update counter of old license matches with the one in the persistence. */
        if (prst_upt_cntr != old_upt_cntr)
        {
            /* The persistent update counter should normally match the oldV2C update counter
             * If this is not the case, then check, if it matches the newV2C update counter.
             */
            if (prst_upt_cntr != new_upt_cntr)
            {
                return FIT_STATUS_UPDATE_COUNT_MISMATCH;
            }
            else
            {
                return FIT_STATUS_OK;
            }
        }
    }
    /* update counter of new license should be greater than update counter stored in
     * persistent storage 
     */
    if (prst_upt_cntr >= new_upt_cntr)
    {
        return FIT_STATUS_LIC_UPDATE_ERROR;
    }

    /* write new update counter in persistent storage */
    status = fit_persist_element_put(cont_id, FIT_PRST_UPDATE_COUNT_REF_ID,
        (uint8_t *)&new_upt_cntr, sizeof(new_upt_cntr));
    if (status != FIT_STATUS_OK)
    {
        return status;
    }

#else // #ifdef FIT_USE_PERSISTENT 
    if (license_old == NULL)
    {
        old_upt_cntr = 0;
    }
    if (new_upt_cntr == 0 && old_upt_cntr == 0)
    {
        return FIT_STATUS_OK;
    }
    else if (old_upt_cntr >= new_upt_cntr)
    {
        return FIT_STATUS_LIC_UPDATE_ERROR;
    }

    status = FIT_STATUS_OK;
#endif // #ifdef FIT_USE_PERSISTENT

   DBG(FIT_TRACE_INFO, "[fit_licenf_prepare_license_update]: Exit \n");

    return status;
}

/**
 *
 * \skip fit_licenf_prepare_license_update
 *
 * This function will validate and prepare license update. Checks the new license,
 * compares the Container ID with the old license, and executes the update script.
 * Note: It does not install or update the new license to the NVM memory - this
 * needs to be handled externally.
 *
 * @param IN    license_old     \n Pointer to fit_license_t structure containing old
 *                                 license data.
 *
 * @param IN    license_new     \n Pointer to fit_license_t structure containing new
 *                                 license data.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_licenf_prepare_license_update(fit_license_t* license_old,
                                               fit_license_t* license_new)
{
    fit_status_t status             = FIT_STATUS_UNKNOWN_ERROR;

#ifdef FIT_USE_MULTI_THREAD
    fit_status_t threadret          = FIT_STATUS_UNKNOWN_ERROR;

    /* acquire write lock on read/write lock */
    threadret = FIT_ACQUIRE_EXCLUSIVE_LOCK();
    if (threadret != FIT_STATUS_OK)
    {
        return threadret;
    }
#endif // #ifdef FIT_USE_MULTI_THREAD

    /* call internal prepare license update fn that will do actual api task */
    status = fit_internal_prepare_license_update(license_old, license_new);

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

