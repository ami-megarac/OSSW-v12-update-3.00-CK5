/****************************************************************************\
**
** fit_persistent.c
**
** Defines functionality for persistent storage utility for embedded devices
** 
** Copyright (C) 2017-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

/* Required Includes ********************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#ifdef FIT_USE_PERSISTENT

#ifdef FIT_USE_SYSTEM_CALLS
#include <string.h>
#endif

#include "fit_debug.h"
#include "fit_internal.h"
#include "fit_persistent.h"
#include "fit_persist.h"

/* Global Data  *************************************************************/
extern fit_persist_storage_t prst_storage; //lint !e2701

/* Function Definitions *****************************************************/


/**
 *
 * \skip fit_persist_init
 *
 * Initialize the persistent storage (if not yet initialized) and check in requested
 * size is available in persistent storage
 *
 * @param IN    cont_id \n Pointer to Container id data.
 *
 * @param IN    items   \n array of persistent size, array ends in an element having 0
 *                         for both fields num_of_items and size_of_items
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_persist_init(void)
{
    fit_status_t status = FIT_STATUS_OK;
 
    /* check if persistence is already initialized */
    status = fit_check_prst_init();
    if (status == FIT_STATUS_PRST_NOT_INIT)
    {
        /* initialized the persistence */
        status = fit_prst_init();
    }

    return status;
}
/**
*
* \skip fit_persist_container_check_size
*
* check in requested if size is available in persistent storage
*
* @param IN    cont_id \n Pointer to Container id data.
*
* @param IN    items   \n array of persistent size, array ends in an element having 0
*                         for both fields num_of_items and size_of_items
*
* @param IN    alloc   \n request to allocate persistence space if not enough
*
* @return FIT_STATUS_OK on success; otherwise appropriate error code.
*
*/
fit_status_t fit_persist_container_check_size(const uint8_t *cont_id,
                       const fit_prst_size_t *items,
                       uint8_t alloc)
{
    fit_status_t status = FIT_STATUS_OK;
    uint32_t used_size = 0;
    uint32_t req_size = sizeof(fit_prst_header_t); // we count first the header size
    uint16_t cntr = 0;
    uint32_t max_size = 0;
    
    /* validate parameters */
    if (cont_id == NULL)
    {
        return FIT_STATUS_INVALID_PARAM_1;
    }
    if (items == NULL)
    {
        return FIT_STATUS_INVALID_PARAM_2;
    }

    /* check if persistence is already initialized */
    status = fit_check_prst_init();
    if (status != FIT_STATUS_OK)
    {
        return status;
    }

    /* get total requested size */
    while (items[cntr].num_of_items != 0 && items[cntr].size_of_item != 0)
    {
        if (items[cntr].size_of_item > max_size)
            max_size = items[cntr].size_of_item;

        req_size += items[cntr].num_of_items * (FIT_PRST_ITEM_FIXED_SIZE + items[cntr].size_of_item);
        cntr++;
    }
    /*
     * we add size to be able to write maximum size value once
     */
    req_size += FIT_PRST_ITEM_FIXED_SIZE + max_size;

    /* get current used size of persistent storage */
    status = fit_get_prst_used_size(&used_size);
    if (status != FIT_STATUS_OK)
    {
        return status;
    }

    if (req_size + used_size > prst_storage.block_size)
    {
        if( alloc )
            return fit_prst_hw_extend_size(req_size + used_size);

        return FIT_STATUS_PRST_INSUFFICIENT_STORAGE;
    }

    return FIT_STATUS_OK;
}

/**
 *
 * \skip fit_persist_element_create
 *
 * Create the entry for persistent element in persistent storage table with value
 * 0 or NULL
 *
 * @param IN    cont_id \n Pointer to Container id data.
 *
 * @param IN    keyid   \n reference id of persistent element to be created.
 *
 * @param IN    size    \n Length of persistent element.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_persist_element_create(const uint8_t *cont_id,
                                        uint32_t keyid,
                                        uint32_t size)
{
    fit_status_t status     = FIT_STATUS_OK;
    uint32_t prst_ref_id    = 0;
    uint32_t prst_val       = 0;
    uint8_t index           = 0;
    uint32_t p              = 0;

    DBG(FIT_TRACE_INFO, "[fit_prst_lic_cont_id_create] \n");

    if (cont_id == NULL)
    {
        return FIT_STATUS_INVALID_PARAM_1;
    }
    /* max value of keyid is 0xFFFFFF */
    if (keyid > 0xFFFFFF)
    {
        return FIT_STATUS_INVALID_PARAM_2;
    }
    if (size == 0)
    {
        return FIT_STATUS_INVALID_PARAM_3;
    }

    /* first get the index associated with the container id */
    status = fit_prst_cont_id_index_get(cont_id, FIT_CONT_ID_LEN, &index);
    if (status == FIT_STATUS_PRST_ID_NOT_FOUND)
    {
        DBG(FIT_TRACE_INFO, "[fit_persist_element_create] container id not present in persistent storage \n");
        /* Create entry in table for container id */
        status = fit_prst_lic_cont_id_create(cont_id, FIT_CONT_ID_LEN, index);
        if (status != FIT_STATUS_OK)
        {
            return status;
        }
    }
    else if (status != FIT_STATUS_OK)
    {
        /* return error */
        return status;
    }

    /* create the persistent element id corresponding to container id */
    prst_ref_id = FIT_PRST_ELEM_ID_CREATE(keyid, index);/*lint !e648 !e835 !e845*/

    status = fit_prst_id_find(prst_ref_id,&p);
    if ( status == FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_ERROR, "Persistent element already present in persistent storage ");
        return FIT_STATUS_PRST_ID_ALREADY_PRESENT;
    }

    /* just create entry for persistent elemnt with value 0 or NULL */
    status = fit_prst_write(prst_ref_id, size, (uint8_t *)&prst_val);

    return status;
}

/**
 *
 * \skip fit_persist_element_delete
 *
 * This function will clean (make all zeros) the entry from persistent storage corresponding
 * to persistent element reference id
 *
 * @param IN    cont_id     \n Pointer to Container id data.
 *
 * @param IN    keyid       \n reference id of persistent element to be clean
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_persist_element_delete(const uint8_t *cont_id,
                                        uint32_t keyid)
{
    uint32_t p = 0;
    fit_prst_item_t item;
    uint8_t index = 0;
    uint32_t prst_elem_id = 0;
    fit_status_t status = FIT_STATUS_UNKNOWN_ERROR;

    /* first get the index associated with the container id */
    status = fit_prst_cont_id_index_get(cont_id, FIT_CONT_ID_LEN, &index);
    if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_INFO, "[fit_clean_prst_element] conatiner id not present in persistent storage \n");
        return status;
    }

    /* if index is found, fetch the persistent element id corresponding to container id */
    prst_elem_id = FIT_PRST_ELEM_ID_CREATE(keyid,index);/*lint !e648 !e732*/

    status = fit_prst_id_find(prst_elem_id,&p);

    if ( status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_INFO, "[fit_persist_element_delete] id not present in persistent storage \n");
        return FIT_STATUS_PRST_ID_NOT_FOUND;
    }

    status = fit_prst_hw_read(prst_storage.current_block_num,p, (uint8_t*)&item, FIT_PRST_ITEM_FIXED_SIZE);
    if (status != FIT_STATUS_OK)
    {
        return status;
    }
    if (item.total_size == FIT_PRST_ITEM_FIXED_SIZE ) {
        /* treat zero size item as "not found) */
        DBG(FIT_TRACE_INFO, "[fit_persist_element_delete] id already has zero size \n");

        return FIT_STATUS_PRST_ID_NOT_FOUND;
    }

    /* write new item with payload size == 0 */
    return fit_prst_write(prst_elem_id, 0, NULL); /*lint !e831 */
}

/**
 *
 * \skip fit_persist_element_get
 *
 * Get persistent data for passed in keyid/reference id of given container id.
 *
 * @param IN    cont_id     \n Pointer to Container id data.
 *
 * @param IN    keyid       \n reference id of persistent element to be read
 *
 * @param OUT   value       \n On return will contain the value of reference id/keyid passed in.
 *
 * @param OUT   len         \n length of above reference id/keyid data.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_persist_element_get(const uint8_t *cont_id,
                                     uint32_t keyid,
                                     uint8_t* value,
                                     uint32_t *len)
{
    fit_status_t status;
    uint8_t index = 0;
    uint32_t prst_elem_id = 0;

    if (cont_id == NULL)
    {
        return FIT_STATUS_INVALID_PARAM_1;
    }
    if (len == NULL)
    {
        return FIT_STATUS_INVALID_PARAM_4;
    }

    /* first get the index associated with the container id */
    status = fit_prst_cont_id_index_get(cont_id, FIT_CONT_ID_LEN, &index);
    if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_INFO, "[fit_persist_element_get] conatiner id not present in persistent storage \n");
        return status;
    }

    /* if index is found, fetch the upersistent element id corresponding to container id */
    prst_elem_id = FIT_PRST_ELEM_ID_CREATE(keyid, index);/*lint !e648 !e732*/

    status = fit_prst_read(prst_elem_id, len, value);

    DBG(FIT_TRACE_INFO, "[fit_persist_element_get] status: %u %s\n",
       (unsigned int)status, fit_get_error_str(status));

    return status;
}

/**
 *
 * \skip fit_persist_element_put
 *
 * Set the persistent data for keyid/reference id of given container id.
 *
 * @param IN    cont_id     \n Pointer to Container id data for which persistent
 *                             data to be set for persistent element that belongs to
 *                             given container.
 *
 * @param IN    keyid       \n reference id of persistent element to be set
 *
 * @param IN    value       \n Value of reference id/keyid to be set
 *
 * @param IN    len         \n length of above reference id/keyid data.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_persist_element_put(const uint8_t *cont_id,
                                  uint32_t keyid,
                                  uint8_t* value,
                                  uint32_t len)
{
    uint32_t prst_elem_id = 0;
    fit_status_t status = FIT_STATUS_UNKNOWN_ERROR;
    uint8_t index   = 0;
    uint32_t p      = 0;

    DBG(FIT_TRACE_INFO, "[fit_persist_element_put] %u\n",keyid);

    if (cont_id == NULL)
    {
        return FIT_STATUS_INVALID_PARAM_1;
    }
    if (value == NULL)
    {
        return FIT_STATUS_INVALID_PARAM_3;
    }

    /* first get the index associated with the container id */
    status = fit_prst_cont_id_index_get(cont_id, FIT_CONT_ID_LEN, &index);
    if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_INFO, "[fit_persist_element_put] conatiner id not present in persistent storage \n");
        return status;
    }

    /* if index is found, sets the update counter value in persistent storage corresponding
     * to container id 
     */
    prst_elem_id = FIT_PRST_ELEM_ID_CREATE(keyid, index);/*lint !e648 !e732*/

    status = fit_prst_id_find(prst_elem_id,&p);
    if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_ERROR, "Persistent element not present in persistent storage ");
        return FIT_STATUS_PRST_ID_NOT_FOUND;
    }

    return fit_prst_write(prst_elem_id, len, value);
}


/**
*
* \skip fit_persist_get_size
*
* check if requested size is available in persistent storage
*
* @return uint32_t - size of persistence
*
*/
uint32_t  fit_persist_get_size(void)
{
    return prst_storage.block_size;
}


/**
*
* \skip fit_persist_element_get_seq
*
* returns elements of a container in increasing sequence, returned one being next after keyid input value
*
* @param IN     cont_id \n container id of the license
*
* @param IO     keyid   \n On input has the value of an element reference id
*                          On output contain the next elemenet reference id in increasing order after the input value
*
* @param OUT    value   \n buffer where the value should be copied. if NULL len will contain on return the required length.
*
* @param IO     len     \n length of the buffer provided in value. If length provided is to small return status will be
                           FIT_STATUS_PRST_ITEM_TOO_BIG and len will contain required value length.
*
* @return FIT_STATUS_OK on success or appropriate error code
*         FIT_STATUS_PRST_ITEM_TOO_BIG - when this status is returned the provided buffer in value is either NULL or the
*                                        value in len is to small for the size of the persistent element value
*         FIT_STATUS_PRST_ID_NOT_FOUND - when this value is returned , there is no next element for the container id
*
*/
fit_status_t fit_persist_element_get_seq(const uint8_t *cont_id,
                                         uint32_t *keyid,
                                         uint8_t *value,
                                         uint32_t *len)
{
    fit_status_t status = FIT_STATUS_OK;
    uint8_t index = 0;
    uint32_t itemid;
    uint8_t new_index;
    uint32_t prstid;

    if (cont_id == NULL || keyid == NULL || value == NULL || len == NULL)
        return FIT_STATUS_INVALID_PARAM;

    /* get the index associated with container */
    status = fit_prst_cont_id_find(cont_id, FIT_CONT_ID_LEN, &index);
    if (status != FIT_STATUS_OK)
    {
        return status;
    }
    /*
     * we start from key and container index and call fit_prst_element_get_seq and will get next element
     */
    itemid = FIT_PRST_ELEM_ID_CREATE(*keyid, index);
    status = fit_prst_element_get_seq(&itemid, value, len);
    if (status != FIT_STATUS_OK)
        return status;

    /*
     *   we decompose itemid and check that next element has same index like the container
     */
    fit_index_and_prstid_get((uint8_t*)&itemid, &new_index, &prstid);/*lint !e818 */
   
    /*
     * we compare index of container with new index - if is no match we are the end of 
     * enumeration for elements of this container. Else we return success with new element
     * in keyid, value and len
     */
    if (index != new_index)
        return FIT_STATUS_PRST_ID_NOT_FOUND;
    /*
     * we store value in keyid only in case of success in order to preserve initial value in case of errors 
    */
    *keyid = prstid;
    
    return FIT_STATUS_OK;
}

#endif // FIT_USE_PERSISTENT

