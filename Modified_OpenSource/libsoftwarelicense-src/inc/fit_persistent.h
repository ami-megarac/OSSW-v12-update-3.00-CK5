/****************************************************************************\
**
** fit_persistent.h
**
** Contains declaration for structures, enum, constants and functions used in
** persistent storage implementation for embedded devices
**
** Copyright (C) 2017, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_PERSISTENT_H__
#define __FIT_PERSISTENT_H__

#ifdef FIT_USE_PERSISTENT

/* Required Includes ********************************************************/
#include "fit_types.h"

/* Constants ****************************************************************/

/*
 * reserved persistence reference id's 
 */
#define FIT_PRST_UPDATE_COUNT_REF_ID    0xFFFFF0
#define FIT_PRST_CONT_UUID_REF_ID       0x0
#define FIT_PRST_UPDATE_COUNT_MAX_LIMIT 0xFFFFFFFF


typedef struct fit_prst_size
{
    /*  number of items of same size */
    uint8_t num_of_items;
    /* size of item in bytes */
    uint32_t size_of_item;
} fit_prst_size_t;

/* Forward Declarations *****************************************************/

/* Types ********************************************************************/

/**
 *
 * \skip fit_persist_init
 *
 * Initialize the persistent storage (if not yet initialized).
 *
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_persist_init(void);

/**
*
* \skip fit_persist_get_size
*
* return size of persistence storage
*
* @return uint32_t - size of persistence
*
*/
uint32_t  fit_persist_get_size(void);


/**
*
* \skip fit_persist_container_check_size
*
* check if requested size is available in persistent storage and allocate additional space iof flag set to true
*
* @param IN    cont_id \n Pointer to Container id data.
*
* @param IN    items   \n array of persistent size, array ends in an element having 0
*                         for both fields num_of_items and size_of_items
*
* @param IN    allocate \n if true allocate missing size
*
* @return FIT_STATUS_OK on success; otherwise appropriate error code.
*
*/
fit_status_t fit_persist_container_check_size(const uint8_t *cont_id,
                                              const fit_prst_size_t *items,
                                              uint8_t allocate);

/**
 *
 * \skip fit_persist_element_create
 *
 * Create the entry for a container persistent element into persistent storage table with value
 * 0 or NULL. If container does not exist it is also created.
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
                                     uint32_t size);

/**
 *
 * \skip fit_persist_element_delete
 *
 * This function will delete the entry from persistent storage corresponding
 * to persistent element reference id.
 *
 * @param IN    cont_id     \n Pointer to Container id data.
 *
 * @param IN    keyid       \n reference id of persistent element to be clean
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_persist_element_delete(const uint8_t *cont_id,
                                        uint32_t keyid);


/**
 *
 * \skip fit_persist_element_get
 *
 * Read persistent data for specified refernce id of given container id.
 *
 * @param IN    cont_id     \n Pointer to Container id data.
 *
 * @param IN    keyid       \n reference id of persistent element to be read
 *
 * @param IN    cont_id_len \n Length of container id.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_persist_element_get(const uint8_t *cont_id,
                                     uint32_t keyid,
                                     uint8_t* value,
                                     uint32_t *len);

/**
 *
 * \skip fit_persist_element_put
 *
 * Gets the update counter value from persistent storage corresponding to container id.
 *
 * @param IN    cont_id     \n Pointer to Container id data.
 *
 * @param IN    keyid       \n Length of container id.
 *
 * @param IN    cont_id_len \n Length of container id.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_persist_element_put(const uint8_t *cont_id,
                                     uint32_t keyid,
                                     uint8_t* value,
                                     uint32_t len);


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
                                         uint32_t *len);

#endif // FIT_USE_PERSISTENT

#endif /* __FIT_PERSISTENT_H__ */

