/****************************************************************************\
**
** fit_api.h
**
** Sentinel FIT Licensing interface header file. File contains exposed interface for
** C/C++ language.
**
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_API_H__
#define __FIT_API_H__

/** Required Includes ********************************************************/

#include <stdlib.h>
#include "fit_types.h"

#ifdef FIT_USE_PERSISTENT
#include "fit_persist.h"
#include "fit_persistent.h"
#endif // #ifdef FIT_USE_PERSISTENT

/** Constants ****************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/** Forward Declarations *****************************************************/

/** Types ********************************************************************/

/** Function Prototypes ******************************************************/


/**
 *
 * fit_licenf_construct_license
 *
 * This function will construct the fit_license_t structure from passed in license
 * data and keys.
 *
 * @param IN  \b  license       \n  Start address of the license in binary format,
 *                                  depending on your READ_LICENSE_BYTE definition
 *                                  e.g. in case of RAM, this can just be the memory
 *                                  address of the license variable 
 *
 * @param IN  \b  keys          \n  Pointer to array of key data. Also contains
 *                                  callback function to read key data in different
 *                                  types of memory(FLASH, E2, RAM).
 *
 * @param OUT \b  license_t     \n  On return will contain the valid license structure
 *                                  than can be used in calling FIT API's.
 *
 */
fit_status_t fit_licenf_construct_license(fit_pointer_t *license,
                                          fit_key_array_t *keys,
                                          fit_license_t *license_t);


/**
 *
 * \skip fit_licenf_get_version
 *
 * This function used for getting information about sentinel fit core versioning
 * information.
 *
 * @param OUT   \b  major_version   \n On return it will contain the sentinel fit
 *                                     core major version data.
 *
 * @param OUT   \b  minor_version   \n On return it will contain the sentinel fit
 *                                     core minor version data.
 *
 * @param OUT   \b  revision        \n On return it will contain the sentinel fit
 *                                     core revision data.
 *
 * @return FIT_STATUS_OK on success; otherwise, returns appropriate error code.
 *
 */
fit_status_t fit_licenf_get_version(uint8_t *major_version,
                                    uint8_t *minor_version,
                                    uint8_t *revision);

/**
 *
 * \skip fit_licenf_find_feature
 *
 * Find a feature with the specified feature ID in the license
 *
 * @param IN  \b  license_t \n Pointer to fit_license_t structure containing license data
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
                                     fit_feature_ctx_t* feature_h);


/**
 *
 * \skip fit_licenf_initialize_scope
 *
 * Functions to initialize a fit_lic_scope_t structure.
 *
 * @param IN  \b  lic_scope_item   \n Pointer to fit_scope_t structure.
 *
 */
fit_status_t fit_licenf_initialize_scope(fit_lic_scope_t* lic_scope_item);

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
                                  fit_info_item_t* item);

/**
 *
 * \skip fit_licenf_start_consume_feature
 *
 * This function starts the consumption of a feature referenced by the context
 *
 * @param IN  \b  context   \n  Structure containing the feature context. Used as
 *                                  a handle for a feature
 *
 * @param IN  \b  flags    \n  tells from which location to start looking for a feature
 *                             in context.
 *
 */
fit_status_t fit_licenf_start_consume_feature(fit_feature_ctx_t *context,
                                              uint32_t flags);

/**
 *
 * \skip fit_licenf_end_consume_feature
 *
 * This function ends the consumption of a feature referenced by the context
 *
 * @param IN  \b  context   \n  Structure containing the feature context. Used as
 *                              a handle for a feature
 *
 */
fit_status_t fit_licenf_end_consume_feature(fit_feature_ctx_t *context);


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
                                         fit_info_item_t* item);

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
                                               fit_license_t* license_new);

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
                                        uint32_t* length);

/**
 *
 * \skip fit_licenf_init
 *
 * Initialization function when the Embedded system is powered up. 
 * This function has the following responsibility:
 * 1. Call related init function of sub-modules
 * 2. Initialize / allocate global variables
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_licenf_init(void);


#ifdef __cplusplus
}
#endif
#endif /** __FIT_API_H__ */

