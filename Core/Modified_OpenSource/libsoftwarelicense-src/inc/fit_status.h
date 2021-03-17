/****************************************************************************\
**
** fit_status.h
**
** This file contains possible error codes used in Sentinel FIT.
** 
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_STATUS_H__
#define __FIT_STATUS_H__

/* Required Includes ********************************************************/

/* Constants ****************************************************************/

/**
 * @defgroup fit_error_codes sentinel fit core Status Codes
 *
 * @{
 */

/**
 * because of MISRA rules we limit the defines to 32 characters
 *
 */
enum fit_error_codes
{
    /** Request successfully completed */
    FIT_STATUS_OK                       = 0,

    /** Sentinel FIT core is out of memory */
    FIT_STATUS_INSUFFICIENT_MEMORY,

    /** Specified Feature ID not available */
    FIT_STATUS_INVALID_FEATURE_ID,

    /** Invalid V2C/Binary data format */
    FIT_STATUS_INVALID_V2C,

    /** Access to Feature or functionality denied */
    FIT_STATUS_ACCESS_DENIED,

    /** Invalid value for Sentinel fit license string. */
    FIT_STATUS_INVALID_VALUE            = 5,

    /** Unable to execute function in this context; the requested
     * functionality is not implemented */
    FIT_STATUS_REQ_NOT_SUPPORTED,

    /** Unknown algorithm used in V2C file */
    FIT_STATUS_UNKNOWN_ALGORITHM,

    /** Required license signing key is not present in key array */
    FIT_STATUS_KEY_NOT_PRESENT,

    /** Requested Feature not available */
    FIT_STATUS_FEATURE_NOT_FOUND,

    /** Reserved status for future use */
    FIT_STATUS_RESERVED_2               = 10,

    /** Reserved status for future use */
    FIT_STATUS_RESERVED_3,

    /** Reserved status for future use */
    FIT_STATUS_RESERVED_4,

    /** licgen version used for generate license is not valid */
    FIT_STATUS_INVALID_LICGEN_VER,

    /** signature id is not valid */
    FIT_STATUS_INVALID_SIG_ID,

    /** Feature expired */
    FIT_STATUS_FEATURE_EXPIRED          = 15,

    /** Error occurred during caching of sentinel fit licenses */
    FIT_STATUS_LIC_CACHING_ERROR,

    /** Invalid Product information */
    FIT_STATUS_INVALID_PRODUCT,

    /** Invalid function parameter */
    FIT_STATUS_INVALID_PARAM,

    /** Invalid function first parameter */
    FIT_STATUS_INVALID_PARAM_1,

    /** Invalid function second parameter */
    FIT_STATUS_INVALID_PARAM_2          = 20,

    /** Invalid function third parameter */
    FIT_STATUS_INVALID_PARAM_3,

    /** Invalid function fourth parameter */
    FIT_STATUS_INVALID_PARAM_4,

    /** Invalid function fifth parameter */
    FIT_STATUS_INVALID_PARAM_5,

    /** Reserved status for future use */
    FIT_STATUS_RESERVED_5,

    /** Reserved status for future use */
    FIT_STATUS_RESERVED_6               = 25,

    /** Invalid wire type */
    FIT_STATUS_INVALID_WIRE_TYPE,

    /** Internal error occurred in Sentinel fit core */
    FIT_STATUS_INTERNAL_ERROR,

    /** Invalid encryption key size */
    FIT_STATUS_INVALID_KEYSIZE,

    /** invalid vendor id */
    FIT_STATUS_INVALID_VENDOR_ID,

    /** invalid product id */
    FIT_STATUS_INVALID_PRODUCT_ID       = 30,

    /** invalid license container id */
    FIT_STATUS_INVALID_CONTAINER_ID,

    /** Field data is present in license */
    FIT_STATUS_LIC_FIELD_PRESENT,

    /** Invalid license type */
    FIT_STATUS_INVALID_LICENSE_TYPE,

    /** Time expiration not supported */
    FIT_STATUS_LIC_EXP_NOT_SUPP,

    /** Invalid start date value */
    FIT_STATUS_INVALID_START_DATE       = 35,

     /** Invalid end date value */
    FIT_STATUS_INVALID_END_DATE,

    /** License not active */
    FIT_STATUS_INACTIVE_LICENSE,

    /** No real time clock is present on board */
    FIT_STATUS_RTC_NOT_PRESENT,

    /** Clock support not present */
    FIT_STATUS_NO_CLOCK_SUPPORT,

    /** length not valid */
    FIT_STATUS_INVALID_FIELD_LEN        = 40,

    /* Data comparison gets failed */
    FIT_STATUS_DATA_MISMATCH_ERROR,

    /* Code not compiled with node locking */
    FIT_STATUS_NODE_LOCKING_NOT_SUPP,

    /** fingerprint magic value not correct */
    FIT_STATUS_FP_MAGIC_NOT_VALID,

    /** Unknown fingerprint algorithm */
    FIT_STATUS_UNKNOWN_FP_ALGORITHM,

    /* Fingerprint data comparison gets failed */
    FIT_STATUS_FP_MISMATCH_ERROR        = 45,

    /* Invalid device id length */
    FIT_STATUS_INVALID_DEVICE_ID_LEN,

    /** Signature verification operation failed */
    FIT_STATUS_INVALID_SIGNATURE,

    /** Unkwown error */
    FIT_STATUS_UNKNOWN_ERROR,

    /** RSA not supported */
    FIT_STATUS_NO_RSA_SUPPORT,

    /** AES not supported */
    FIT_STATUS_NO_AES_SUPPORT           = 50,

    /** Invalid key scope */
    FIT_STATUS_INVALID_KEY_SCOPE,

    /** Invalid signing key (RSA public key, or AES key) */
    FIT_STATUS_INVALID_SIGNING_KEY,

    /** Buffer overrun error */
    FIT_STATUS_BUFFER_OVERRUN,

    /** Maximum level/depth overrun */
    FIT_STATUS_MAX_LEVEL_EXCEEDS,

    /* License requirements not supported */
    FIT_STATUS_LIC_REQ_NOT_SUPP         =55,

    /* Error during base64 encoding */
    FIT_STATUS_BASE64_ENCODING_ERROR,

    /* Error during base64 decoding */
    FIT_STATUS_BASE64_DECODING_ERROR,

    /* key or tag not found in license string */
    FIT_STATUS_INVALID_TAGID,

    /* license element not found */
    FIT_STATUS_ITEM_NOT_FOUND           =60,

    /* license element not found */
    FIT_STATUS_CONCUR_LIMIT_EXCEEDS,

    /* wire type mismatch error */
    FIT_STATUS_WIRE_TYPE_MISMATCH,

    /* base 64 invalid character */
    FIT_STATUS_BASE64_INVAL_CHARACTER,
    
    /* partial get info list found */
    FIT_STATUS_PARTIAL_INFO,

    /* license update error */
    FIT_STATUS_LIC_UPDATE_ERROR         =65,

    /* Invalid feature context */
    FIT_STATUS_INVALID_FEATURE_CONTEXT,

    /* Skip data as this information not required */
    FIT_STATUS_SKIP_ELEMENT_DATA,

    /** FIT mutex initialization error. */
    FIT_STATUS_UNINITIALIZED_MUTEX_ERROR,

    /** FIT mutex lock error. */
    FIT_STATUS_LOCK_MUTEX_ERROR,

    /** FIT mutex unlock error. */
    FIT_STATUS_UNLOCK_MUTEX_ERROR       =70,

    /** FIT fit_scope_item structure not initialized. */
    FIT_STATUS_SCOPE_NOT_INITIALIZED,

    /** FIT for FIT_FIND_ITEM_NEXT item scope.tag_id is not same like item.tag_id. */
    FIT_STATUS_INVALID_FIND_NEXT_TAGID,

    /** container id mismatch error in license update */
    FIT_STATUS_CONTAINER_ID_MISMATCH,

    /* specific feature found */
    FIT_STATUS_FEATURE_ID_FOUND,

    /** minimum lm version required to consume license is not valid */
    FIT_STATUS_INVALID_LM_VER           =75,

    /** item id not found in persistent storage */
    FIT_STATUS_PRST_ID_NOT_FOUND,

    /** license update count does not match than the one in persistence */
    FIT_STATUS_UPDATE_COUNT_MISMATCH,

    /** item data too big to fit in persistent storage */
    FIT_STATUS_PRST_ITEM_TOO_BIG,

    /** persistent storage corrupt */
    FIT_STATUS_PRST_CORRUPT,

    /** persistent storage out of memory - too many items */
    FIT_STATUS_PRST_INSUFFICIENT_MEMORY     =80,

    /** error writing to persistent memory */
    FIT_STATUS_PRST_WRITE_ERROR,

    /** error reading to persistent memory */
    FIT_STATUS_PRST_READ_ERROR,

    /** error erasing persistent memory */
    FIT_STATUS_PRST_ERASE_ERROR,

    /** persistence block is completely empty */
    FIT_STATUS_PRST_BLOCK_EMPTY,

    /** illegal operation while transaction in progress */
    FIT_STATUS_PRST_ILLEGAL_IN_TRANSACTION  =85,

    /** persistence transaction NOT active */
    FIT_STATUS_PRST_NOT_IN_TRANSACTION,

    /** persistence transaction aborted due to error */
    FIT_STATUS_PRST_TRANSACTION_ABORTED,

    /** persistent storage value does not match with license element value */
    FIT_STATUS_PRST_MISMATCH_ERROR,

    /** persistent storage not initialized */
    FIT_STATUS_PRST_NOT_INIT,

    /** license already applied */
    FIT_STATUS_LIC_ALREADY_APPLIED          =90,

    /* prst element already present */
    FIT_STATUS_PRST_ID_ALREADY_PRESENT,

    /* not enough persistent storage */
    FIT_STATUS_PRST_INSUFFICIENT_STORAGE,

    /* could not acquire shared lock for read/write lock */
    FIT_STATUS_THREAD_SHARED_LOCK_ERROR,

     /* could not acquire exclusive lock for read/write lock */
    FIT_STATUS_THREAD_EXCLUSIVE_LOCK_ERROR,

    /* unlock error for read/write lock */
    FIT_STATUS_THREAD_UNLOCK_ERROR          =95,

    /** persistent storage file cannot be written */
    FIT_STATUS_PRST_CANNOT_WRITE,

    /** persistent storage file not found */
    FIT_STATUS_PRST_NOT_FOUND,

    /* fit not initialized error */
    FIT_STATUS_NOT_INITIALIZED,

};

/**
 * @}
 */

/* Types ********************************************************************/

typedef enum fit_error_codes fit_status_t;

/* Macro Functions **********************************************************/

#endif /* __FIT_STATUS_H__ */

