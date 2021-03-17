/****************************************************************************\
**
** fit_internal.h
**
** Contains declaration for strctures, enum, constants and functions used in Sentinel fit
** project and not exposed outside.
** 
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_INTERNAL_H__
#define __FIT_INTERNAL_H__

/* Required Includes ********************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif /* ifdef __cplusplus__ */

#include <stdlib.h>
#include "fit.h"

/* Constants ****************************************************************/

#ifndef NULL
#define NULL (void *)0
#endif

#define LM_FEAT_COUNT_TAG               "FC="
#define LM_ALGORITHM_ID_TAG             "AlgID="
#define LM_LICGEN_VER_INFO_TAG          "Licver="
#define LM_LM_VER_INFO_TAG              "LMver="
#define LM_UID_INFO_TAG                 "FIT_UID_TAG_ID="
#define LM_FP_ALG_ID_TAG                "HID="
#define LM_FP_HASH_TAG                  "FPHash="
#define LM_CONTAINER_INFO_TAG           "CID="
#define LM_CONTAINER_UUID_TAG           "UUID="
#define LM_LICGEN_UID_TAG               "lg_uid="
#define LM_LICGEN_TXN_UID_TAG           "lg_txuid="
#define LM_LICGEN_TXN_UPTCNT_TAG        "lg_txuptcnt="
#define LM_VENDOR_INFO_TAG              "VID="
#define LM_PRODUCT_ID_TAG               "PID="
#define LM_PRODUCT_PART_ID_TAG          "PPID="
#define LM_PERPETUAL_TAG                "Perpetual="
#define LM_START_DATE_TAG               "Start date="
#define LM_END_DATE_TAG                 "End date="
#define LM_FEATURE_ID_TAG               "FID="
#define LM_REQR_ID_TAG                  "Lic_reqr="
#define LM_CONCUR_LIMIT_TAG             "Cncr_limit="
#define LM_UPDATE_COUNTER_TAG           "Upd_cntr="
#define LM_CUSTOM_ATTR_KEY_ID_TAG       "Attr_key="
#define LM_CUSTOM_ATTR_KEY_VAL_TAG      "Attr_val="

#define OFFSETOF(type, member) ((size_t) &((type *)0)->member)/*lint !e893*/
#define FIT_CONT_ID_LEN           0x10

/* we have starting from Fit 1.2 a header in front of sproto license */
/* first two bytes are 0. In this case old core (> 1.2) will see license as empty and return error */
/* starting from 1.2 the first two bytes being zero are considered signature */
/* byte 3 and 4 are the minimal required core version */
#define FIT_SIZEOF_LICENSE_HEADER			4  

/* Types ********************************************************************/

/*
 * Global structure for caching RSA validation data. It caches the hash of license
 * string using Davies Meyer hash function.
 */
typedef struct fit_cache_data {
    /** TRUE if RSA operation was performed, FALSE otherwise */
    fit_boolean_t rsa_check_done;
    /** Davies Meyer hash of license data.*/
    uint8_t dm_hash[FIT_DM_HASH_SIZE];
} fit_cache_data_t;

/** Associate a unique string and a tagid for each member of sproto */
typedef struct fit_sproto_types {
    /** String to be associated with each member of sproto */
    char const *str;
    /** wire type corresponding of sproto member */
    uint8_t wiretype;
    /** tagid corresponding of sproto member */
    uint8_t tagid;
} fit_sproto_types_t;

/*
 * Prototype of a callback function. This function is called during parsing of 
 * sentinel fit licenses.
 */
typedef fit_status_t (*fit_parse_callback)(fit_pointer_t *pdata,
                                           fit_tag_id_t tagid,
                                           uint32_t length,
                                           void *opdata,
                                           fit_pointer_t *license);

/*
 * This structure is used for registering fit_parse_callbacks for each operation type.
 * Each callback fn should have same prototype.
 */
typedef struct fit_parse_callbacks
{
    uint8_t operation;              /* Operation to be perform on license data */
    fit_parse_callback callback_fn; /* Callback function that will do operation */
} fit_callbacks_t;

#ifdef FIT_USE_UNIT_TESTS

/*
 * Prototype of a callback function. This function is called during parsing of sentinel fit
 * licenses for testing validity of licenses.
 */
typedef fit_status_t (*fit_test_field_callback)(fit_pointer_t *pdata,
                                                fit_tag_id_t tagid,
                                                void *opdata);

/*
 * This structure is used for registering fit_parse_callbacks for any member of license
 * binary (see sproto schema). Callback function can be same for tag identifiers or
 * different/unique for each tag identifier, but each callback fn should have same
 * prototype.
 */
struct fit_testcallbacks
{
    /** tag identifier (as per sproto schema)on which operation is to be performed.*/
    fit_tag_id_t tagid;
    /** Operation to be perform on license data */
    uint8_t operation;
    /** Callback function that will do operation */
    fit_test_field_callback callback_fn;
} fit_testcallbacks_t;


#endif /* #ifdef FIT_USE_UNIT_TESTS */

/* Function Prototypes ******************************************************/

/**
 *
 * \skip fit_memcpy
 *
 * Copies data from source to destination location.
 *
 * @param OUT   dst     \n Destination pointer where data need to copied.
 *
 * @param IN    src     \n Source pointer which need to be copied to destination
 *                         pointer
 *
 * @param IN    srclen  \n Length of data to be copied.
 *
 */
int fit_memcpy(void *dst, size_t dstlen, void *src, size_t srclen);

/**
 *
 * \skip fitptr_memcpy
 *
 * Copies data from source to destination location. Source data comes from fit_pointer_t.
 *
 * @param OUT   dst     \n Destination pointer where data need to copied.
 *
 * @param IN    src     \n Pointer to fit_pointer_t that contains source data pointer
 *                         and length to be copied.
 *
 */
int fit_fitptr_memcpy(uint8_t *dst, uint16_t dstlen, fit_pointer_t *src);


/**
 *
 * \skip fit_fitptr_memcmp
 *
 * Compares data from two different memory address.
 *
 * @param IN    pdata1  \n Pointer to data1
 *
 * @param IN    pdata2  \n Pointer to data2
 *
 * @param IN    len     \n Length of data to be compared.
 *
 * @return 0 if pdata1 and pdata2 are same; otherwise return difference.
 *
 */
int32_t fit_fitptr_memcmp(fit_pointer_t *pdata1, uint8_t *pdata2, uint32_t len);


/*
 * This function will fetch fingerprint/deviceid for the respective board. This will
 * call the hardware implemented callback function which will give raw data that would
 * be unique to each device. Raw data would be then hash with Daview Meyer hash function.
 */
fit_status_t fit_get_device_fpblob(fit_fingerprint_t* fp,
                                   fit_fp_callback callback_fn);

/** This function is used to validate the fingerprint information present in license data */
fit_status_t fit_validate_fp_data(fit_pointer_t *license);

/** This function will return the current time in unix.*/
fit_status_t fit_getunixtime(uint32_t *unixtime);

/** This function is used to validate minimal core version requirement */
fit_status_t fit_check_license_version(fit_pointer_t *license);

/** This function is used to extract part of the license which is signed */
fit_status_t fit_get_license_part_data(fit_pointer_t* license,uint32_t* length,uint8_t** data);

/* This function will get the key data corresponding to algorithm id from key array */
fit_status_t fit_get_key_data_from_keys(fit_key_array_t *keys,
                                        uint32_t algorithm,
                                        fit_pointer_t *key,
                                        fit_boolean_t *keyfound);

/* get vendor id with which fit core is build */
uint32_t fit_get_vendor_id(void);
/* This function will undo the changes done by fit_licenf_init fn */
fit_status_t fit_licenf_uninit(void);

/** This function is used to validate signature (AES, RSA etc) in the license binary. */
fit_status_t fit_verify_license(fit_pointer_t *license,
                                fit_key_array_t *keys,
                                fit_boolean_t check_cache,
                                fit_boolean_t check_prst);

fit_status_t fit_internal_verify_license(fit_pointer_t *license,
                                         fit_key_array_t *keys,
                                         fit_boolean_t check_cache,
                                        fit_boolean_t check_prst);

/* Internal function implementation for exposed api's */
fit_status_t fit_internal_find_feature(fit_license_t *license_t,
                                       uint32_t feature_id,
                                       uint32_t flags,
                                       fit_feature_ctx_t* feature_h);

fit_status_t fit_internal_find_item(fit_license_t *license_t,
                                    fit_lic_scope_t* lic_scope_ref,
                                    fit_lic_scope_t* lic_scope_item,
                                    uint32_t flags,
                                    fit_info_item_t* item);

fit_status_t fit_internal_get_license_info(fit_license_t *license_t,
                                           fit_lic_scope_t* lic_scope_ref,
                                           fit_info_item_t* item);

fit_status_t fit_internal_start_consume_feature(fit_feature_ctx_t *context,
                                                uint32_t flags);

fit_status_t fit_internal_prepare_license_update(fit_license_t* license_old,
                                                 fit_license_t* license_new);


#ifdef FIT_USE_SYSTEM_CALLS
#define fit_memcmp memcmp
#define fit_memset memset
#define fit_strcat(dst,dlen,src) strcat(dst,src)
#else
int fit_memcmp(const uint8_t *pdata1, const uint8_t *pdata2, size_t len);
void *fit_memset(void *pdata, uint8_t value, unsigned int len);
int fit_strcat(char* dst, unsigned int dstlen, const char * src);
#endif

char* fit_utoa(uint64_t intval, char *str);

/** Secure memory comparision function */
int16_t fit_sec_memcmp(uint8_t* pdata1, uint8_t* pdata2, uint16_t len);
int16_t fit_fitptr_sec_memcmp(fit_pointer_t *pdata1, const uint8_t *pdata2, uint16_t len);
fit_status_t fit_check_init_status(void);

#ifdef FIT_USE_NODE_LOCKING

/* base64 encode functions */
fit_status_t fit_base64_encode(uint8_t *dst, uint32_t dlen, uint32_t *olen,
                               const uint8_t *src, uint32_t slen);

fit_status_t fit_get_fingerprint(fit_pointer_t *fpdata, fit_fingerprint_t *fpstruct, fit_pointer_t *license);
#endif /* ifdef FIT_USE_NODE_LOCKING */

#ifdef FIT_USE_LEGACY_API

/**
 *
 * \skip fit_licenf_get_info
 *
 * This function will parse the license binary passed to it and call the user provided
 * callback function for every field data. User can take any action on receiving
 * license field data like storing values in some structure or can take some action
 * like calling consume license api with feature id etc.
 *
 * @param IN    \b  license     \n Start address of the license in binary format,
 *                                 depending on your READ_LICENSE_BYTE definition
 *                                 e.g. in case of RAM, this can just be the memory
 *                                 address of the license variable 
 *
 * @param IN    \b  callback_fn \n User provided callback function to be called by
 *                                 fit core.
 *
 * @param IO    \b  context     \n Pointer to user provided data structure.
 *
 * @return FIT_STATUS_OK on success; otherwise, returns appropriate error code.
 *
 */
fit_status_t fit_licenf_get_info(fit_pointer_t* license,
                                 fit_get_info_callback callback_fn,
                                 void *context);

/*
 * Callback function for get_info. Called for every item while traversing license data
 * This function will get complete license information for embedded devices
 */
fit_status_t fit_getlicensedata_cb (fit_tag_id_t tagid,
                                    fit_pointer_t *pdata,
                                    uint32_t length,
                                    fit_boolean_t *stop_parse,
                                    void *opdata,
                                    fit_pointer_t *license);


/** This function will fetch licensing information present in the data passed in.*/
EXTERNC fit_status_t fit_testgetinfodata(fit_pointer_t *licenseData,
                                         uint8_t *pgetinfo,
                                         uint32_t *getinfolen,
                                         void *opdata);

#endif // #ifdef FIT_USE_LEGACY_API

#endif  /* __FIT_INTERNAL_H__ */

