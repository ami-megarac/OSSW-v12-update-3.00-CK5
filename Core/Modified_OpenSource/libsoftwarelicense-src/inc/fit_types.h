/****************************************************************************\
**
** fit_types.h
**
** Basic types used in Sentinel FIT
** 
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_TYPES_H__
#define __FIT_TYPES_H__

/** Required Includes ********************************************************/
#ifndef _MSC_VER
#include <stdint.h>
#endif
#include "fit_status.h"

/** we check if NULL is correctly defined  - please adapt the check to your compiler if you get an error*/
#if !defined(__STDC__) && !defined(COMX_FIT_EXPORTS) && !defined(WIN32) 
#if NULL != 0  
        #error Sentinel Fit code was built using standard C presuming NULL is defined as (void*)0 or 0
#endif 
#endif
/** Constants ****************************************************************/
/** Maximum no. of level supported in sproto schema */
#define FIT_MAX_LEVEL                       0x10
/** Maximum no. of index in a level supported in sproto schema */
#define FIT_MAX_INDEX                       0x10
/** Davies meyer hash size */
#define FIT_DM_HASH_SIZE                    0x10
/** Invalid concurrency value */
#define FIT_INVALID_CONCURRENCY_VALUE       0xFFFFFFFFU
/** Invalid start date value */
#define FIT_INVALID_START_DATE              0x0
/** Invalid end date value */
#define FIT_INVALID_END_DATE                0x0
/** license element scope is global */
#define FIT_LICENF_LICENSE_SCOPE_GLOBAL     NULL

#define FIT_MAX_ACTIVE_ALGORITHMS 4
#define FIT_MAX_ACTIVE_KEYS       3

/** Types ********************************************************************/

/**
 * it's safe to rely on stdint types being available, since they are crucial
 * for embedded stuff; does not make any sense to introduce own types apart
 * from annoying users
 */

#ifdef _MSC_VER

typedef unsigned char           uint8_t;
typedef signed char             int8_t;
typedef unsigned short          uint16_t;
typedef signed short            int16_t;
typedef unsigned long           uint32_t;
typedef signed long             int32_t;
typedef signed long long int    int64_t;
typedef unsigned long long int  uint64_t;

#endif /** _MSC_VER */

/** Types ********************************************************************/

/** Prototype of read "license/RSA public key" byte callback function.*/
typedef uint8_t (*fit_read_byte_callback_t)(const uint8_t *address);

typedef unsigned char fit_boolean_t;

/** boolean types for Sentinel fit project */
#define FIT_FALSE   0
#define FIT_TRUE    1

/**
 * Define tag id for each field (as per sproto schema). So each tagid will represent
 * member/field used in sentinel fit licenses.
 */
enum fit_tag_id {
    FIT_BASE_TAG_ID_VALUE = 0,

    FIT_V2C_TAG_ID,
    FIT_LICENSE_TAG_ID,
    FIT_LIC_CONTAINER_ARRAY_TAG_ID,
    FIT_LIC_CONTAINER_TAG_ID,
    FIT_ID_LC_TAG_ID                    = 5,
    FIT_VENDOR_ARRAY_TAG_ID,
    FIT_LIC_CONT_NAME_TAG_ID,
    FIT_VENDOR_TAG_ID,
    FIT_VENDOR_ID_TAG_ID,
    FIT_PRODUCT_ARRAY_TAG_ID            =10,
    FIT_VENDOR_NAME_TAG_ID,
    FIT_PRODUCT_TAG_ID,
    FIT_PRODUCT_ID_TAG_ID,
    FIT_PRODUCT_VER_REGEX_TAG_ID,
    FIT_PRODUCT_PART_ARRAY_TAG_ID       =15,
    FIT_PRODUCT_NAME_TAG_ID,
    FIT_PRODUCT_PART_TAG_ID,
    FIT_PRODUCT_PART_ID_TAG_ID,
    FIT_LIC_PROP_TAG_ID,
    FIT_PRODUCT_PART_NAME_TAG_ID        =20,
    FIT_CUSTOM_ATTR_ARRAY_TAG_ID,
    FIT_FEATURE_ARRAY_TAG_ID,
    FIT_PERPETUAL_TAG_ID,
    FIT_START_DATE_TAG_ID,
    FIT_END_DATE_TAG_ID                 =25,
    FIT_COUNTER_ARRAY_TAG_ID,
    FIT_DUR_FROM_FIRST_USE_TAG_ID,
    FIT_DUR_START_DATE_TAG_ID,
    FIT_FEATURE_TAG_ID,
    FIT_FEATURE_ID_TAG_ID               =30,
    FIT_FEATURE_NAME_TAG_ID,
    FIT_COUNTER_TAG_ID,
    FIT_COUNTER_ID_TAG_ID,
    FIT_COUNTER_LIMIT_TAG_ID,
    FIT_COUNTER_SOFT_LIMIT_TAG_ID       =35,
    FIT_COUNTER_IS_FIELD_TAG_ID,
    FIT_COUNTER_NAME_TAG_ID,
    FIT_CONCURRENCY_TAG_ID,
    FIT_CONCURRENCY_LIMIT_ID,
    FIT_CONCURRENCY_SOFT_LIMIT_ID       =40,
    FIT_CONCURRENCY_BORROWABLE_ID,
    FIT_CONCURRENCY_BORROW_LIMIT_ID,
    FIT_CONCURRENCY_BORROW_PERIOD_ID,
    FIT_CUSTOM_ATTR_TAG_ID,
    FIT_CUSTOM_ATTR_KEY_TAG_ID          =45,
    FIT_CUSTOM_ATTR_KEY_VALUE_TAG_ID,
    FIT_LICGEN_VERSION_TAG_ID,
    FIT_LM_VERSION_TAG_ID,
    FIT_UID_TAG_ID,
    FIT_FP_TAG_ID                       =50,
    FIT_REQUIREMENTS_TAG_ID,
    FIT_UPDATE_COUNTER_TAG_ID,
    FIT_HEADER_TAG_ID,
    FIT_ALGORITHM_ID_TAG_ID,
    FIT_SIGNATURE_STR_TAG_ID            =55,
    FIT_SIGNATURE_TAG_ID,
    FIT_SIG_ARRAY_TAG_ID,
    FIT_LIC_CONT_UUID_TAG_ID,
    FIT_SYSTEM_ATTR_ARRAY_TAG_ID,
    FIT_SYSTEM_ATTR_TAG_ID              =60,
    FIT_SYSTEM_ATTR_KEY_TAG_ID,
    FIT_SYSTEM_ATTR_KEY_VALUE_TAG_ID,
    FIT_PROD_CUSTOM_ATTR_ARRAY_TAG_ID,
    FIT_PROD_CUSTOM_ATTR_TAG_ID,
    FIT_PROD_CUSTOM_ATTR_KEY_TAG_ID     =65,
    FIT_PROD_CUSTOM_ATTR_KEY_VALUE_TAG_ID,
    FIT_LICGEN_SEQ_TAG_ID,
    FIT_LICGEN_SEQ_UID_TAG_ID,
    FIT_LICGEN_SEQ_TXUID_TAG_ID,
    FIT_LICGEN_SEQ_TXUPT_CNT_TAG_ID     =70,

    /** Please Update FIT_END_TAG_ID when adding new tag id's at bottom of list.*/
    FIT_END_TAG_ID, 
};

typedef enum fit_tag_id fit_tag_id_t;

/** enum describing about algorithm used in Sentinel Fit project */
typedef enum fit_algorithm_id {
    /** RSA algorithm used for signing the license */
    FIT_RSA_2048_ADM_PKCS_V15_ALG_ID      = 1,
    /** AES-128 algorithm used for signing the license */
    FIT_AES_128_OMAC_ALG_ID,
    /** AES-256 algorithm used for crypto purposes in Sentinel Fit*/
    FIT_AES_256_ALG_ID,

    /** Maximum value that algorithm id can take */
    FIT_ALG_ID_MAX = 4095,
} fit_algorithm_id_t;

/** enum describing scope of algorithm id usage */
typedef enum fit_key_scope {
    /** For signing the license or sproto field (as per sproto schema) */
    FIT_KEY_SCOPE_SIGN =   1,
    /** For crypto related operations for sproto field (as per sproto schema) */
    FIT_KEY_SCOPE_CRYPT,

    /** Maximum value that key scope can take */
    FIT_KEY_SCOPE_ID_MAX = 15,

} fit_key_scope_t;


/** valid flags values for fit_licenf_find_feature api  */
#define  FIT_FIND_FEATURE_FIRST  1  /** Start parsing license from beginning */
#define  FIT_FIND_FEATURE_NEXT   2  /** Continue parsing from existing location */

typedef int fit_find_feature_flags;

/** valid flags values for fit_licenf_find_item api  */
#define FIT_FIND_ITEM_FIRST  1   /** Start parsing license from beginning */
#define	FIT_FIND_ITEM_NEXT   2   /** Continue parsing from existing location */
#define FIT_FIND_ITEM_MATCH  4   /** Check for matching value */

typedef int fit_find_item_flags;

/** Sentinel fit license schema data types. - restricted to 8 bits*/
typedef uint8_t fit_wire_type_t;

#define FIT_INVALID_VALUE  0
#define FIT_INTEGER        1     /** Repesents integer data */
#define FIT_STRING         2     /** Represents string data */
#define FIT_BOOLEAN        3     /** Represents boolean data */
#define FIT_OBJECT         4     /** Represents object.*/
#define FIT_ARRAY          5     /** Represents arrays of object.*/
#define FIT_BINARY         6     /** Represents binary data */

    

/** Structure describing list of algorithm supoorted for any crypto/signing key. */
typedef struct fit_algorithm_list {
    /** Number of algorithm supported crypto/signing key. */
    uint8_t num_of_alg;
    /** GUID having algorithm id and its scope
      * algorithm_id = 12 bits | key scope = 4 bits => algorithm_guid
      * Sentinel Fit supports upto 16 scopes and 4095 algorithms
      */
    uint16_t *algorithm_guid[FIT_MAX_ACTIVE_ALGORITHMS];

} fit_algorithm_list_t;

/** Structure descibing key (signing/crypto) data and purpose of that key in Sentinel Fit */
typedef struct fit_key_data {
    /** Key data used for license verification or crypto purposes */
    uint8_t *key;
    /** Length of above key */
    uint32_t key_length;  
    /** List of algorithm that above key will support and its scope */
    fit_algorithm_list_t *algorithms;

} fit_key_data_t;

/**
 * To access the license data and RSA public key data in differnt types of memory
 * (FLASH, E2, RAM), following structure is used.
 */
typedef struct fit_pointer
{
    /** pointer to data to be read. */
    uint8_t *data;
    /** length of data to be read.*/
    uint32_t length;  
    /** pointer to read byte function for reading data part.*/
    fit_read_byte_callback_t read_byte;
}fit_pointer_t;


/** Strcuture descibing arrays of key data for Sentinel Fit and function for reading data part */
typedef struct fit_key_array {
    /** pointer to read byte function for reading key part.*/
    fit_read_byte_callback_t read_byte;
    /** Number of supported keys */
    uint8_t number_of_keys;
    /** Array of fit_key_data_t structures */
    fit_key_data_t *keys[FIT_MAX_ACTIVE_KEYS];
    /* Vendor id corresponding to key data */
    uint32_t vendor_id;
} fit_key_array_t;

/** Structure containing license data and keys data for checking license vailidity.*/
typedef struct fit_license
{
    /** pointer to license data.*/
    fit_pointer_t *license;
    /** pointer to keys data that used to check license validity.*/
    fit_key_array_t *keys;
    /** Contains Magic number 'FIT_LIC_VERIFIED_MAGIC_NUM', if license signature is
      * correctly verified 
      */
    uint32_t sig_verified_marker;
} fit_license_t;

/** license object */
typedef union fit_object
{
    /** will contain integer value if license item is integer */
    uint64_t intval;
    /** will contain boolean value if license item is boolean */
    fit_boolean_t boolval;
    /** Only used as input data (e.g. if the FIND_MATCH flag is set, and a certain value should be found) */
    uint8_t* string;
    /** Only used as output data (e.g. to return a pointer to the relevant data in the license structure) */
    fit_pointer_t data_ptr;
} fit_object_t;

/** fit license item */
typedef struct fit_info_item
{
    fit_tag_id_t tag_id;
    fit_wire_type_t type;
    fit_object_t object;
} fit_info_item_t;

/** Struture describing concurrency element */
typedef struct fit_concurrency
{
    /** concurrency limit */
    uint32_t limit;
} fit_concurrency_t;

/** Type of licensing model supported.*/
typedef struct fit_licensemodel
{
    /** for perpetual licenses.*/
    fit_boolean_t       isperpetual;
    /** Start date information for time based licenses.*/
    uint32_t            startdate;
    /** End date information for time based licenses.*/
    uint32_t            enddate;
    /** Concurrency count. */
    fit_concurrency_t   concurrency;
} fit_licensemodel_t;


/** Struture describing sproto element. */
typedef struct sp_node{
    /** Tag identifier corresponding to license element.*/
	fit_tag_id_t tagid;
   /**
     * Pointer to child nodes. Child node can be another object, pointers to objects,
     * integer or string.
     */
    const struct sp_childs* childs;
}SP_NODE;

/** Structure describing sproto object. */
typedef struct sp_childs{
    /** Number of childs in the "list" */
    uint8_t number;
    /** List of sproto elements describing the sproto objects */
    const SP_NODE* nodes;
}SP_CHILD;

/** Object containing license elements states during parsing of license data.
  * Also contains state of sproto objects during license parsing.
  */
typedef struct fit_lic_parser_state {
    /** Pointer to license data corresponding to sproto object. */
    uint8_t     *data;
    /** Length of above data passed in */
    uint32_t    datalen;
    /** Tells about wire_type of stored object */
    fit_wire_type_t objtype;
    /** Pointer to child nodes of sproto object (as per sproto schema). */
    SP_CHILD *child_nodes;
    /** Current element number in process (sproto table). */
    uint8_t sproto_obj_cntr;

    union {
        struct {
            /** Current object in sequence at particular level.*/
            uint8_t cur_obj;
            /** Represents start of field data(all except integer data) i.e. number of bytes 
              * after which field data will start. If field value is 00 00 that means data
              * corresponding to that filled will be encoded in data part.
              */
            uint32_t obj_data_offset;
            /**
              * skip_elements represents number of fields to skip or number of fields that
              * does not have any data in license binary.
              */
            uint8_t skip_elements;
            /** FIT_TRUE if first element of object has been parsed; FIT_FALSE otherwise. */
            fit_boolean_t not_first_element;
        }obj;

        struct {
            /** Total size of all objects in an array in case objtype is FIT_ARRAY */
            uint32_t array_size;
            /** Total size parsed in case objtype is FIT_ARRAY */
            uint32_t parsed_array_size;
        }arr;
    }node;

} fit_lic_parser_state_t;

/** fit_lic_scope_t maigic -- fitS*/
#define FIT_SCOPE_INITIALIZED_MAGIC     0x666D7453 

/** Tree node path to a specific element in the sproto license */
typedef struct fit_lic_scope
{
    /** level/depth of of license element */
    uint8_t depth;
    /** tells if all nodes of reference path are done or not. */
    fit_boolean_t ref_path_done;
    /** Array of license element states */
    fit_lic_parser_state_t node[FIT_MAX_LEVEL];
    /** magic to be sure structure is initialized*/
    uint32_t magic;
    /** tag id that corresponds to the scope*/
    fit_tag_id_t tag_id;
} fit_lic_scope_t;

/** Feature related information  This informtaion is used in case of calling fit_licenf_find_feature API. */
typedef struct fit_feature_info {
    /** contains feature id value in fit_licenf_find_feature */
    uint32_t feature_id;
    /** contains product id associated with above feature id */
    uint32_t product_id;
    /** license model associated with above feature id */
    fit_licensemodel_t license_model;
} fit_feature_info_t;

/** Structure containing the feature context. Used as a handle for a feature */
typedef struct fit_feature_ctx  {
    /** Indicates that the license data and feature context is valid . */
    uint32_t lic_verified_marker;
    /** structure containing license and keys data. */
    fit_license_t lic_data;
    /** Detailed information on feature and license model */
    fit_feature_info_t feature_info;
    /** Current scope of the feature in the license (tree node path) */
    fit_lic_scope_t lic_scope;
} fit_feature_ctx_t;


/** Prototype of a get_info callback function.
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

typedef fit_status_t (*fit_get_info_callback)(fit_tag_id_t tagid,
                                              fit_pointer_t *pdata,
                                              uint32_t length,
                                              fit_boolean_t *stop_parse,
                                              void *opdata,
                                              fit_pointer_t *license);

/** Prototype of a get fingerprint/deviceid data callback function.
 *
 * @param IO  \b  rawdata       \n  pointer to buffer containing the fingerprint raw data
 *
 * @param IN  \b  rawdata_size  \n  size of rawdata buffer
 *
 * @param OUT  \b  datalen      \n  pointer to integer which will return length of raw data 
 *                                  returned back
 *
 */

typedef fit_status_t (*fit_fp_callback)(uint8_t *rawdata,
                                        uint8_t rawdata_size,
                                        uint16_t *datalen);

/** Macro Functions **********************************************************/

/** Extern Data **************************************************************/

extern fit_status_t fit_prst_init_status;

/** Function Prototypes ******************************************************/

#endif /** __FIT_TYPES_H__ */

