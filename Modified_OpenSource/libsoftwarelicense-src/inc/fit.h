/****************************************************************************\
**
** fit.h
**
** Sentinel FIT Licensing interface header file. File contains exposed interface for
** C/C++ language.
** 
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_H__
#define __FIT_H__

/* Required Includes ********************************************************/
#include "fit_types.h"
#include "fit_api.h"


/* Constants ****************************************************************/

/** Fixed size of RSA signature */
#define FIT_RSA_SIG_SIZE            0x100
/** Maximum feature id value supported */
#define FIT_MAX_FEATURE_ID_VALUE        0xFFFFFFFFu
/** Maximum product id value supported */
#define FIT_MAX_PRODUCT_ID_VALUE        0xFFBFu
/** Maximum UID length */
#define FIT_UID_LEN                     0x20
/** Maximum length for any field in sproto (except RSA signature) */
#define FIT_MAX_FIELD_SIZE              0x20

enum fit_license_type {
    /** Invalid value */
    FIT_LIC_INVALID_VALUE       = 0,
    /** Perpetual licenses */
    FIT_LIC_PERPETUAL,
    /** Time based licenses i.e no. of days from its first use */
    FIT_LIC_TIME_BASED,
    /** Execution based licenses */
    FIT_LIC_COUNTER_BASED,
    /** Time expiration based licenses */
    FIT_LIC_EXPIRATION_BASED,
};

/** Enum describing types of query to be operate on sentinel fit licenses. */
enum fit_operation_type {
    /** Default value. It means no data requested */
    FIT_OP_NONE              = 0,
    /** Get data address of license field (as per sproto schema) */
    FIT_OP_GET_DATA_ADDRESS,
    /** Get licence related info */
    FIT_OP_GET_LICENSE_INFO_DATA,    

#ifdef FIT_USE_UNIT_TESTS
    /*
     * Describes types of query to be operate on sentinel fit licenses for testing
     *licence string.
     */

    /** test for validate license data i.e. it should parse without any error.*/
    FIT_OP_TEST_PARSE_LICENSE,
    /** test for validate license container data */
    FIT_OP_TEST_LIC_CONTAINER_DATA,
    /** test for validate license vendor information data like vendor id etc. */
    FIT_OP_TEST_VENDOR_DATA,
    /** test for validate license product definition. */
    FIT_OP_TEST_LIC_PRODUCT_DATA,
    /** test for validate license property information. */
    FIT_OP_TEST_LIC_PROPERTY_DATA,
    /** test for validate license fetaure definition or data. */
    FIT_OP_TEST_FEATURE_DATA,
    /** test for validate license header information like version information etc. */
    FIT_OP_TEST_LIC_HEADER_DATA,
    /** test for wire protocol */
    FIT_OP_TEST_WIRE_PROTOCOL,
    /** test for validity of AES algorithm */
    FIT_OP_TEST_AES_ALGORITHM,
#endif /* #ifdef FIT_USE_UNIT_TESTS */

    FIT_OP_LAST,
};

/** enum containing information codes used internally */
enum fit_information_codes
{
	/** Stop further parsing of Sentinel fit Licenses */
	FIT_INFO_STOP_PARSE = 1,
	/** Continue parsing of Sentinel fit Licenses */
	FIT_INFO_CONTINUE_PARSE,
	/* No more entries in table containinf license and sproto state information */
	FIT_INFO_SPROTO_TABLE_EMPTY,
};

typedef enum fit_information_codes fit_information_codes_t;


/* Forward Declarations *****************************************************/

/* Types ********************************************************************/

/*
 * Defines operational data for sentinel fit. This structure is used when user wants to query
 * license data, or wants to see current state of sentinel fit licenses.
 */
typedef struct fit_op_data {
    /*
     * Defines operation type to be performed on license string. See enum 
     * fit_operation_type
     */
    uint8_t operation;
    /* tagid represents member field in license binary (as per sproto schema) */
    fit_tag_id_t tagid;
    /** FIT_TRUE if test callback fn to be called; FIT_FALSE otherwise.*/
    fit_boolean_t testop;
    /** Contains length of license string or license object depending upon operation value.*/
    uint32_t length;
    /** Contains Return value if required.*/
    fit_status_t status;
    /** Contains information code value like FIT_INFO_STOP_PARSE, FIT_INFO_CONTINUE_PARSE etc. */
    fit_information_codes_t parserstatus;
    /* requested data type */
    fit_wire_type_t type;
    /* pointer to string if exact match is to be found */
    uint8_t *string;
    /* flags for fit_find_item */
    uint32_t flags;
    /* integer value if exact match is to be found */
    uint64_t intval;

    union {
        /*
         * License data address. To be used for getting pointer to any field (as per sproto schema)
         * in license binary
         */
        uint8_t *addr;
        /*
        * Can be feature id or product id or any other valid value for sentinel fit
        * based licenses.
        */
        uint32_t id;

        /** get info data.*/
        struct {
            /** Pointer to callback function to be called for get info api.*/
            fit_get_info_callback callback_fn;
            /** Pointer to requested data for get info api.*/
            void *get_info_data;
        } getinfodata;

    } parserdata;

} fit_op_data_t;

/** Structure describing fingerprint information.*/
typedef struct fit_fingerprint {
/** fingerprint magic.*/
    uint32_t    magic;
    uint32_t     algid;
/** hash (Davies Meyer) of fingerprint */
    uint8_t     hash[FIT_DM_HASH_SIZE];
} fit_fingerprint_t;

/* Macro Functions **********************************************************/

/* Function Prototypes ******************************************************/


#endif /* __FIT_H__ */

