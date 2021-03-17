/****************************************************************************\
**
** fit_internal.c
**
** Defines functionality for common function use across Sentinel fit project.
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
#include <string.h>
#endif

#include "fit_parser.h"
#include "fit_internal.h"
#include "fit_debug.h"
#include "fit_mem_read.h"
#include "fit_aes.h"
#include "fit_consume.h"
#include "fit_rsa.h"
#include "fit_omac.h"
#include "fit_version.h"
#include "fit_capabilities.h"
#include "fit_hwdep.h"
#ifdef FIT_USE_PERSISTENT
#include "fit_persistent.h"
#endif // #ifdef FIT_USE_PERSISTENT
#ifdef FIT_USE_NODE_LOCKING
#include "fit_dm_hash.h"
#endif /* ifdef FIT_USE_NODE_LOCKING */

/* Global Data **************************************************************/
fit_boolean_t g_fit_init = FIT_FALSE; //lint !e765

#ifdef FIT_USE_MULTI_THREAD
fit_mutex_t fit_init_mutex = INITITIAL_MUTEX_VALUE; //lint !e708
fit_mutex_t fit_mutex = INITITIAL_MUTEX_VALUE; //lint !e708
#endif // #ifdef FIT_USE_MULTI_THREAD


/**
 *
 * Function address can be of 2 bytes or 4 bytes or x bytes depending upon data bus.
 * This function will return fn address depending upon length of pointer.
 *
 */

static fit_status_t fit_get_fn_address(uint8_t * addr,/*lint !e818 */
                                       fit_read_byte_callback_t clbk_read_byte,
                                       uint8_t **value)
{
    uint8_t x = sizeof(uint8_t *);

    switch(x)
    {
    case 2:
        {
            uint16_t v = fit_read_word(addr, clbk_read_byte);
            if (fit_memcpy((uint8_t*)value, sizeof(v), (uint8_t*)&v, sizeof(v)) != 0)
            {
                return FIT_STATUS_BUFFER_OVERRUN;
            }
        }
        break;
    case 4:
        {
            uint32_t v = fit_read_dword(addr, clbk_read_byte);
            if (fit_memcpy((uint8_t*)value, sizeof(v), (uint8_t*)&v, sizeof(v)) != 0)
            {
                return FIT_STATUS_BUFFER_OVERRUN;
            }
        }
        break;
    case 8:
        {
            uint64_t v = fit_read_ulonglong(addr, clbk_read_byte);
            if (fit_memcpy((uint8_t*)value, sizeof(v), (uint8_t*)&v, sizeof(v)) != 0)
            {
                return FIT_STATUS_BUFFER_OVERRUN;
            }
        }
        break;

    default:
        break;
    }

    return FIT_STATUS_OK;
}

/**
 *
 * \skip fit_get_key_data_from_keys
 *
 * This function is used to get key data (AES, RSA etc) corresponding to algorithm
 * id passed in from license binary.
 *
 * @param IN    keys    \n Pointer to fit_key_array_t structure containing array of
 *                         key data and algorithms supported for each key.
 *
 * @param IN    algorithm   \n Algorithm id for which key data is to be fetch from
 *                             keys array.
 *
 * @param OUT   key     \n Pointer to fit_pointer_t structure that will contain
 *                         requested key data.
 *
 * @param OUT   keyfound    \n return FIT_TRUE if key data found corresponding to
 *                             algid else FIT_FALSE
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_get_key_data_from_keys(fit_key_array_t *keys,
                                        uint32_t algorithm,
                                        fit_pointer_t *key,
                                        fit_boolean_t *keyfound)
{
    fit_status_t status     = FIT_STATUS_KEY_NOT_PRESENT;
    uint16_t cntrx          = 0;
    uint16_t cntry          = 0;
    uint16_t keyscope       = 0;
    uint16_t algid          = 0;
    uint8_t num_keys        = 0;
    uint8_t num_of_alg      = 0;
    uint32_t key_len        = 0;
    uint16_t keysoffset     = 0;
    uint16_t keydataoffset  = 0;
    uint8_t *keydataptr     = NULL;
    uint16_t algdataoffset  = 0;
    uint8_t *algdataptr     = NULL;
    uint8_t *algguidptr     = NULL;
    uint8_t *keysdata       = (uint8_t *)keys;

    if ((keys == NULL) || (keys->read_byte == NULL)) {
        return FIT_STATUS_INVALID_PARAM;
    }

    *keyfound = FIT_FALSE;
    DBG(FIT_TRACE_INFO, "fit_get_key_data_from_keys: Entry\n");

    /** Check if presence of algorithm in fit_key_array_t data passed in.
      * if present then get the key data corresponding to algorithm id is put in fit_pointer_t
      * structure.
      */

    keysoffset = OFFSETOF(fit_key_array_t, number_of_keys);/*lint !e413 !e545*/
    num_keys = fit_read_byte(keysdata+keysoffset, (fit_read_byte_callback_t)FIT_READ_KEY_BYTE);

    /* offset to first key data structure */
    keysoffset = OFFSETOF(fit_key_array_t, keys);/*lint !e413 !e545*/
    for (cntrx = 0; cntrx < num_keys; cntrx++)
    {
        /* Get address where key data is stored */
        status = fit_get_fn_address(keysdata+keysoffset, (fit_read_byte_callback_t)FIT_READ_KEY_BYTE,
                &keydataptr);
        if (status != FIT_STATUS_OK)
        {
            return status;
        }

        /* offset to key_length member */
        keydataoffset = OFFSETOF(fit_key_data_t, key_length);/*lint !e413 !e545*/
        key_len = fit_read_dword(keydataptr+keydataoffset, (fit_read_byte_callback_t)FIT_READ_KEY_BYTE);

        DBG(FIT_TRACE_INFO, "Key Len: %d\n", key_len);
        /* Validate the length of the key. */
        if (key_len == 0) {
            continue;
        }

        /* Get the algorithm id and scope of the license. */
        keydataoffset = OFFSETOF(fit_key_data_t, algorithms);/*lint !e413 !e545*/
        status = fit_get_fn_address(keydataptr+keydataoffset, (fit_read_byte_callback_t)FIT_READ_KEY_BYTE,
            &algdataptr);
        if (status != FIT_STATUS_OK)
        {
            return status;
        }

        algdataoffset = OFFSETOF(fit_algorithm_list_t, num_of_alg);/*lint !e413 !e545*/
        num_of_alg = fit_read_byte(algdataptr+algdataoffset, (fit_read_byte_callback_t)FIT_READ_KEY_BYTE);

        /* offset to algorithm list structure */
        algdataoffset = OFFSETOF(fit_algorithm_list_t, algorithm_guid);/*lint !e413 !e545*/
        for (cntry = 0; cntry < num_of_alg; cntry++)
        {
            status = fit_get_fn_address(algdataptr+algdataoffset, (fit_read_byte_callback_t)FIT_READ_KEY_BYTE,
                &algguidptr);
            if (status != FIT_STATUS_OK)
            {
                return status;
            }

            keyscope = ((fit_read_word(algguidptr, (fit_read_byte_callback_t)FIT_READ_KEY_BYTE)) >> 12);
            algid = ((fit_read_word(algguidptr, (fit_read_byte_callback_t)FIT_READ_KEY_BYTE)) & 0xFFF);

            DBG(FIT_TRACE_INFO, "keyscope=%d, algid=%d\n", keyscope, algid);
            if ((fit_key_scope_t)keyscope < FIT_KEY_SCOPE_SIGN) 
            {
                return FIT_STATUS_INVALID_KEY_SCOPE;
            }

            /* If match then initialize the fit_pointer_t structure with the key data  */
            if (algid == algorithm)
            {
                DBG(FIT_TRACE_INFO, "Key Data found\n");
                status = fit_get_fn_address(keydataptr, (fit_read_byte_callback_t)FIT_READ_KEY_BYTE,
                    &key->data);
                if (status != FIT_STATUS_OK)
                {
                    return status;
                }
                key->length = key_len;
                key->read_byte = keys->read_byte;
                status = FIT_STATUS_OK;
                *keyfound = FIT_TRUE;
                break;
            }

            algdataoffset += sizeof(uint8_t *);
        }
        if (*keyfound == FIT_TRUE)
        {
            break;
        }

        keysoffset += sizeof(uint8_t *);
    }

    DBG(FIT_TRACE_INFO, "fit_get_key_data_from_keys: Exit\n");

    return status;
}



/**
 *
 * \skip fit_check_license_version
 *
 * This function is used to validate license version
 *
 * @param IN    license     \n Pointer to fit_pointer_t structure containing license
 *                             data. To access the license data in different types of
 *                             memory (FLASH, E2, RAM), fit_pointer_t is used.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_check_license_version(fit_pointer_t *license)
{
    fit_status_t status = FIT_STATUS_UNKNOWN_ERROR;
    uint16_t temp = 0;

    /* we check here if first two bytes of the license are 0 and if required LM
     * is smaller or equal than current core version 
     */
    status = fit_read_word_safe(license->data,license->read_byte, license, &temp);
    if(status != FIT_STATUS_OK)
    {
        return status;
    }

    if( temp != 0 )
    {
        return FIT_STATUS_INVALID_LICGEN_VER;
    }
    else
    {
        uint16_t required_lm_version = 0;
        uint16_t current_version = ((FIT_MAJOR_VERSION << 8) | FIT_MINOR_VERSION);

        status = fit_read_word_safe(license->data+2,license->read_byte, license, &required_lm_version);
        if(status != FIT_STATUS_OK)
        {
            return status;
        }

        if( required_lm_version > current_version)
        {
            return FIT_STATUS_INVALID_LICGEN_VER;
        }
    }

    return FIT_STATUS_OK;
}

/**
 *
 * \skip fit_internal_verify_license
 *
 * This function is used to validate signature (AES, RSA etc) in the license binary.
 *
 * @param IN    license     \n Pointer to fit_pointer_t structure containing license
 *                             data. To access the license data in different types of
 *                             memory (FLASH, E2, RAM), fit_pointer_t is used.
 *
 * @param IN    keys    \n  Pointer to array of key data. Also contains callback
 *                          to read key data in different types of memory(FLASH, E2, RAM).
 *
 * @param IN    check_cache \n FIT_TRUE if signing verification is already done; FIT_FALSE
 *                             otherwise.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_internal_verify_license(fit_pointer_t *license,
                                         fit_key_array_t *keys,
                                         fit_boolean_t check_cache,/*lint !e715 */
                                        fit_boolean_t check_prst)
{
    fit_status_t status             = FIT_STATUS_UNKNOWN_ERROR;
    fit_status_t getalgid_status    = FIT_STATUS_UNKNOWN_ERROR;
    uint32_t signalgid              = 0;
    fit_pointer_t key_data          = {(void*)0};
    fit_pointer_t sig_data          = {(void*)0};
    fit_boolean_t lic_verified      = FIT_FALSE;
    fit_lic_scope_t lic_scope_item  = {0};
    fit_op_data_t opdata            = { 0 };
    uint16_t temp1                  = 0;
    fit_boolean_t keyfound          = FIT_FALSE;
#ifdef FIT_USE_PERSISTENT
    uint32_t cntr                   = 0;
    uint8_t cont_id[FIT_CONT_ID_LEN] = {0};
    uint32_t upt_cntr               = 0;
    uint32_t prst_upt_cntr          = 0;
    uint32_t prst_size              = 0;
#endif // #ifdef FIT_USE_PERSISTENT

    DBG(FIT_TRACE_INFO, "[fit_internal_verify_license]: Entry");

    status = fit_licenf_initialize_scope(&lic_scope_item);
    if(status != FIT_STATUS_OK)
    {
        return status;
    }
    /* Logic of getting algid will change if licgen supports multiple algorithms
     * in one license binary
     */
    /* Parse license data to get first signing algorithm id. */
    (void)fit_memset((uint8_t *)&opdata, 0, (int)sizeof(fit_op_data_t));
    opdata.flags = FIT_FIND_ITEM_FIRST;
    opdata.tagid = FIT_ALGORITHM_ID_TAG_ID;
    opdata.type = FIT_INTEGER;
    opdata.operation = (uint8_t)FIT_OP_GET_DATA_ADDRESS;
    opdata.status = FIT_STATUS_OK;

    getalgid_status = fit_license_parser_execute(license, FIT_LICENF_LICENSE_SCOPE_GLOBAL, &lic_scope_item,
            FIT_FIND_ITEM_FIRST, &opdata);
    if (getalgid_status == FIT_STATUS_OK && (opdata.parserstatus == FIT_INFO_STOP_PARSE))
    {
        status = fit_read_word_safe(opdata.parserdata.addr, license->read_byte,
            license, (uint16_t *)&temp1);
        if(status != FIT_STATUS_OK)
        {
            return status;
        }
        signalgid = (uint32_t)((temp1 / 2) - 1);
        getalgid_status = FIT_STATUS_OK;
    }
    else
    {
        DBG(FIT_TRACE_ERROR, "Not able to get algorithm data used for license "
            "signing %d\n", (unsigned int)status);

        return getalgid_status;
    }

    /* Validate license signature */
    while (getalgid_status != FIT_STATUS_ITEM_NOT_FOUND)
    {
        keyfound = FIT_FALSE;
        /* Get key data corresponding to algid used in signing license binary */
        (void)fit_memset((uint8_t *)&key_data, 0x00, sizeof(fit_pointer_t));
        status = fit_get_key_data_from_keys(keys, signalgid, &key_data, &keyfound);
        if (status != FIT_STATUS_OK || keyfound != FIT_TRUE) {
            status = FIT_STATUS_KEY_NOT_PRESENT;
            goto get_next_algid;/*lint !e801*/
        }

        /* get signature data corresponding to algorithm id */
        (void)fit_memset((uint8_t *)&opdata, 0, (int)sizeof(fit_op_data_t));
        opdata.flags = FIT_FIND_ITEM_NEXT;
        opdata.tagid = FIT_SIGNATURE_STR_TAG_ID;
        opdata.type = FIT_STRING;
        opdata.operation = (uint8_t)FIT_OP_GET_DATA_ADDRESS;
        opdata.status = FIT_STATUS_OK;
        status = fit_license_parser_execute(license, FIT_LICENF_LICENSE_SCOPE_GLOBAL, &lic_scope_item,
            FIT_FIND_ITEM_NEXT, &opdata);
        if (status != FIT_STATUS_OK && opdata.parserstatus != FIT_INFO_STOP_PARSE) {
            break;
        }
        sig_data.data = opdata.parserdata.addr;
        sig_data.length = opdata.length;
        sig_data.read_byte = license->read_byte;

        if ((fit_algorithm_id_t)signalgid == FIT_RSA_2048_ADM_PKCS_V15_ALG_ID)
        {
#ifdef FIT_USE_RSA_SIGNING
            /* Verify the license string against RSA signing and node locking */
            status = fit_verify_rsa_signature(license, &key_data,
                &sig_data, check_cache);
            if (status == FIT_STATUS_OK) {
                lic_verified = FIT_TRUE;
                break;
            }
#else
            status = FIT_STATUS_NO_RSA_SUPPORT;
#endif // #ifdef FIT_USE_RSA_SIGNING
        }
        else if ((fit_algorithm_id_t)signalgid == FIT_AES_128_OMAC_ALG_ID)
        {
#ifdef FIT_USE_AES_SIGNING
            /* Verify the license string against AES signing and node locking */
            status = fit_validate_omac_signature(license, &key_data, &sig_data);
            if (status == FIT_STATUS_OK) {
                lic_verified = FIT_TRUE;
                break;
            }
#else
            status = FIT_STATUS_NO_AES_SUPPORT;
#endif // #ifdef FIT_USE_AES_SIGNING
        }

get_next_algid:
        if (status == FIT_STATUS_INVALID_SIGNATURE || status == FIT_STATUS_KEY_NOT_PRESENT || 
            status == FIT_STATUS_INVALID_SIGNING_KEY)
        {
            /* If license was not yet verified, get the next algorithm id and validate
             * against it, else return error 
             */
            (void)fit_memset((uint8_t *)&opdata, 0, (int)sizeof(fit_op_data_t));
            opdata.flags = FIT_FIND_ITEM_NEXT;
            opdata.tagid = FIT_ALGORITHM_ID_TAG_ID;
            opdata.type = FIT_INTEGER;
            opdata.operation = (uint8_t)FIT_OP_GET_DATA_ADDRESS;
            opdata.status = FIT_STATUS_OK;
            getalgid_status = fit_license_parser_execute(license, FIT_LICENF_LICENSE_SCOPE_GLOBAL, &lic_scope_item,
                FIT_FIND_ITEM_FIRST, &opdata);
            if (getalgid_status == FIT_STATUS_OK && (opdata.parserstatus == FIT_INFO_STOP_PARSE))
            {
                status = fit_read_word_safe(opdata.parserdata.addr, license->read_byte,
                    license, (uint16_t *)&temp1);
                if(status != FIT_STATUS_OK)
                {
                    return status;
                }
                signalgid = (uint32_t)((temp1 / 2) - 1);
                getalgid_status = FIT_STATUS_OK;
            }
            else
            {
                break;
            }
        }
        else
        {
            break;
        }
    }

    if (lic_verified == (fit_boolean_t)FIT_TRUE)
    {
        /* Check license requirements against core capabilities */
        status = fit_check_core_capabilities(license);
        if (status != FIT_STATUS_OK)
        {
            DBG(FIT_TRACE_CRITICAL, "fit_check_core_capabilities failed with error code %d\n",
                (unsigned int)status);
            return status;
        }
    }
    if (status != FIT_STATUS_OK)
    {
        return status;
    }


#ifdef FIT_USE_PERSISTENT

    if (check_prst == FIT_TRUE)
    {
        /* Get update counter value for update license */
        (void)fit_memset(&lic_scope_item, 0, sizeof(fit_lic_scope_t));
        status = fit_licenf_initialize_scope(&lic_scope_item);
        if(status != FIT_STATUS_OK)
        {
            return status;
        }
        /* Get update counter value for update license */
        (void)fit_memset((uint8_t *)&opdata, 0, (int)sizeof(fit_op_data_t));
        opdata.flags = FIT_FIND_ITEM_FIRST;
        opdata.tagid = FIT_LIC_CONT_UUID_TAG_ID;
        opdata.type = FIT_BINARY;
        opdata.operation = (uint8_t)FIT_OP_GET_DATA_ADDRESS;
        opdata.status = FIT_STATUS_OK;

        status = fit_license_parser_execute(license, FIT_LICENF_LICENSE_SCOPE_GLOBAL, &lic_scope_item,
                FIT_FIND_ITEM_FIRST, &opdata);
        if (status != FIT_STATUS_OK || (status == FIT_STATUS_OK && opdata.parserstatus != FIT_INFO_STOP_PARSE))
        {
            DBG(FIT_TRACE_INFO, "container uuid not present in license binary (may be license generated from <= 1.3)"
                "status=%d\n", (unsigned int)status);
            return FIT_STATUS_OK;
        }
        for (cntr = 0; cntr < opdata.length; ++cntr)
        {
            cont_id[cntr] = license->read_byte(opdata.parserdata.addr + cntr);
        }

        (void)fit_memset((uint8_t *)&opdata, 0, (int)sizeof(fit_op_data_t));
        opdata.flags = FIT_FIND_ITEM_NEXT;
        opdata.tagid = FIT_UPDATE_COUNTER_TAG_ID;
        opdata.type = FIT_INTEGER;
        opdata.operation = (uint8_t)FIT_OP_GET_DATA_ADDRESS;
        opdata.status = FIT_STATUS_OK;

        status = fit_license_parser_execute(license, FIT_LICENF_LICENSE_SCOPE_GLOBAL, &lic_scope_item,
                FIT_FIND_ITEM_NEXT, &opdata);
        if (status != FIT_STATUS_OK || (status == FIT_STATUS_OK && opdata.parserstatus != FIT_INFO_STOP_PARSE))
        {
            DBG(FIT_TRACE_INFO, "update counter value not present in license binary (may be license generated from <= 1.3)"
                "status=%d\n", (unsigned int)status);
            return FIT_STATUS_OK;
        }

        status = fit_read_word_safe(opdata.parserdata.addr, license->read_byte,
            license, (uint16_t *)&temp1);
        if(status != FIT_STATUS_OK)
        {
            return status;
        }
        upt_cntr = (uint32_t)((temp1 / 2) - 1);
        prst_size = sizeof(prst_upt_cntr);

        status = fit_persist_element_get(cont_id, FIT_PRST_UPDATE_COUNT_REF_ID,
            (uint8_t *)&prst_upt_cntr, &prst_size);

        if (upt_cntr == 0 && (status == FIT_STATUS_PRST_ID_NOT_FOUND || status == FIT_STATUS_PRST_NOT_INIT))
        {
            /* no persistence present */
            return FIT_STATUS_OK;
        }
        else  if (upt_cntr > 0 && status == FIT_STATUS_PRST_ID_NOT_FOUND)
        {
            /* no persistence present */
            return status;
        }
        /* Check if Update counter of license matches with the one in the persistence. */
        if (upt_cntr > 0 && prst_upt_cntr > upt_cntr)
        {
            return FIT_STATUS_UPDATE_COUNT_MISMATCH;
        }

    }

#endif // FIT_USE_PERSISTENT

    DBG(FIT_TRACE_INFO, "[fit_internal_verify_license]: Exit");

    return status;
}

/**
 *
 * \skip fit_verify_license
 *
 * This function is used to validate signature (AES, RSA etc) in the license binary.
 *
 * @param IN    license     \n Pointer to fit_pointer_t structure containing license
 *                             data. To access the license data in different types of
 *                             memory (FLASH, E2, RAM), fit_pointer_t is used.
 *
 * @param IN    keys    \n  Pointer to array of key data. Also contains callback
 *                          to read key data in different types of memory(FLASH, E2, RAM).
 *
 * @param IN    check_cache \n FIT_TRUE if signing verification is already done; FIT_FALSE
 *                             otherwise.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_verify_license(fit_pointer_t *license,
                                fit_key_array_t *keys,
                                fit_boolean_t check_cache,/*lint !e715 */
                                fit_boolean_t check_prst)
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

    /* call internal verify license fn that will do actual api task */
    status = fit_internal_verify_license(license, keys, check_cache, check_prst);

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
 * \skip fit_get_license_part_data
 *
 * Extracts license Copies data from source to destination location.
 *
 * @param IN    license  \n Pointer to fit_pointer_t structure containing license
 *                         data. To access the license data in different types of
 *                         memory (FLASH, E2, RAM), fit_pointer_t is used.
 *
 * @param OUT   length   \n Destination pointer where to store license data length.
 *
 * @param OUT   data     \n Pointer to pointer to the license data.
 *
 */
fit_status_t fit_get_license_part_data(fit_pointer_t* license,uint32_t* length,uint8_t** data)
{
    fit_status_t status = FIT_STATUS_UNKNOWN_ERROR;
    uint16_t num_fields = 0;

    status = fit_read_word_safe(license->data + FIT_SIZEOF_LICENSE_HEADER,
        license->read_byte, license, &num_fields);
    if(status != FIT_STATUS_OK)
    {
        return status;
    }

    status = fit_read_dword_safe(license->data + FIT_SIZEOF_LICENSE_HEADER + ((num_fields*FIT_PFIELD_SIZE)+FIT_PFIELD_SIZE),
        license->read_byte, license, length);
    if(status != FIT_STATUS_OK)
    {
        return status;
    }

    *data = (uint8_t *)license->data + FIT_SIZEOF_LICENSE_HEADER +
        ((num_fields*FIT_PFIELD_SIZE)+FIT_PFIELD_SIZE+FIT_PARRAY_SIZE);

    return FIT_STATUS_OK;
}


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
int fit_memcpy(void *dst, size_t dstlen, void *src, size_t srclen)
{
    size_t cntr;
    size_t totlen = 0;
    uint8_t *d = dst;
    uint8_t *s = src;

    for (cntr = 0; cntr < srclen; ++cntr)
    {
        if (totlen++ > dstlen)
        {
            return 1;
        }
        *d++ = *s++;
    }

    return 0;
}

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
int32_t fit_fitptr_memcmp(fit_pointer_t *pdata1, uint8_t *pdata2, uint32_t len)/*lint !e818 */
{
    uint32_t cntr;
    uint8_t  tmp;

    for (cntr = 0; cntr < len; ++cntr)
    {
        tmp = pdata1->read_byte(pdata1->data + cntr);
        if (tmp == *pdata2++) {
            continue;
        }
        else
        {
            return (int32_t)(len - cntr);
        }
    }

    return 0;
}

/**
 *
 * \skip fit_utoa
 *
 * Converts unsigned integer value to string value.
 *
 * @param IN    intval  \n Unsigned Integer value to be converted into string
 *
 * @param IO    str     \n Pointer to buffer which will contains the string value of integer.
 *
 */
char* fit_utoa(uint64_t intval, char *str)
{
    int8_t const digit[] = "0123456789";
    char*        strptr  = str;
    uint64_t     shifter = intval;

    do
    {
        ++strptr;
        shifter = shifter/10;
    }
    while(shifter);

    *strptr = '\0';
    do
    {
        *--strptr = digit[intval%10];
        intval = intval/10;
    }
    while(intval);

    return str;
}

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
int fit_fitptr_memcpy(uint8_t *dst, uint16_t dstlen, fit_pointer_t *src)/*lint !e818 */
{
    uint16_t cntr;
    uint16_t totlen = 0;

    for (cntr = 0; cntr < src->length; ++cntr)
    {
        if (totlen++ > dstlen)
        {
            return 1;
        }
        *dst++ = src->read_byte(src->data + cntr);
    }

    return 0;
}

/**
 *
 * \skip fit_memcmp
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
#ifndef FIT_USE_SYSTEM_CALLS
int fit_memcmp(const uint8_t *pdata1, const uint8_t *pdata2, size_t len)
{
  const unsigned char *s1 = pdata1;
  const unsigned char *s2 = pdata2;

  while (len-- > 0)
    {
      if (*s1++ != *s2++)
	  return s1[-1] < s2[-1] ? -1 : 1;
    }
  return 0;
}

int fit_strcat(char *dst, unsigned int dstlen, const char *src)
{
    uint16_t totlen = 0;

    while (*dst != '\0')
    {
        dst++;
        totlen++;
        if (totlen >= dstlen)
        {
            return 1;
        }
    }

    while (*src != '\0')
    {
        *dst++ = *src++;
        totlen++;
        if (totlen >= dstlen)
        {
            return 1;
        }
    }

    *dst++ = '\0';

    return 0;
}

#endif

/**
 *
 * \skip fit_memset
 *
 * Initialize data with value passed in.
 *
 * @param IN    pdata   \n Pointer to data to be initialize.
 *
 * @param IN    value   \n Value to assign to pdata.
 *
 * @param IN    len     \n Length of pdata to be initialized.
 *
 */
#ifndef FIT_USE_SYSTEM_CALLS
void *fit_memset(void *pdata, uint8_t value, unsigned int len)
{
    uint8_t *dest = pdata;
    while ((len--) != 0)
    {
        *dest++ = value;
    }
    return pdata;
}
#endif

/**
 *
 * \skip fit_sec_memcmp
 *
 * Compares data from two different memory address.
 * To prevent side channel attack, full memory buffer is compared.
 *
 * @param IN    pdata1  \n Pointer to data1 in RAM
 *
 * @param IN    pdata2  \n Pointer to data2 in RAM
 *
 * @param IN    len     \n Length of data to be compared.
 *
 * @return 0 if pdata1 and pdata2 are same; otherwise return difference.
 *
 */
int16_t 
fit_sec_memcmp(uint8_t* pdata1, uint8_t* pdata2, uint16_t len)/*lint !e818*/
{
    int16_t result = 0;

    while(len--)
    {
        result |= ((*pdata1++ - *pdata2++));        
    }

    return result;
}

/**
 *
 * \skip fitptr_sec_memcmp
 *
 * Compares data from two different memory address. 
 * To prevent side channel attack, full memory buffer is compared.
 *
 * @param IN    pdata1  \n Pointer to data1 in RAM/FLASH/E2 etc.
 *
 * @param IN    pdata2  \n Pointer to data2 in RAM
 *
 * @param IN    len     \n Length of data to be compared.
 *
 * @return 0 if pdata1 and pdata2 are same; otherwise return difference.
 *
 */
int16_t 
fit_fitptr_sec_memcmp(fit_pointer_t *pdata1, const uint8_t *pdata2, uint16_t len)
{        
    int16_t result = 0;

    while(len--)
    {
        result |= ((pdata1->read_byte(pdata1->data++) - *pdata2++));
    }

    return result;
}

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
fit_status_t fit_licenf_init(void)
{
    fit_status_t status = FIT_STATUS_INTERNAL_ERROR;

#ifdef FIT_USE_MULTI_THREAD
    fit_boolean_t mtx = FIT_FALSE;

    /* Create a new mutex lock for safe multithreading operations. */
    if (FIT_MUTEX_CREATE(&fit_init_mutex) != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_ERROR, "Failed to create cache signature verification mutex\n");
        return FIT_STATUS_UNINITIALIZED_MUTEX_ERROR;
    }
    else
    {
        mtx = FIT_MUTEX_LOCK(&fit_init_mutex);
        if (mtx != FIT_TRUE)
        {
            FIT_MUTEX_DESTROY(&fit_init_mutex);
            return FIT_STATUS_LOCK_MUTEX_ERROR;
        }
    }

    if (FIT_MUTEX_CREATE(&fit_mutex) != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_ERROR, "Failed to create cache signature verification mutex\n");
        return FIT_STATUS_UNINITIALIZED_MUTEX_ERROR;
    }

#endif // #ifdef FIT_USE_MULTI_THREAD

    if (!g_fit_init)
    {
#ifdef FIT_USE_PERSISTENT
        status = fit_prst_init();
        if (status != FIT_STATUS_OK)
        {
#ifdef FIT_USE_MULTI_THREAD
            (void)FIT_MUTEX_UNLOCK(&fit_init_mutex);
            FIT_MUTEX_DESTROY(&fit_init_mutex);
#endif // #ifdef FIT_USE_MULTI_THREAD
            return status;
        }
#endif // #ifdef FIT_USE_PERSISTENT

        g_fit_init = FIT_TRUE;
        status = FIT_STATUS_OK;
    }
    else
    {
        status = FIT_STATUS_OK;
    }

#ifdef FIT_USE_MULTI_THREAD
    (void)FIT_MUTEX_UNLOCK(&fit_init_mutex);
#endif

    return status;
}

/**
 *
 * \skip fit_check_init_status
 *
 * This function will check if fit_licenf_init was called and if not return
 * FIT_STATUS_NOT_INITIALIZED else FIT_STATUS_OK
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_check_init_status(void)
{
#ifdef FIT_USE_MULTI_THREAD
    fit_boolean_t mtx = FIT_FALSE;
#endif // #ifdef FIT_USE_MULTI_THREAD

#ifdef FIT_USE_MULTI_THREAD
    mtx = FIT_MUTEX_LOCK(&fit_init_mutex);
    if (mtx != FIT_TRUE)
    {
        return FIT_STATUS_LOCK_MUTEX_ERROR;
    }
#endif // #ifdef FIT_USE_MULTI_THREAD
    if (g_fit_init != FIT_TRUE)
    {
#ifdef FIT_USE_MULTI_THREAD
        (void)FIT_MUTEX_UNLOCK(&fit_init_mutex);
#endif // #ifdef FIT_USE_MULTI_THREAD
        return FIT_STATUS_NOT_INITIALIZED;
    }
#ifdef FIT_USE_MULTI_THREAD
    mtx = FIT_MUTEX_UNLOCK(&fit_init_mutex);
    if (mtx != FIT_TRUE)
    {
        return FIT_STATUS_UNLOCK_MUTEX_ERROR;
    }
#endif // #ifdef FIT_USE_MULTI_THREAD

    return FIT_STATUS_OK;
}
