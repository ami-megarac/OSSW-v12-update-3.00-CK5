/****************************************************************************\
**
** fit_parser.c
**
** Defines functionality for parsing licenses for embedded devices.
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

#include <string.h> 

#include "fit_internal.h"
#include "fit_parser.h"
#include "fit_hwdep.h"
#include "fit_debug.h"
#include "fit_consume.h"
#include "fit_mem_read.h"
#include "fit_version.h"
#include "fit_aes.h"
#include "fit_rsa.h"
#include "fit_alloc.h"

#ifdef FIT_USE_UNIT_TESTS
#include "unittest/fit_test_parser.h"
#endif /* #ifdef FIT_USE_UNIT_TESTS */

/* Forward Declarations *****************************************************/

/*
 * This function will be used to get address for passed in tag
 * identifier. Each field of license binary is assigned a unique tagid
 */
static fit_status_t fit_get_data_address(fit_pointer_t *pdata,
                                         fit_tag_id_t tagid,
                                         uint32_t length,
                                         void *opdata,
                                         fit_pointer_t *license);

/* This function will fetch the next license object (can be integer, string, object or array)
 * from the level/depth contained in fit_lic_scope_t structure and also fetch the
 * corresponding sproto element from the sproto tree for further processing.
 */
static fit_status_t fit_get_next_lic_element(uint8_t **pdata,
                                             uint32_t *objlen,
                                             SP_NODE **obj_node,
                                             fit_read_byte_callback_t my_read_byte,
                                             fit_lic_scope_t *lic_scope_item,
                                             fit_lic_scope_t *lic_scope_ref,
                                             fit_pointer_t *license,
                                             uint32_t flags,
	                                         fit_information_codes_t *parser_status);

/* This function will add an license element (either object or array) and corresponding
 * sproto information in the lic_path_t structure.
 */
static fit_status_t fit_add_lic_elem_in_lic_path(uint8_t *pdata,
                                                 uint32_t datalen,
                                                 fit_wire_type_t objtype,
                                                 SP_CHILD *child_node,
                                                 fit_read_byte_callback_t my_read_byte,
                                                 fit_lic_scope_t *lic_path,
                                                 fit_pointer_t *license);

/* This function will call the callback function register for each operation type.*/
static fit_status_t parsercallbacks(fit_tag_id_t tagid,
                                    fit_pointer_t *pdata,
                                    uint32_t length,
                                    void *opdata,
                                    fit_pointer_t *license);

#ifdef FIT_USE_UNIT_TESTS
/* This function will call the callback function register against tagid. */
static fit_status_t fieldcallbackfn(fit_tag_id_t tagid,
                                    fit_pointer_t *pdata,
                                    void *opdata);
#endif /* #ifdef FIT_USE_UNIT_TESTS */

/* Global Data **************************************************************/

/* Callback function registered against each fit based operation.*/
static struct fit_parse_callbacks fct[] = {{FIT_OP_NONE, NULL},
                                    {FIT_OP_GET_DATA_ADDRESS,(fit_parse_callback) fit_get_data_address}
};


#ifdef FIT_USE_UNIT_TESTS
/*
 * Callback function registered against each tag identifier. Each elemengt of license
 * binary is assigned a unique tagid.
 */
static struct fit_testcallbacks testfct[] =
   {{FIT_LIC_CONTAINER_ARRAY_TAG_ID,
        FIT_OP_TEST_LIC_CONTAINER_DATA,
        (fit_test_field_callback)fit_test_lic_container_data},

    {FIT_HEADER_TAG_ID,
        FIT_OP_TEST_LIC_HEADER_DATA,
        (fit_test_field_callback)fit_test_header_data},

    {FIT_VENDOR_ARRAY_TAG_ID,
        FIT_OP_TEST_VENDOR_DATA,
        (fit_test_field_callback)fit_test_vendor_data},

    {FIT_PRODUCT_ARRAY_TAG_ID,
        FIT_OP_TEST_LIC_PRODUCT_DATA,
        (fit_test_field_callback)fit_test_lic_product_data},

    {FIT_PRODUCT_PART_ARRAY_TAG_ID,
        FIT_OP_TEST_LIC_PROPERTY_DATA,
        (fit_test_field_callback)fit_test_lic_property_data},

    {FIT_FEATURE_ARRAY_TAG_ID,
        FIT_OP_TEST_FEATURE_DATA,
        (fit_test_field_callback)fit_test_feature_info}};

#endif /* #ifdef FIT_USE_UNIT_TESTS */

/* Constants ****************************************************************/

/* Sproto objects tree parser table implementation. Each object of sproto table
 * is identified via tag id and also associated with wiretype (integer, string,
 * boolean, object, array) 
 */

static const SP_NODE integer_NODE[] = {{(fit_tag_id_t)FIT_INTEGER,NULL}};
static const SP_CHILD sp_integer    = {sizeof(integer_NODE)/sizeof(SP_NODE),integer_NODE};
static const SP_NODE string_NODE[]  = {{(fit_tag_id_t)FIT_STRING,NULL}};
static const SP_CHILD sp_string     = {sizeof(string_NODE)/sizeof(SP_NODE),string_NODE};
static const SP_NODE boolean_NODE[] = {{(fit_tag_id_t)FIT_BOOLEAN,NULL}};
static const SP_CHILD sp_boolean    = {sizeof(boolean_NODE)/sizeof(SP_NODE),boolean_NODE};
static const SP_NODE binary_NODE[]  = {{(fit_tag_id_t)FIT_BINARY,NULL}};
static const SP_CHILD sp_binary     = {sizeof(binary_NODE)/sizeof(SP_NODE),binary_NODE};
/* Concurrency object data */
static const SP_NODE concurrency_NODE[]     = {{FIT_CONCURRENCY_LIMIT_ID,&sp_integer},{FIT_CONCURRENCY_SOFT_LIMIT_ID,&sp_integer},
                                              {FIT_CONCURRENCY_BORROWABLE_ID,&sp_boolean},{FIT_CONCURRENCY_BORROW_LIMIT_ID,&sp_integer},
                                              {FIT_CONCURRENCY_BORROW_PERIOD_ID,&sp_string}};
static const SP_CHILD concurrency           = {sizeof(concurrency_NODE)/sizeof(SP_NODE),concurrency_NODE};

/* Counter object data */
static const SP_NODE counter_NODE[] = {{FIT_COUNTER_ID_TAG_ID,&sp_integer},{FIT_COUNTER_LIMIT_TAG_ID,&sp_integer},
                                       {FIT_COUNTER_SOFT_LIMIT_TAG_ID,&sp_integer},{FIT_COUNTER_IS_FIELD_TAG_ID,&sp_integer},
                                       {FIT_COUNTER_NAME_TAG_ID,&sp_string}};
static const SP_CHILD counter       = {sizeof(counter_NODE)/sizeof(SP_NODE),counter_NODE};
static const SP_NODE counters_NODE[]= {{FIT_COUNTER_TAG_ID,&counter}};
static const SP_CHILD counters      = {sizeof(counters_NODE)/sizeof(SP_NODE),counters_NODE};

/* Product Custom attribute object data */
static const SP_NODE prod_custom_attr_NODE[]     = {{FIT_PROD_CUSTOM_ATTR_KEY_TAG_ID,&sp_string},{FIT_PROD_CUSTOM_ATTR_KEY_VALUE_TAG_ID,&sp_string}};
static const SP_CHILD prod_custom_attr           = {sizeof(prod_custom_attr_NODE)/sizeof(SP_NODE),prod_custom_attr_NODE};
static const SP_NODE prod_custom_attrs_NODE[]    = {{FIT_PROD_CUSTOM_ATTR_TAG_ID,&prod_custom_attr}};
static const SP_CHILD prod_custom_attrs          = {sizeof(prod_custom_attrs_NODE)/sizeof(SP_NODE),prod_custom_attrs_NODE};
/* Feature Custom attribute object data */
static const SP_NODE custom_attr_NODE[]     = {{FIT_CUSTOM_ATTR_KEY_TAG_ID,&sp_string},{FIT_CUSTOM_ATTR_KEY_VALUE_TAG_ID,&sp_string}};
static const SP_CHILD custom_attr           = {sizeof(custom_attr_NODE)/sizeof(SP_NODE),custom_attr_NODE};
static const SP_NODE custom_attrs_NODE[]    = {{FIT_CUSTOM_ATTR_TAG_ID,&custom_attr}};
static const SP_CHILD custom_attrs          = {sizeof(custom_attrs_NODE)/sizeof(SP_NODE),custom_attrs_NODE};

/* Feature object data */
static const SP_NODE feature_NODE[]     =  {{FIT_FEATURE_ID_TAG_ID,&sp_integer},{FIT_FEATURE_NAME_TAG_ID,&sp_string},
                                            {FIT_CUSTOM_ATTR_ARRAY_TAG_ID,&custom_attrs}};
static const SP_CHILD feature           = {sizeof(feature_NODE)/sizeof(SP_NODE),feature_NODE};
static const SP_NODE features_NODE[]    = {{FIT_FEATURE_TAG_ID,&feature}};
static const SP_CHILD features          = {sizeof(features_NODE)/sizeof(SP_NODE),features_NODE};

/* License Property object data */
static const SP_NODE licprop_NODE[]     = {{FIT_FEATURE_ARRAY_TAG_ID,&features},{FIT_PERPETUAL_TAG_ID,&sp_boolean},
                                           {FIT_START_DATE_TAG_ID,&sp_integer},{FIT_END_DATE_TAG_ID,&sp_integer},
                                           {FIT_COUNTER_ARRAY_TAG_ID,&counters},{FIT_DUR_FROM_FIRST_USE_TAG_ID,&sp_integer},
                                           {FIT_DUR_START_DATE_TAG_ID,&sp_integer},{FIT_CONCURRENCY_TAG_ID,&concurrency}};
static const SP_CHILD licenseproperties = {sizeof(licprop_NODE)/sizeof(SP_NODE),licprop_NODE};

/* System attribute object data */
static const SP_NODE system_attr_NODE[]     = {{FIT_SYSTEM_ATTR_KEY_TAG_ID,&sp_string},{FIT_SYSTEM_ATTR_KEY_VALUE_TAG_ID,&sp_string}};
static const SP_CHILD system_attr           = {sizeof(system_attr_NODE)/sizeof(SP_NODE),system_attr_NODE};
static const SP_NODE system_attrs_NODE[]    = {{FIT_SYSTEM_ATTR_TAG_ID,&system_attr}};
static const SP_CHILD system_attrs          = {sizeof(system_attrs_NODE)/sizeof(SP_NODE),system_attrs_NODE};

/* Product part object data */
static const SP_NODE productpart_NODE[]    = {{FIT_PRODUCT_PART_ID_TAG_ID,&sp_integer},
                                               {FIT_LIC_PROP_TAG_ID,&licenseproperties},
                                               {FIT_PRODUCT_PART_NAME_TAG_ID,&sp_string}};
static const SP_CHILD productpart           = {sizeof(productpart_NODE)/sizeof(SP_NODE),productpart_NODE};
static const SP_NODE productparts_NODE[]    = {{FIT_PRODUCT_PART_TAG_ID,&productpart}};
static const SP_CHILD productparts          = {sizeof(productparts_NODE)/sizeof(SP_NODE),productparts_NODE};
/* Product object data */
static const SP_NODE product_NODE[]     = {{FIT_PRODUCT_ID_TAG_ID,&sp_integer},{FIT_PRODUCT_VER_REGEX_TAG_ID,&sp_string},
                                           {FIT_PRODUCT_PART_ARRAY_TAG_ID,&productparts},
                                           {FIT_PRODUCT_NAME_TAG_ID,&sp_string},
                                           {FIT_PROD_CUSTOM_ATTR_ARRAY_TAG_ID,&prod_custom_attrs},
                                           {FIT_SYSTEM_ATTR_ARRAY_TAG_ID,&system_attrs}};
static const SP_CHILD product           = {sizeof(product_NODE)/sizeof(SP_NODE),product_NODE};
static const SP_NODE products_NODE[]    = {{FIT_PRODUCT_TAG_ID,&product}};
static const SP_CHILD products          = {sizeof(products_NODE)/sizeof(SP_NODE),products_NODE};
/* Vendor object data */
static const SP_NODE vendor_NODE[]      = {{FIT_VENDOR_ID_TAG_ID,&sp_integer},{FIT_PRODUCT_ARRAY_TAG_ID,&products},
                                           {FIT_VENDOR_NAME_TAG_ID,&sp_string}};
static const SP_CHILD vendor            = {sizeof(vendor_NODE)/sizeof(SP_NODE),vendor_NODE};
static const SP_NODE vendors_NODE[]     = {{FIT_VENDOR_TAG_ID,&vendor}};
static const SP_CHILD vendors           ={sizeof(vendors_NODE)/sizeof(SP_NODE),vendors_NODE};

/*license generate sequense object data */
static const SP_NODE licgen_seq_NODE[]  = {{FIT_LICGEN_SEQ_UID_TAG_ID,&sp_integer},{FIT_LICGEN_SEQ_TXUID_TAG_ID,&sp_integer},
                                           {FIT_LICGEN_SEQ_TXUPT_CNT_TAG_ID,&sp_integer}};
static const SP_CHILD licgen_seq = {sizeof(licgen_seq_NODE)/sizeof(SP_NODE),licgen_seq_NODE};

/* License Container object data */
static const SP_NODE lic_cont_NODE[]        = {{FIT_ID_LC_TAG_ID,&sp_integer},{FIT_VENDOR_ARRAY_TAG_ID,&vendors},
                                               {FIT_LIC_CONT_NAME_TAG_ID,&sp_string},{FIT_LIC_CONT_UUID_TAG_ID,&sp_binary},
                                               {FIT_UPDATE_COUNTER_TAG_ID,&sp_integer},{FIT_LICGEN_SEQ_TAG_ID,&licgen_seq}};
static const SP_CHILD lic_cont              = {sizeof(lic_cont_NODE)/sizeof(SP_NODE),lic_cont_NODE};
static const SP_NODE lic_containers_NODE[]  = {{FIT_LIC_CONTAINER_TAG_ID,&lic_cont}};
static const SP_CHILD lic_containers        = {sizeof(lic_containers_NODE)/sizeof(SP_NODE),lic_containers_NODE};

/* Header object data */
static const SP_NODE header_NODE[]  = {{FIT_LICGEN_VERSION_TAG_ID,&sp_integer},{FIT_LM_VERSION_TAG_ID,&sp_integer},
                                       {FIT_UID_TAG_ID,&sp_string},{FIT_FP_TAG_ID,&sp_string},{FIT_REQUIREMENTS_TAG_ID,&sp_binary}};
static const SP_CHILD header        = {sizeof(header_NODE)/sizeof(SP_NODE),header_NODE};

static const SP_NODE licenses_NODE[] =  {{FIT_HEADER_TAG_ID,&header},{FIT_LIC_CONTAINER_ARRAY_TAG_ID,&lic_containers}};
static const SP_CHILD licenses = {sizeof(licenses_NODE)/sizeof(SP_NODE),licenses_NODE};

/* Signature object data */
static const SP_NODE signature_NODE[]= {{ FIT_ALGORITHM_ID_TAG_ID,&sp_integer},{FIT_SIGNATURE_STR_TAG_ID,&sp_string}};
static const SP_CHILD signature = {sizeof(signature_NODE)/sizeof(SP_NODE),signature_NODE};
static const SP_NODE signatures_NODE[]={{FIT_SIGNATURE_TAG_ID, &signature}};
static const SP_CHILD signatures = {sizeof(signatures_NODE)/sizeof(SP_NODE),signatures_NODE};
/* V2C object data */
static const SP_NODE v2c_NODE[] = {{FIT_LICENSE_TAG_ID,&licenses},{FIT_SIG_ARRAY_TAG_ID, &signatures}};
static const SP_CHILD v2c = {sizeof(v2c_NODE)/sizeof(SP_NODE),v2c_NODE};

/* Functions ****************************************************************/

/**
 *
 * fit_add_lic_elem_in_lic_path
 *
 * This function will add an license element (either object or array) and corresponding
 * sproto information in the lic_path_t structure.
 *
 * @param IN    pdata   \n Pointer to license object/array to be added in fit_lic_scope_t.
 *
 * @param IN    datalen \n Length of above object/array.
 *
 * @param IN    objtype \n Tell about wire type of object.
 *
 * @param IN    child_node   \n Pointer to sproto element corresponding to license object.
 *
 * @param IN    read_byte   \n Prototype of read "license" byte callback function
 *
 * @param IN    lic_path   \n Tree node path of license binary.
 *
 * @return FIT_STATUS_OK on success otherwise, returns appropriate error code.
 *
 */
static fit_status_t fit_add_lic_elem_in_lic_path(uint8_t *pdata,
                                                 uint32_t datalen,
                                                 fit_wire_type_t objtype,
                                                 SP_CHILD *child_node,
                                                 fit_read_byte_callback_t my_read_byte,
                                                 fit_lic_scope_t *lic_path,
                                                 fit_pointer_t *license)/*lint !e818*/
{
    /* For every license object, first field represents number of elements in license
     * object
     */
    uint16_t num_fields                 = 0;
    fit_lic_parser_state_t *lic_node    = lic_path->node;
    fit_status_t status                 = FIT_STATUS_UNKNOWN_ERROR;

    /* Get to next level/depth into the lic_path_t. */
    lic_path->depth++;
    if (lic_path->depth > FIT_MAX_LEVEL)
    {
        return FIT_STATUS_MAX_LEVEL_EXCEEDS;
    }

    /* Initialize the data with all zeros at current level */
    (void)memset(&lic_node[lic_path->depth], 0, (size_t)sizeof(fit_lic_parser_state_t));

    /* Initialize the lic_path_t structure for addin level/depth with the passed in 
     * data. This also contains the wire type (i.e. object or an array) corresponding
     * to license object.
     */
    lic_node[lic_path->depth].sproto_obj_cntr = 0;
    lic_node[lic_path->depth].child_nodes = (SP_CHILD *)child_node;

    lic_node[lic_path->depth].data = pdata;
    lic_node[lic_path->depth].objtype = objtype;
    lic_node[lic_path->depth].datalen = datalen;
    lic_node[lic_path->depth].node.obj.not_first_element = FIT_FALSE;
    
    status = fit_read_word_safe(pdata, my_read_byte, license, &num_fields);
    if(status != FIT_STATUS_OK)
    {
        return status;
    }

    if (objtype == FIT_OBJECT)
    {
        lic_node[lic_path->depth].node.obj.cur_obj = 0;
        lic_node[lic_path->depth].node.obj.not_first_element = FIT_FALSE;
        lic_node[lic_path->depth].node.obj.obj_data_offset  = (num_fields+1)*FIT_PFIELD_SIZE;
        if (lic_node[lic_path->depth].node.obj.obj_data_offset > datalen)
        {
            return FIT_STATUS_INVALID_V2C;
        }
    }

    if (objtype == FIT_ARRAY)
    {
        /* Get the total size of array in bytes.*/
        status = fit_read_dword_safe(pdata, my_read_byte, license, 
            &lic_node[lic_path->depth].node.arr.array_size);
        if(status != FIT_STATUS_OK)
        {
            return status;
        }

        /* Parsed size */
        lic_node[lic_path->depth].node.arr.parsed_array_size = 0;
    }

    return FIT_STATUS_OK;
}

/**
 *
 * fit_get_next_lic_element
 *
 * This function will fetch the next license object (can be integer, string, object or array)
 * from the level/depth contained in fit_lic_scope_t structure and also fetch the
 * corresponding sproto element from the sproto tree for further processing.
 *
 * @param OUT   pdata   \n  On rturn will contain the pointer to next license object
 *
 * @param OUT   objlen \n   Will return the length object in case of type of object
 *                          is integer or string.
 *
 * @param OUT   obj_node \n Will contain the sproto element corresponding to license
 *                          element.
 *
 * @param IN    read_byte   \n Prototype of read "license" byte callback function
 *
 * @param IO    lic_scope_item   \n Tree node path of license binary. This will be
 *                                 updated as we traverse along with license binary
 *
 * @param IN    lic_scope_ref   \n reference path for element to be searched.
 *
 * @return FIT_STATUS_OK on success otherwise, returns appropriate error code.
 *
 */
static fit_status_t fit_get_next_lic_element(uint8_t **pdata,
                                             uint32_t *objlen,
                                             SP_NODE **obj_node,
                                             fit_read_byte_callback_t my_read_byte,
                                             fit_lic_scope_t *lic_scope_item,
                                             fit_lic_scope_t *lic_scope_ref,
                                             fit_pointer_t *license,/*lint !e818*/
                                             uint32_t flags,
	                                         fit_information_codes_t* parser_status
	                                         )
{
    fit_lic_parser_state_t *temp    = NULL;
    fit_lic_parser_state_t *refnode = NULL;
    uint8_t *curelem                = NULL;
    uint16_t field_data             = 0;
    fit_status_t status             = FIT_STATUS_UNKNOWN_ERROR;
    fit_boolean_t list              = FIT_TRUE;
    /*
     * skip_fields represents number of fields to skip or number of fields that
     * does not have any data in license binary.
     */
    uint8_t skip_fields     = 1;
    /* For every license object, first field represents number of elements in license object.*/
    uint16_t num_fields      = 0;
    uint8_t cntr            = 0;
    uint32_t objectlen      = 0;

	*parser_status = FIT_INFO_CONTINUE_PARSE;

    if (lic_scope_item->depth > FIT_MAX_LEVEL)
    {
        DBG(FIT_TRACE_ERROR,"Table containing license state information overruns. \n");
        return FIT_STATUS_MAX_LEVEL_EXCEEDS;
    }

start:
    if (lic_scope_item->depth == 0xFF)
    {
        /* No more license object in table */
		*parser_status = FIT_INFO_SPROTO_TABLE_EMPTY;
        return FIT_STATUS_OK;
    }

    /* Get the license object(last one) from table */
    temp = &(lic_scope_item->node[lic_scope_item->depth]);

    /* Find the next element/object in license binary at current level and for same in sproto tree */
    if (temp->objtype == FIT_OBJECT)
    {
        if (temp->node.obj.not_first_element)
        {
            /* Get the field data value of previous element in the object. */
            status = fit_read_word_safe(temp->data+FIT_PFIELD_SIZE+(temp->node.obj.cur_obj*FIT_PFIELD_SIZE),
                my_read_byte, license, &field_data);
            if(status != FIT_STATUS_OK)
            {
                return status;
            }

            if( field_data == 0ul )
            {
                /* Get the length of previous object */
                status = fit_read_dword_safe(temp->data+temp->node.obj.obj_data_offset, my_read_byte,
                    license, &objectlen);
                if(status != FIT_STATUS_OK)
                {
                    return status;
                }

                temp->node.obj.obj_data_offset = (temp->node.obj.obj_data_offset +
                                        objectlen +
                                        sizeof(uint32_t));
            }
            /* Move pointer of current object to next field.*/
            temp->node.obj.cur_obj++;
            temp->sproto_obj_cntr += temp->node.obj.skip_elements;
        }
    }

    while (list)
    {
        if (temp->data == NULL)
        {
            return FIT_STATUS_INVALID_V2C;
        }
        
        status = fit_read_word_safe(temp->data, my_read_byte, license, &num_fields);
        if(status != FIT_STATUS_OK)
        {
            return status;
        }

        if (temp->objtype == FIT_OBJECT)
        {
            /* First check if all members of objects are parsed. If yes then delete the
             * object and go to the parent object 
             */
            if (temp->node.obj.cur_obj >= num_fields)
            {
                /* Update corresponding sproto table */
                (void)fit_memset(temp, 0, (size_t)sizeof(fit_lic_parser_state_t));
                lic_scope_item->depth--;
				//use goto for footprint optimization
				goto start; //lint !e801 
            }
            else
            {
                list = FIT_FALSE;
            }
        }
        else if (temp->objtype == FIT_ARRAY)
        {
            /* If this is last object of the array then remove the array object from table */
            if(temp->node.arr.array_size == temp->node.arr.parsed_array_size)
            {
                /* Update the corresponding sproto table */
                lic_scope_item->depth--;
				//use goto for footprint optimization
				goto start; //lint !e801 
            }
            else
            {
                list = FIT_FALSE;
            }
        }
    }

    /* license parser will reach here only if
     * 1 - search scope is global
     * 2 - scope is limited to lic_scope_ref and did not reach till its depth
     * 3 - scope is limited to lic_scope_ref and parsing of sibling is going on
     */
    if (temp->objtype == FIT_OBJECT)
    {
        /* Get current field data for each license object.
         * Each field in field part is a 16bit integer  Value of this field will
         * tell what type of data it contains.
         */
        status = fit_read_word_safe(temp->data+FIT_PFIELD_SIZE+(temp->node.obj.cur_obj*FIT_PFIELD_SIZE), 
            my_read_byte, license, &field_data);
        if(status != FIT_STATUS_OK)
        {
            return status;
        }

        /*
         * If value of field_data is odd, that means the some fields does not have any data
         * in license object i.e. we need to skip struct member fields by (field_data+1)/2 .
         */
        if( field_data & 1)
        {
            /* No. of fields to skip */
            skip_fields += (uint8_t)(field_data+1)/2;
            if (skip_fields > temp->datalen)
            {
                return FIT_STATUS_INVALID_V2C;
            }

            /* Increment the object count by 1 */
            temp->node.obj.cur_obj++;

            /* Get the field data value of next element in the object. */
            status = fit_read_word_safe(temp->data+FIT_PFIELD_SIZE+(temp->node.obj.cur_obj*FIT_PFIELD_SIZE),
                my_read_byte, license, &field_data);
            if(status != FIT_STATUS_OK)
            {
                return status;
            }
        }

        /*
         * If field_data is zero, that means the field data is encoded in data part.
         * This field data can be in form of string or array or an object itself.
         */
        if( field_data == 0ul )
        {
            /* Get to the data pointer of current object  */
            *pdata = temp->data + temp->node.obj.obj_data_offset;
            /* Get the length of current object */
            status = fit_read_dword_safe(temp->data+temp->node.obj.obj_data_offset, my_read_byte, license, objlen);
            if(status != FIT_STATUS_OK)
            {
                return status;
            }
        }
        /*
         * if field_data is even (and not zero), then the field contains integer
         * value and the value of this field is field_data/2-1 
         */
        else if(field_data%2 == 0)
        {
            /* Get to the data pointer of current object  */
            *pdata = temp->data+FIT_PFIELD_SIZE+(temp->node.obj.cur_obj*FIT_PFIELD_SIZE);
            *objlen = FIT_PFIELD_SIZE;
        }
        else
        {
            /* Wrong data.*/
            DBG(FIT_TRACE_CRITICAL, "[fit_get_next_lic_element]: Invalid license data. \n");
            return FIT_STATUS_INVALID_V2C;
        }

        if (*objlen > temp->datalen)
        {
            return FIT_STATUS_INVALID_V2C;
        }

        if ((temp->sproto_obj_cntr+skip_fields-1) >= temp->child_nodes->number)
        {
            status = FIT_STATUS_SKIP_ELEMENT_DATA;
        }
        else
        {
            /* Get the wire type(data field) corresponding to above license object. */
            *obj_node = (SP_NODE*)&(temp->child_nodes->nodes[temp->sproto_obj_cntr+skip_fields-1]);
            status = FIT_STATUS_OK;
        }

        temp->node.obj.not_first_element = FIT_TRUE;
        temp->node.obj.skip_elements = skip_fields;
    }
    else if (temp->objtype == FIT_ARRAY)
    {
        /* get data from refernce node */
        if ((lic_scope_ref != FIT_LICENF_LICENSE_SCOPE_GLOBAL) &&
            (lic_scope_item->ref_path_done != FIT_TRUE)&&
            ((flags & FIT_FIND_ITEM_FIRST) == FIT_FIND_ITEM_FIRST) &&
            ((lic_scope_item->node[lic_scope_item->depth]).child_nodes == 
            (lic_scope_ref->node[lic_scope_item->depth]).child_nodes))
        {
            /* Get the reference array data (that belongs to ref path) at active depth */
            if (fit_memcpy(&(lic_scope_item->node[lic_scope_item->depth]), sizeof(fit_lic_parser_state_t),
                &(lic_scope_ref->node[lic_scope_item->depth]), sizeof(fit_lic_parser_state_t)) != 0)
            {
                return FIT_STATUS_BUFFER_OVERRUN;
            }

            refnode = &(lic_scope_item->node[lic_scope_item->depth]);
            refnode->node.arr.parsed_array_size = refnode->node.arr.array_size;
            *pdata = refnode->data;
            *objlen = refnode->datalen;
        }
        /* stop parsing if reference path depth is reached and we are going backward */
        else if ((lic_scope_ref != FIT_LICENF_LICENSE_SCOPE_GLOBAL) &&
            (flags == FIT_FIND_ITEM_NEXT) &&
            (lic_scope_item->ref_path_done == FIT_TRUE) && 
            (lic_scope_item->depth < lic_scope_ref->depth))
        {
			*parser_status = FIT_INFO_STOP_PARSE;
            return FIT_STATUS_OK;
        }
        else
        {
            uint32_t temp2 = 0;

            /** Get the next object in the array */
            if (temp->node.arr.parsed_array_size == 0)
            {
               curelem = temp->data + FIT_PARRAY_SIZE;
            }
            else
            {
                status = fit_read_dword_safe(temp->data, my_read_byte, license, &temp2);
                if(status != FIT_STATUS_OK)
                {
                    return status;
                }

                curelem = temp->data + FIT_PARRAY_SIZE + temp2;
            }

            /* Update the parsed size and pointer to current object in the array.*/

            status = fit_read_dword_safe(curelem, my_read_byte, license, &temp2);
            if(status != FIT_STATUS_OK)
            {
                return status;
            }

            temp->node.arr.parsed_array_size += FIT_POBJECT_SIZE + temp2;
            temp->data = curelem;
            *pdata = curelem;

            status = fit_read_dword_safe(curelem, my_read_byte, license, objlen);
            if(status != FIT_STATUS_OK)
            {
                return status;
            }
            
            if (*objlen > temp->datalen)
            {
                return FIT_STATUS_INVALID_V2C;
            }
        }

        /* Get the corresponding sproto object from table */
        *obj_node = (SP_NODE*)&(temp->child_nodes->nodes[0]);

        status = FIT_STATUS_OK;
    }
    else
    {
        return FIT_STATUS_INVALID_V2C;
    }

    /* if FIT_TRACE_LIC_PARSE flag is enabled then it would log data related to license parsing */
    if ((fit_trace_flags & FIT_TRACE_LIC_PARSE) == FIT_TRACE_LIC_PARSE)
    {
        for(cntr = 0; cntr <= lic_scope_item->depth; cntr++)
        {
            DBG(FIT_TRACE_LIC_PARSE, " ");
        }
    }

    return status;
}

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
                                          fit_license_t *license_t)
{
    fit_status_t status = FIT_STATUS_INTERNAL_ERROR;

    /* Validate Parameters */
    if (license == NULL )
    {
        return FIT_STATUS_INVALID_PARAM_1;
    }
    if (keys == NULL )
    {
        return FIT_STATUS_INVALID_PARAM_2;
    }
    if (license_t == NULL )
    {
        return FIT_STATUS_INVALID_PARAM_3;
    }

    /* check the init flag. fit_licenf_init should be called before use of any fit api */
    status = fit_check_init_status();
    if (status != FIT_STATUS_OK)
    {
        return status;
    }

    license_t->license = license;
    license_t->keys = keys;
    license_t->sig_verified_marker = 0;

    return status;
}

/**
 *
 * fit_check_license_validity
 *
 * This function will check the license validity. If the license string was not verified
 * then it would verify the license string.
 *
 * @param IN  license   \n  Pointer to fit_license_t structure containing license data
 *                          and keys to read data part. To access the license data in
 *                          different types of memory (FLASH, E2, RAM), fit_license_t is used.
 *
 */
fit_status_t fit_check_license_validity(fit_license_t *license, fit_boolean_t check_prst)
{
    fit_status_t status     = FIT_STATUS_OK;

    /* Verify the license string against signing key data present in keys array */
    if (license->sig_verified_marker != FIT_LIC_VERIFIED_MAGIC_NUM)
    {
        status = fit_internal_verify_license(license->license, license->keys, FIT_TRUE, check_prst);
        if (status != FIT_STATUS_OK)
        {
            return status;
        }
        license->sig_verified_marker = FIT_LIC_VERIFIED_MAGIC_NUM;
    }

    return status;
}

/**
 *
 * get_field_type_from_tagid
 *
 * This function will get the wire type corresponding to tagid.
 *
 * @param IN    tagid       \n Each license element is assigned a uniue tag indentifier.
 *
 * @param IN    sproto_type \n On return will contain the wire type corresponding to
 *                             tagid passed in.
 *
 */
void fit_get_field_type_from_tagid(fit_tag_id_t tagid, fit_wire_type_t *sproto_type)
{
	// unused values are not required in switch
    switch(tagid) //lint !e788
    {
        /* Represents license elements as objects. */
        case(FIT_V2C_TAG_ID):
        case(FIT_LICENSE_TAG_ID):
        case(FIT_HEADER_TAG_ID):
        case(FIT_LIC_CONTAINER_TAG_ID):
        case(FIT_VENDOR_TAG_ID):
        case(FIT_PRODUCT_TAG_ID):
        case(FIT_PRODUCT_PART_TAG_ID):
        case(FIT_LIC_PROP_TAG_ID):
        case(FIT_FEATURE_TAG_ID):
        case(FIT_COUNTER_TAG_ID):
        case(FIT_SIGNATURE_TAG_ID):
        case(FIT_CUSTOM_ATTR_TAG_ID):
        case(FIT_PROD_CUSTOM_ATTR_TAG_ID):
        case(FIT_CONCURRENCY_TAG_ID):
        case(FIT_LICGEN_SEQ_TAG_ID):
        case(FIT_SYSTEM_ATTR_TAG_ID):
            *sproto_type = FIT_OBJECT;
            break;

        /* Represents license elements as arrays. */
        case(FIT_LIC_CONTAINER_ARRAY_TAG_ID):
        case(FIT_VENDOR_ARRAY_TAG_ID):
        case(FIT_PRODUCT_ARRAY_TAG_ID):
        case(FIT_PRODUCT_PART_ARRAY_TAG_ID):
        case(FIT_FEATURE_ARRAY_TAG_ID):
        case(FIT_COUNTER_ARRAY_TAG_ID):
        case(FIT_SIG_ARRAY_TAG_ID):
        case(FIT_CUSTOM_ATTR_ARRAY_TAG_ID):
        case(FIT_PROD_CUSTOM_ATTR_ARRAY_TAG_ID):
        case(FIT_SYSTEM_ATTR_ARRAY_TAG_ID):
             *sproto_type = FIT_ARRAY;
            break;

        /* Represents license elements as integers. */
        case(FIT_ID_LC_TAG_ID):
        case(FIT_VENDOR_ID_TAG_ID):
        case(FIT_PRODUCT_ID_TAG_ID):
        case(FIT_PRODUCT_PART_ID_TAG_ID):
        case(FIT_START_DATE_TAG_ID):
        case(FIT_END_DATE_TAG_ID):
        case(FIT_LICGEN_VERSION_TAG_ID):
        case(FIT_LM_VERSION_TAG_ID):
        case(FIT_FEATURE_ID_TAG_ID):
        case(FIT_ALGORITHM_ID_TAG_ID):
        case(FIT_UPDATE_COUNTER_TAG_ID):
        case(FIT_CONCURRENCY_LIMIT_ID):
        case(FIT_CONCURRENCY_SOFT_LIMIT_ID):
        case(FIT_CONCURRENCY_BORROW_LIMIT_ID):
        case(FIT_DUR_FROM_FIRST_USE_TAG_ID):
        case(FIT_DUR_START_DATE_TAG_ID):
        case(FIT_COUNTER_ID_TAG_ID):
        case(FIT_COUNTER_LIMIT_TAG_ID):
        case(FIT_COUNTER_SOFT_LIMIT_TAG_ID):
        case(FIT_COUNTER_IS_FIELD_TAG_ID):
        case(FIT_LICGEN_SEQ_UID_TAG_ID):
        case(FIT_LICGEN_SEQ_TXUID_TAG_ID):
        case(FIT_LICGEN_SEQ_TXUPT_CNT_TAG_ID):
            *sproto_type = FIT_INTEGER;
            break;

        /* Represents license elements as strings. */
        case(FIT_UID_TAG_ID):
        case(FIT_FP_TAG_ID):
        case(FIT_SIGNATURE_STR_TAG_ID):
        case(FIT_CONCURRENCY_BORROW_PERIOD_ID):
        case(FIT_CUSTOM_ATTR_KEY_TAG_ID):
        case(FIT_CUSTOM_ATTR_KEY_VALUE_TAG_ID):
        case(FIT_PROD_CUSTOM_ATTR_KEY_TAG_ID):
        case(FIT_PROD_CUSTOM_ATTR_KEY_VALUE_TAG_ID):
        case(FIT_PRODUCT_VER_REGEX_TAG_ID):
        case(FIT_SYSTEM_ATTR_KEY_TAG_ID):
        case (FIT_SYSTEM_ATTR_KEY_VALUE_TAG_ID):

        case(FIT_LIC_CONT_NAME_TAG_ID):
        case(FIT_VENDOR_NAME_TAG_ID):
        case(FIT_PRODUCT_NAME_TAG_ID):
        case(FIT_PRODUCT_PART_NAME_TAG_ID ):
        case(FIT_FEATURE_NAME_TAG_ID):
        case(FIT_COUNTER_NAME_TAG_ID):
            *sproto_type = FIT_STRING;
            break;

        case(FIT_CONCURRENCY_BORROWABLE_ID):
        case(FIT_PERPETUAL_TAG_ID):
            *sproto_type = FIT_BOOLEAN;
            break;

        case(FIT_LIC_CONT_UUID_TAG_ID):
        case(FIT_REQUIREMENTS_TAG_ID):
            *sproto_type = FIT_BINARY;
            break;

        default:
            *sproto_type = FIT_INVALID_VALUE;
            break;
    }
}

/**
 *
 * fit_license_parser
 *
 * This function will parse the license data passed to it and perform operations
 * as per data passed in fit_op_data_t strcuture
 *
 * @param IN    license     \n Pointer to fit_pointer_t structure containing license data.
 *                             To access the license data in different types of memory
 *                             (FLASH, E2, RAM), fit_pointer_t is used.
 *
 * @param IN    opdata      \n Pointer to fit operational data structure.
 *
 */
fit_status_t fit_license_parser(fit_pointer_t *license,
                                void *opdata)
{
    fit_status_t status         = FIT_STATUS_OK;
    fit_lic_scope_t lic_path     = {0};

    /* Initialize the variables */
    lic_path.depth = 0xFF;

    /* Parse the license string  */
    status = fit_license_parser_execute(license, NULL, &lic_path, FIT_FIND_ITEM_FIRST, opdata);

    return status;
}

/**
 *
 * fit_license_parser_execute
 *
 * fit_license_parser_execute will parse the license data passed to it.
 * This function will iterate all license elements (integer, string, objects/arrays)
 * in license data and calls appropriate routines/functions/callbacks to process or
 * consume license data.
 *
 * @param IN  \b  license   \n Pointer to fit_pointer_t structure containing license data.
 *                             To access the license data in different types of memory
 *                             (FLASH, E2, RAM), fit_pointer_t is used.
 *
 * @param IO  \b  lic_scope_ref \n If FIT_LICENF_LICENSE_SCOPE_GLOBAL(null) search
 *                                 for an item is global otherwise search is limited
 *                                 to the related tree branches specified in lic_scope_ref.
 *
 * @param IO  \b  lic_scope_item    \n Tree node path of particular license element
 *
 * @param IO  \b  opdata    \n Pointer to fit operational data structure.
 *
 * @return FIT_STATUS_OK on success otherwise, returns appropriate error code.
 *
 */
fit_status_t fit_license_parser_execute(fit_pointer_t *license,
                                        fit_lic_scope_t *lic_scope_ref,
                                        fit_lic_scope_t *lic_scope_item,
                                        uint32_t flags,
                                        void *opdata)
{
    /* Contains success or error code.*/
    fit_status_t status         = FIT_STATUS_OK;
    fit_pointer_t fitlicobjptr  = {0};
    fit_wire_type_t type        = FIT_INVALID_VALUE;
    uint32_t objlen             = 0;
    uint32_t field_len          = 0;
    uint16_t integer            = 0;
    SP_NODE *obj_node           = NULL;
    uint32_t templen            = 0;
    fit_pointer_t pdata         = {0};
    fit_op_data_t *popdata    = (fit_op_data_t *)opdata;
	fit_information_codes_t parser_status = FIT_INFO_CONTINUE_PARSE;
    uint16_t temp               = 0;

    DBG(FIT_TRACE_INFO, "[fit_license_parser_execute start]: pdata=0x%X \n", pdata.data);

    /* rest of parser code is interested in sproto license only so we skip the header */
    pdata.data = license->data + FIT_SIZEOF_LICENSE_HEADER;
    pdata.length = license->length - FIT_SIZEOF_LICENSE_HEADER;
    pdata.read_byte = license->read_byte;

    /* Check for minimum license length required */
    if (license->length < FIT_SIZEOF_LICENSE_HEADER )
    {
        return FIT_STATUS_INVALID_V2C;
    }

    /* check if required core version is ok */
    status = fit_check_license_version(license);
    if( status != FIT_STATUS_OK)
    {
        return status;
    }

    /* Make sure first two bytes of license data (after header) are not corrupted */
    status = fit_read_word_safe(pdata.data, pdata.read_byte, license, &temp);
    if(status != FIT_STATUS_OK)
    {
        return status;
    }

    if (temp > FIT_MAX_FIELDS_IN_SPROTO_OBJ)
    {
        return FIT_STATUS_INVALID_V2C;
    }

    /* Get length of license/data pointed by pdata */
    status = fit_get_object_len(&pdata, &objlen, license);
    if (status != FIT_STATUS_OK || pdata.length != objlen)
    {
        return FIT_STATUS_INVALID_V2C;
    }

    fitlicobjptr.length = 0;
    fitlicobjptr.read_byte = pdata.read_byte;

    if (lic_scope_item->depth == 0xFF)
    {
        /* Initialize the arrays(table) of license objects */
        status = fit_add_lic_elem_in_lic_path(pdata.data, objlen, FIT_OBJECT,
            (SP_CHILD *)&v2c, pdata.read_byte, lic_scope_item, license);
        if (status != FIT_STATUS_OK)
        {
            return status;
        }
    }

    /* Iterate until no more license elements in lic_path_t structure */
    while(lic_scope_item->depth < FIT_MAX_LEVEL)
    {
        /* If there is any error then stop further parsing and return the error.
         * Check parserstatus value in fit opertaional data. If this is set to 
         * FIT_INFO_STOP_PARSE then stop further parsing of license string 
         */
        if (status != FIT_STATUS_OK || popdata->parserstatus == FIT_INFO_STOP_PARSE)
        {
            break;
        }
        /* Get license object from the array and then parse its elements */
        status = fit_get_next_lic_element(&fitlicobjptr.data, &objlen,
            &obj_node, fitlicobjptr.read_byte, lic_scope_item, lic_scope_ref, license, flags,&parser_status);

        if (status == FIT_STATUS_OK && parser_status == FIT_INFO_SPROTO_TABLE_EMPTY)
        {
            status = FIT_STATUS_OK;
            break;
        }
        else if (status == (fit_status_t)FIT_STATUS_SKIP_ELEMENT_DATA)
        {
            status = FIT_STATUS_OK;
            continue;
        }
        if (status != FIT_STATUS_OK)
        {
            break;
        }

        /* Get the wire type (data type) from the tag id. */
        if (obj_node) {
            fit_get_field_type_from_tagid(obj_node->tagid, &type);
        } else {
            break;
        }

        switch(type)
        {
            case(FIT_OBJECT):
            case(FIT_ARRAY):
            {
                status = fit_read_dword_safe(fitlicobjptr.data, fitlicobjptr.read_byte,
                    license, &templen);
                if(status != FIT_STATUS_OK)
                {
                    break;
                }

                if (templen > objlen)
                {
                    status = FIT_STATUS_INVALID_V2C;
                    break;
                }
#ifdef FIT_USE_UNIT_TESTS
                /*
                 * This code is used for unit tests. This will call the callback fn
                 * registered for tag identifier (tagid).
                 */
                if (popdata->testop == FIT_TRUE)
                {
                    status = fieldcallbackfn(obj_node->tagid, &fitlicobjptr, opdata);
                    /* If there is any error then stop further parsing and return the error.*/
                    if (status != FIT_STATUS_OK)
                        break;
                    /*
                     * Check parserstatus value in fit operational data. If this is set to 
                     * FIT_INFO_STOP_PARSE or FIT_INFO_CONTINUE_PARSE then stop further
                     * operations.
                     */
                    if ((popdata->parserstatus == FIT_INFO_STOP_PARSE) ||
                            (popdata->parserstatus == FIT_INFO_CONTINUE_PARSE))
                    {
                        break;
                    }
                }
#endif /* #ifdef FIT_USE_UNIT_TESTS */
                /* Check if there is any operation or some checks that need to be
                 * performed on object/array.
                 */
                status = parsercallbacks(obj_node->tagid, &fitlicobjptr, FIT_PARRAY_SIZE, opdata, license);
                if (status != FIT_STATUS_OK)
                {
                    break;
                }

                /* Puch the license elements on the array(table) for object/array for further processing */
                if (type == FIT_OBJECT)
                {
                    status = fit_add_lic_elem_in_lic_path(fitlicobjptr.data+FIT_POBJECT_SIZE,
                        templen, type, (SP_CHILD *)obj_node->childs, fitlicobjptr.read_byte, lic_scope_item, license);
                }
                else if (type == FIT_ARRAY)
                {
                    status = fit_add_lic_elem_in_lic_path(fitlicobjptr.data, templen, type,
                        (SP_CHILD *)obj_node->childs, fitlicobjptr.read_byte, lic_scope_item, license);
                }
                if (lic_scope_ref != FIT_LICENF_LICENSE_SCOPE_GLOBAL)
                {
                    /* ref_path would be marked done only if - 
                     * 1 - we reach to depth equal to reference path depth AND
                     * 2 - elements at reference path depth and current depth are same 
                     */
                    if ((lic_scope_item->depth == lic_scope_ref->depth) &&
                        (lic_scope_item->node[lic_scope_item->depth].child_nodes == lic_scope_ref->node[lic_scope_ref->depth].child_nodes))
                    {
                        lic_scope_item->ref_path_done = FIT_TRUE;
                    }
                }

                /* Check the status */
                if (status != FIT_STATUS_OK)
                {
                    break;
                }
                break;
            }

            case(FIT_INTEGER):
            case(FIT_STRING):
            case(FIT_BOOLEAN):
            case(FIT_BINARY):
            {
                /* Check/Validate minimum lm version required to consume the licenses. */
                if (obj_node->tagid == FIT_LM_VERSION_TAG_ID)
                {
                    status = fit_read_word_safe(fitlicobjptr.data, fitlicobjptr.read_byte,
                        license, &integer);
                    if(status != FIT_STATUS_OK)
                    {
                        break;
                    }
                    
                    integer = (uint16_t)((integer/2)-1);

                    if (integer > FIT_RUN_TIME_VERSION )
                    {
                        status = FIT_STATUS_INVALID_LM_VER;
                        break;
                    }
                }
#ifdef FIT_USE_UNIT_TESTS
                /*
                 * This code is used for unit tests. This will call the callback fn
                 * registered at tagid for integer and string objects.
                 */
                if (popdata->testop == FIT_TRUE)
                {
                    status = fieldcallbackfn(obj_node->tagid, &fitlicobjptr, opdata);
                }
                else
#endif /* #ifdef FIT_USE_UNIT_TESTS */
                {
                    /*
                     * If there is any callback function registered at tagid or operation
                     * requested by Fit then call the function.
                     */
                    if (objlen == FIT_PFIELD_SIZE && (type == FIT_INTEGER || type == FIT_BOOLEAN))
                    {
                        status = parsercallbacks(obj_node->tagid, &fitlicobjptr, objlen, opdata, license);
                    }
                    else
                    {
                        status = fit_read_dword_safe(fitlicobjptr.data, fitlicobjptr.read_byte,
                            license, &field_len);
                        if(status != FIT_STATUS_OK)
                        {
                            break;
                        }

                        if (field_len > objlen)
                        {
                            status = FIT_STATUS_INVALID_V2C;
                            break;
                        }
                        fitlicobjptr.data = fitlicobjptr.data+FIT_PSTRING_SIZE;
                        status = parsercallbacks(obj_node->tagid, &fitlicobjptr, field_len, opdata, license);
                    }

                }
                break;
            }

            default:
            {
                /* Wrong license data.*/
                DBG(FIT_TRACE_CRITICAL, "[parse_object]: Invalid license data. \n");
                status = FIT_STATUS_INVALID_V2C;
                break;
            }
        }
    }

    DBG(FIT_TRACE_INFO, "[fit_license_parser_execute end]:\n\n");

    return status;
}

/* Gets integer data from the pointer to data passed in */
fit_status_t fit_get_integer_data(fit_pointer_t *pdata,
                                  uint32_t length,
                                  uint64_t *integer,
                                  fit_pointer_t *license)/*lint !e818*/
{
    fit_status_t status = FIT_STATUS_UNKNOWN_ERROR;

    /* Get integer value. Integer value can be 16 bit value or 32 bit value.*/
    /* Get the 16 bit field value.*/
    if (length == sizeof(uint16_t))
    {
        uint16_t temp1 = 0;

        status = fit_read_word_safe(pdata->data, pdata->read_byte, license, &temp1);
        if(status != FIT_STATUS_OK)
        {
            return status;
        }

        *integer = (uint32_t)((temp1/2)-1);

        DBG(FIT_TRACE_INFO, "Integer Value = %ld\n", integer);
    }
    /* Get the 32 bit field value.*/
    else if (length == sizeof(uint32_t))
    {
        uint32_t temp1 = 0;

        /* This represents integer data in form of string, so need to do calculations.*/
        status = fit_read_dword_safe(pdata->data, pdata->read_byte, license, &temp1);
        if(status != FIT_STATUS_OK)
        {
            return status;
        }

        *integer = temp1;

        DBG(FIT_TRACE_INFO, "Integer Value = %ld\n", integer);
    }
    /* Get the 32 bit field value.*/
    else if (length == sizeof(uint64_t))
    {
        uint64_t temp1 = 0;

        /* This represents long integer data (8 byte) in form of string.
         * Maximum value of any integer data supported is 0xFFFFFF. So presently
         * using uint32_t data type. Need to change this when maximum supported
         * value exceeds 0xFFFFFFFF
         */        

        status = fit_read_ulonglong_safe(pdata->data, pdata->read_byte, license, &temp1);
        if(status != FIT_STATUS_OK)
        {
            return status;
        }

        *integer = (uint32_t)temp1;

        DBG(FIT_TRACE_INFO, "Integer Value = %ld\n", integer);
    }

    return FIT_STATUS_OK;
}

/**
 *
 * fit_get_data_address
 *
 * This function will be used to get address passed in tag identifier. Each field of
 * license binary is assigned a unique tagid.
 *
 * @param IN    pdata   \n Pointer to fit_pointer_t structure containing license
 *                         data corresponding to tag id.
 *
 * @param IN    tagid   \n tag identifier (as per sproto schema) identifies a
 *                         unique field in license binary.
 *
 * @param IN    length  \n Length of the data to be get.
 *
 * @param IN    opdata \n Pointer to fit operational data structure.
 *
 */
static fit_status_t fit_get_data_address(fit_pointer_t *pdata,
                                  fit_tag_id_t tagid,
                                  uint32_t length,
                                  void *opdata,
                                  fit_pointer_t *license)
{
    fit_op_data_t *popdata  = (fit_op_data_t *)opdata;
    fit_status_t status     = FIT_STATUS_OK;
    fit_pointer_t fitptr    = {0};
    uint64_t integer        = 0;
    uint8_t *temp           = NULL;
    uint16_t strlen         = 0;

    if (tagid == popdata->tagid)
    {
        DBG(FIT_TRACE_INFO, "[fit_get_data_address]: for tagid=%d, pdata=0x%X \n",
            (unsigned int)tagid, pdata->data);

        if (popdata->type == FIT_STRING && popdata->string != NULL &&
                ((popdata->flags & FIT_FIND_ITEM_MATCH) == FIT_FIND_ITEM_MATCH))
        {
            fitptr.data = pdata->data;
            fitptr.length = length;
            fitptr.read_byte = pdata->read_byte;

            temp = popdata->string;
			// what is done here ?????
            /* get the length of data to be compared */
            while (*temp != '\0')
            {
                strlen++;
                temp++;
            }
			/** HorG - what about if length > 2**16 ????? */
            if(strlen != length || (fit_fitptr_sec_memcmp(&fitptr, (const uint8_t *)popdata->string,
                (uint16_t)length) != 0))
            {
                return FIT_STATUS_OK;
            }
        }
        else if (popdata->type == FIT_INTEGER &&
                    (popdata->flags & FIT_FIND_ITEM_MATCH) == FIT_FIND_ITEM_MATCH)
        {
            status = fit_get_integer_data(pdata, length, &integer, license);

            if(status != FIT_STATUS_OK)
            {
                return status;
            }

            if(integer != popdata->intval)
            {
                return FIT_STATUS_OK;
            }
        }

        popdata->parserdata.addr = pdata->data;
        popdata->length = length;
        popdata->parserstatus = FIT_INFO_STOP_PARSE;
        popdata->status = FIT_STATUS_LIC_FIELD_PRESENT;
    }

    return status;
}

#ifdef FIT_USE_UNIT_TESTS

/**
 *
 * fieldcallbackfn
 *
 * This function will call the callback function register at tagid. Each field of license
 * binary is assigned a unique tagid.
 *
 * @param IN    tagid   \n tag identifier (as per sproto schema) identifies a
 *                         unique field in license binary.
 *
 * @param IN    pdata   \n Pointer to fit_pointer_t structure containing license data
 *                         for passed in tagid.
 *
 * @param IN    opdata \n Pointer to fit operational data structure.
 *
 */
static fit_status_t fieldcallbackfn(fit_tag_id_t tagid,
                                    fit_pointer_t *pdata,
                                    void *opdata)
{
    fit_op_data_t *popdata  = (fit_op_data_t *)opdata;
    uint16_t cntr               = 0;
    fit_status_t status         = FIT_STATUS_OK;

    if (tagid > FIT_END_TAG_ID)
    {
        return FIT_STATUS_INVALID_PARAM_1;
    }

    DBG(FIT_TRACE_INFO, "[fieldcallbackfn start]: for tagid=%d, pdata=0x%X \n",
        (unsigned int)tagid, pdata->data);

    /* Call callback function that is registered against tag identifier.*/
    for(cntr = 0; cntr < (sizeof(testfct)/sizeof(fit_testcallbacks_t)); cntr++)
    {
        if( ((testfct[cntr].tagid == popdata->tagid) && testfct[cntr].tagid == tagid))
        {
            status = testfct[cntr].callback_fn(pdata, tagid, opdata);
            break;
        }
    }

    return status;
}
#endif /* #ifdef FIT_USE_UNIT_TESTS */

/**
 *
 * parsercallbacks
 *
 * This function will call the callback function register for each operation type.
 *
 * @param IN    tagid   \n tag identifier (as per sproto schema) identifies a
 *                         unique field in license binary.
 *
 * @param IN    pdata   \n Pointer to fit_pointer_t structure containing license data
 *                         for passed in tagid.
 *
 * @param IN    length  \n Length of the data to be get.
 *
 * @param IN    opdata \n Pointer to fit operational data structure.
 *
 */
static fit_status_t parsercallbacks(fit_tag_id_t tagid,
                             fit_pointer_t *pdata,
                             uint32_t length,
                             void *opdata,
                             fit_pointer_t *license)
{
    fit_op_data_t *popdata  = (fit_op_data_t *)NULL;
    fit_status_t status         = FIT_STATUS_OK;
    fit_boolean_t stop_parse           = FIT_FALSE;

    /* Validate parameters passed in.*/
    if (tagid > FIT_END_TAG_ID)
    {
        return FIT_STATUS_INVALID_PARAM_1;
    }

    DBG(FIT_TRACE_INFO, "[parsercallbacks start]: for tagid=%d, pdata=0x%X \n",
        (unsigned int)tagid, pdata->data);

    popdata = (fit_op_data_t *)opdata;
    if (popdata->operation > (uint8_t)FIT_OP_LAST)
    {
        return FIT_STATUS_INVALID_PARAM_5;
    }
    if (popdata->operation == (uint8_t)FIT_OP_NONE)
    {
        return FIT_STATUS_OK;
    }

    /*
     * Call the getinfo api fn for passed in tag identifier if operation requested
     * is FIT_OP_GET_LICENSE_INFO_DATA
     */
    if (popdata->operation == (uint8_t)FIT_OP_GET_LICENSE_INFO_DATA)
    {
        uint8_t *buf = (uint8_t *)popdata->parserdata.getinfodata.get_info_data;

        DBG(FIT_TRACE_INFO, "Calling user provided callback function\n");
        status = popdata->parserdata.getinfodata.callback_fn(tagid, pdata, length, &stop_parse, buf, license);
        if (stop_parse == FIT_TRUE)
        {
            popdata->parserstatus = FIT_INFO_STOP_PARSE;
        }
    }
    /* Else Call the callback function that is registered against operation type.*/
    else
    {
        if( (popdata->operation > (uint8_t)FIT_OP_NONE) && 
            (popdata->operation < (uint8_t)(sizeof(fct)/sizeof(struct fit_parse_callbacks))) )
        {
            status = fct[popdata->operation].callback_fn(pdata, tagid, length, popdata, license);             
        }        
    }

    DBG(FIT_TRACE_INFO, "[parsercallbacks end]: for tagid=%d \n", (unsigned int)tagid);
    return status;
}

/**
 *
 * fit_get_license_len
 *
 * This function will get the length of passed in sproto object
 *
 * @param IN    pdata   \n Pointer to fit_pointer_t structure that contains object
 *                         data
 *
 */
fit_status_t fit_get_object_len(fit_pointer_t* pdata, 
                                uint32_t *length, 
                                fit_pointer_t *license)/*lint !e818*/
{
    uint16_t num_fields  = 0;
    uint8_t cntr         = 0;
    uint8_t *parserdata  = pdata->data;
    uint16_t field_data  = 0;
    fit_pointer_t fitptr = {0};
    fit_status_t status  = FIT_STATUS_UNKNOWN_ERROR;

    fitptr.read_byte = pdata->read_byte;
    fitptr.data = pdata->data;
    
    status = fit_read_word_safe(fitptr.data, fitptr.read_byte, license, &num_fields);
    if(status != FIT_STATUS_OK)
    {
        return status;
    }

    *length = (num_fields+1)*FIT_PFIELD_SIZE;

    /*
     * First field represents no. of fields for object. Move data pointer to next
     * field to get first field data.
     */
    fitptr.data = fitptr.data + FIT_PFIELD_SIZE;

    for( cntr = 0; cntr < num_fields; cntr++)
    {
        /*
         * Each field in field part is a 16bit integer  Value of this field will
         * tell what type of data it contains.
         */ 
        status = fit_read_word_safe(fitptr.data, fitptr.read_byte, license, &field_data);
        if(status != FIT_STATUS_OK)
        {
            return status;
        }

        if( field_data == 0ul )
        {
            uint32_t temp = 0;

            status = fit_read_dword_safe(parserdata+(*length), fitptr.read_byte, license, &temp);
            if(status != FIT_STATUS_OK)
                return status;

            *length   = (*length + temp + sizeof(uint32_t));
        }
        if (*length > pdata->length)
        {
            return FIT_STATUS_INVALID_V2C;
        }

        /* Move data pointer to next field.*/
        fitptr.data = fitptr.data + FIT_PFIELD_SIZE;
    }

    return FIT_STATUS_OK;
}

