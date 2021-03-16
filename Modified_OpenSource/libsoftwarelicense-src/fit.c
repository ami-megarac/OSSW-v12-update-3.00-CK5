/****************************************************************************\
**
** fit_demo.c
**
** Sample Sentinel FIT licensing for embedded devices demo
**
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#ifdef __linux__
#define fit_strcmpi strcasecmp
#elif _WIN32
#define fit_strcmpi strcmpi
#endif

#define NO_PRODUCT_ID_SPECIFIED 0
#define NO_OF_KEYS				2

#define SAMPLE_FAILURE_EXIT_CODE	100
#define SAMPLE_ALL_CONSUME_FAIL		101
#define FP_MAX_BUFFER_SIZE			65

#define FIT_VENDOR_ID 5242893
#define FIT_VENDOR_GLOBAL "EJYNW|5242893"

#if defined (FIT_BUILD_SAMPLE)

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "fit_api.h"
#include "fit_internal.h"
#include "fit_hwdep.h"
#include "fit_mem_read.h"
#include "fit_debug.h"
#include "fit_parser.h"
#include "fit_aes.h"
//#include "fit_types.h"

#include "fit_omac.h"
#include "fit_info.h"
#include "fit_consume.h"

#include "mbedtls/base64.h"
#include "fit_version.h"

#define LIC_PATH "/conf/licenseFile.v2c"


fit_pointer_t key[NO_OF_KEYS];

fit_key_array_t *keys_array = NULL;

uint16_t rsa_algo_guid = FIT_KEY_SCOPE_SIGN << 12 | FIT_RSA_2048_ADM_PKCS_V15_ALG_ID;
uint16_t aes_algo_guid = FIT_KEY_SCOPE_SIGN << 12 | FIT_AES_128_OMAC_ALG_ID;

fit_algorithm_list_t rsa_algorithm = {1, &rsa_algo_guid};
//fit_algorithm_list_t rsa_algorithm;

fit_algorithm_list_t aes_algorithm = {1, &aes_algo_guid};
//fit_algorithm_list_t aes_algorithm;

fit_key_data_t aes_key_data = {0};
fit_key_data_t rsa_key_data = {0};

char vendor_global[20] = "";

/****************************************************************************/

void setup(void)
{
    fit_board_setup();

    /*
    * Set current time to current unixtime. You can customize that according to
    * your hardware capabilities
    */
    FIT_TIME_SET((unsigned long)time(NULL)); /* Jan 25, 2016 */

    fit_led_off();
}

/****************************************************************************/

const unsigned char VENDOR_AES_128[] = {    
   0x77, 0x12, 0x13, 0x32, 0x01, 0x69, 0xd1,0x2d,
   0xa6, 0xc3, 0x53, 0xee, 0xa5, 0xd7, 0xa3, 0x13
};

const unsigned char VENDOR_RSA_pubkey[292] = {
    0x30, 0x82, 0x01, 0x20, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03,
    0x82, 0x01, 0x0d, 0x00, 0x30, 0x82, 0x01, 0x08, 0x02, 0x82,
    0x01, 0x01, 0x00, 0xca, 0xfb, 0x5e, 0x2d, 0x78, 0xb3, 0x3c,
    0x75, 0x14, 0x8f, 0x48, 0x8e, 0xbf, 0xaa, 0x1c, 0xa5, 0xd8,
    0x4c, 0x5d, 0x58, 0xf0, 0xf1, 0xd6, 0x36, 0x4e, 0xad, 0xc3,
    0x31, 0x7e, 0xa6, 0x60, 0xb2, 0xf6, 0xba, 0x95, 0x54, 0xc4,
    0xd8, 0xeb, 0x4d, 0x08, 0x93, 0x95, 0x76, 0x70, 0x95, 0x7a,
    0xc8, 0x64, 0x77, 0x24, 0x75, 0xb2, 0xc5, 0xd2, 0x21, 0x4d,
    0x58, 0x13, 0x7b, 0x56, 0x97, 0x2d, 0xf2, 0xce, 0xbc, 0xd0,
    0x96, 0x71, 0x05, 0xd0, 0x81, 0xa3, 0x47, 0x16, 0x75, 0x4b,
    0x7d, 0xa0, 0xba, 0x23, 0x9a, 0x62, 0xa0, 0xbf, 0x8b, 0x0e,
    0xde, 0x1b, 0x86, 0x8f, 0x8f, 0x7a, 0x05, 0x80, 0x68, 0xdf,
    0x7b, 0xbc, 0xa3, 0x59, 0x9d, 0xf3, 0x86, 0x79, 0x8b, 0xe1,
    0x92, 0x09, 0x98, 0x0b, 0xa0, 0xd7, 0x0f, 0x90, 0xe9, 0x97,
    0x87, 0x16, 0xaf, 0xde, 0xf9, 0x27, 0xf6, 0xcf, 0xcd, 0x5f,
    0xe7, 0x99, 0xd5, 0x36, 0x41, 0xc9, 0xc9, 0xa8, 0xf7, 0x8d,
    0xa3, 0xc2, 0xc8, 0x64, 0x6e, 0x38, 0x70, 0x30, 0x18, 0x1c,
    0x24, 0x4f, 0x5d, 0xfc, 0x29, 0x69, 0xdf, 0x16, 0x97, 0xba,
    0x9a, 0x8b, 0x9a, 0x68, 0x2d, 0xbc, 0x5c, 0x4f, 0xe4, 0xfc,
    0x4c, 0x4d, 0x1a, 0x02, 0xaf, 0x60, 0xab, 0xff, 0xa5, 0x67,
    0x5e, 0xd2, 0x61, 0x4b, 0xf9, 0xf1, 0x87, 0xfa, 0x74, 0x7d,
    0x82, 0x55, 0x62, 0x84, 0xa8, 0x46, 0xd6, 0xe3, 0x56, 0x12,
    0x5c, 0x38, 0xdf, 0xb5, 0xe1, 0xa0, 0xf2, 0x3a, 0x3e, 0x85,
    0xf7, 0x60, 0x80, 0x8d, 0xc1, 0x18, 0xd7, 0xc6, 0xfd, 0xa6,
    0x4b, 0xd3, 0xe4, 0xbe, 0xd2, 0x65, 0x19, 0x2e, 0x80, 0x05,
    0xeb, 0xed, 0xe3, 0x71, 0xe1, 0xee, 0x16, 0xf9, 0xdc, 0x34,
    0x83, 0x3f, 0x28, 0xc1, 0xa1, 0xbe, 0x5c, 0xac, 0xb5, 0x45,
    0xb9, 0xe0, 0xcb, 0x17, 0xfb, 0xfc, 0x95, 0x8a, 0x49, 0x02,
    0x01, 0x03 };

int fmt_bin_write(char *path, unsigned char *buffer, long buffer_len)
{
    FILE *fd = NULL;
    int i = 0;
    int status = 0;

    if (buffer == NULL || buffer_len == 0)
    {
        return -1;
    }

    if ((fd = fopen(path, "wb")) == NULL)
    {
        printf("\n Error opening file for write\n");
        return -1;
    }

    status = fwrite(buffer, buffer_len, 1, fd);
    if (status != 1)
    {
        fprintf(stderr, "\n Error writing file\n");
        fclose(fd);
        return -1;
    }
    fclose(fd);
    return 0;
}

void fit_putc(char c); /* defined in fit_debug.h - used to output large buffer */

int fmt_read_file(char *path, unsigned char **buffer, uint32_t *filesize1)
{
    FILE *fd;
    int i = 0;
    if ((fd = fopen(path, "rb")) == NULL)
    {
        perror("\n Error opening file\n");
        return -1;
    }
    fseek(fd, 0, SEEK_END);
    *filesize1 = ftell(fd);
    rewind(fd);
    *buffer = (unsigned char *)calloc(1,(*filesize1) + 1);
    if (*buffer == NULL)
    {
        fclose(fd);
        return -1;
    }

    if (fread(*buffer, sizeof(char), *filesize1, fd) != *filesize1)
    {
        fprintf(stderr, "\n Error reading file\n");
        fclose(fd);
        return -1;
    }
//	(*buffer)[*filesize1] = '\0';
    fclose(fd);
    return 0;
}

/**
 *	load_license
 *	
 *	This Function can be load a fit license from a file 
 *
 * @param IN  \b  lic_name   \n  Full path of the file to be read as license
 *
 * @param IN  \b  lic_name   \n  Full path of the file to be read as license
 *
 */
int load_license(char *lic_name, fit_pointer_t *lic)
{
    uint8_t val = 0;

    if (lic == NULL)
    {
        printf("\n\t Pointer to license cannot be NULL...\n");
        return 1;
    }

    if (lic->data)
    {
        free(lic->data);
        lic->data = NULL;
    }

    lic->length = 0;

    val = fmt_read_file(lic_name, &lic->data, &lic->length);

    if (val == 0)
    {
        printf("\n\t\t License Load successful, | lic length=%d | \n", lic->length);
        lic->read_byte = FIT_READ_BYTE_RAM;
    }
    else
    {
        printf("\n\t\t License Load Unsuccessful, Try Again !!\n");
        return 1;
    }

    return 0;
}

int setKey(uint32_t vid);

/**
 *	do_all_consume
 *	
 *	This Function can be used to perform a "Full-Consume" operation on all features within a license
 *	"Full-Consume": 1. fit_licenf_find_feature()
 *					2. fit_licenf_start_consume()
 *					3. fit_licenf_end_consume()
 *
 * @param IN  \b  license   \n  Pointer to an fit_license_t object that contains fit-license and its keys
 *
 */
fit_status_t do_all_consume(fit_license_t *license)
{

    uint32_t pid = 0;
    uint32_t fid = 0;

    char qty[10] = "";
    char* qty_str = "quantity";

    fit_lic_scope_t product_scope;
    fit_lic_scope_t feature_scope;
    fit_lic_scope_t item_scope;
    fit_lic_scope_t ref_scope;

    fit_info_item_t product_item;
    fit_info_item_t feature_item;
    fit_info_item_t temp_item;

    fit_status_t status = FIT_STATUS_OK;

    fit_boolean_t next_product_exists = FIT_TRUE;
    fit_boolean_t next_feature_exists = FIT_TRUE;

    fit_feature_ctx_t ftr_ctx = {0};

    fit_licenf_initialize_scope(&product_scope);
    fit_licenf_initialize_scope(&feature_scope);
    fit_licenf_initialize_scope(&item_scope);
    fit_licenf_initialize_scope(&ref_scope);

    (void)fit_memset(&product_item, 0, sizeof(fit_info_item_t));
    (void)fit_memset(&feature_item, 0, sizeof(fit_info_item_t));
    (void)fit_memset(&temp_item, 0, sizeof(fit_info_item_t));

    product_item.tag_id = FIT_PRODUCT_ID_TAG_ID;
    feature_item.tag_id = FIT_FEATURE_ID_TAG_ID;

    product_item.type = FIT_INTEGER;
    feature_item.type = FIT_INTEGER;
#if 0
    printf("\n");
    printf("\n\t\t ---------------------------------------");
    printf("\n\t\t ---|CONSUME ALL FEATURES IN LICENSE|---");
    printf("\n\t\t ---------------------------------------");
#endif
    status = fit_licenf_find_item(license, FIT_LICENF_LICENSE_SCOPE_GLOBAL, &product_scope, FIT_FIND_ITEM_FIRST, &product_item);
    if (status != FIT_STATUS_OK)
    {
        printf("\n\t fit_licenf_find_item() for any product in license failed with status %d\n", status);
        return status;
    }

    do /* PRODUCT LOOP*/
    {

        temp_item.tag_id = FIT_SYSTEM_ATTR_KEY_TAG_ID;
        temp_item.type = FIT_STRING;
        temp_item.object.string = (uint8_t*)qty_str;
        status = fit_licenf_find_item(license, &product_scope, &ref_scope, FIT_FIND_ITEM_FIRST|FIT_FIND_ITEM_MATCH, &temp_item);
        if (status == FIT_STATUS_OK)
        {
            temp_item.tag_id = FIT_SYSTEM_ATTR_KEY_VALUE_TAG_ID;
            temp_item.type = FIT_STRING;
            status = fit_licenf_find_item(license, &ref_scope, &item_scope, FIT_FIND_ITEM_FIRST, &temp_item);
            if (status == FIT_STATUS_OK)
            {
                memcpy(qty, temp_item.object.data_ptr.data, temp_item.object.data_ptr.length);
                printf("\n\t\t |PRODUCT ID:%d \t Quantity: %s|\n", (uint32_t)product_item.object.intval, qty);
            }
            else
                printf("\n\t Quantity attribute value not found...\n");
        }

        fit_licenf_initialize_scope(&item_scope);
        fit_licenf_initialize_scope(&ref_scope);

        memset(&temp_item, 0, sizeof(fit_info_item_t));
        memset(&qty, 0, sizeof(qty));


        status = fit_licenf_find_item(license, &product_scope, &feature_scope, FIT_FIND_ITEM_FIRST, &feature_item);
        if (status != FIT_STATUS_OK)
        {
            printf("\n\t No Feature Found in product %d in License...\n", (uint32_t)product_item.object.intval);
            return status;
        }

        next_feature_exists = FIT_TRUE;
        do /* FEATURE LOOP*/
        {

            memset(&ftr_ctx, 0, sizeof(fit_feature_ctx_t));

            status = fit_licenf_find_feature(license, feature_item.object.intval, FIT_FIND_FEATURE_FIRST, &ftr_ctx);
            if (status != FIT_STATUS_OK)
            {
                printf("\n\t Fit_licenf_find_feature() failed for fid: %d with status %d\n", (uint32_t)feature_item.object.intval, (unsigned int)status);
                return status;
            }

            if (ftr_ctx.feature_info.product_id != product_item.object.intval)
            {
                do
                {
                    status = fit_licenf_find_feature(license, feature_item.object.intval, FIT_FIND_FEATURE_NEXT, &ftr_ctx);

                } while (ftr_ctx.feature_info.product_id != product_item.object.intval && status == FIT_STATUS_OK);

                if (ftr_ctx.feature_info.product_id != product_item.object.intval)
                {
                    printf("\n\t Feature Id: %d not found within Product Id: %d ...\n", (uint32_t)feature_item.object.intval, (uint32_t)product_item.object.intval);
                    return FIT_STATUS_INTERNAL_ERROR;
                }
            }

            status = fit_licenf_start_consume_feature(&ftr_ctx, 0);
            if (status == FIT_STATUS_OK)
            {
                printf("\n\t fit_licenf_start_consume_feature() for feature_id: %d was SUCCESSFUL with status %d...\n", (uint32_t)feature_item.object.intval, status);
            }
            else
            {
                printf("\n\t fit_licenf_start_consume_feature() for feature_id: %d FAILED with status %d...\n", (uint32_t)feature_item.object.intval, status);
                return status;
            }

            status = fit_licenf_end_consume_feature(&ftr_ctx);
            if (status == FIT_STATUS_OK)
            {
                printf("\n\t fit_licenf_end_consume_feature()   for feature_id: %d was SUCCESSFUL with status %d...\n", (uint32_t)feature_item.object.intval, status);
            }
            else
            {
                printf("\n\t fit_licenf_end_consume_feature()   for feature_id: %d FAILED with status %d...\n", (uint32_t)feature_item.object.intval, status);
                return status;
            }

            printf("\n");

            status = fit_licenf_find_item(license, &product_scope, &feature_scope, FIT_FIND_ITEM_NEXT, &feature_item);
            if (status != FIT_STATUS_OK)
            {
                next_feature_exists = FIT_FALSE;
            }

        } while (next_feature_exists == FIT_TRUE); /* END OF FEATURE LOOP*/

        printf("\n");

        status = fit_licenf_find_item(license, FIT_LICENF_LICENSE_SCOPE_GLOBAL, &product_scope, FIT_FIND_ITEM_NEXT, &product_item);
        if (status != FIT_STATUS_OK)
        {
            next_product_exists = FIT_FALSE;
        }

    } while (next_product_exists == FIT_TRUE); /* END OF PRODUCT LOOP*/

    return FIT_STATUS_OK;
}


/**
 *	do_single_consume
 *	
 *	This Function can be used to perform a "Full-Consume" operation on a single feature within a license
 *	"Full-Consume": 1. fit_licenf_find_feature()
 *					2. fit_licenf_start_consume()
 *					3. fit_licenf_end_consume()
 *
 * @param IN  \b  feature_id   \n  Feature Id for which consume operation is to be performed
 *
 * @param IN  \b  license   \n  Pointer to an fit_license_t object that contains license and its keys
 *
 * @param IN  \b  product_id   \n  Id of the product within which feature_id has to be searched(in case multiple products can have same feature_id)
 *								   If product_id is passed as 0 then feature_id will be searched globally and the feature_id that is first found
 *								   would be used for consume operation
 *
 */
fit_status_t do_single_consume(uint32_t feature_id, fit_license_t *license, uint32_t product_id)
{
    fit_feature_ctx_t ftr_ctx = {0};
    fit_status_t status = FIT_STATUS_OK;

    printf("\n");
    printf("\n\t\t Feature id: %d ", feature_id);
    if (product_id != 0)
        printf("| Product id: %d\n", product_id);

    status = fit_licenf_find_feature(license, feature_id, FIT_FIND_FEATURE_FIRST, &ftr_ctx);
    if (status != FIT_STATUS_OK)
    {
        printf("\n\t\t fit_licenf_find_feature() failed for fid: %d with status %d\n", feature_id, (unsigned int)status);
        return status;
    }

    if ((product_id != 0) && (ftr_ctx.feature_info.product_id != product_id))
    {
        do
        {
            status = fit_licenf_find_feature(license, feature_id, FIT_FIND_FEATURE_NEXT, &ftr_ctx);
            if (status != FIT_STATUS_OK)
            {
                printf("\n\t\t fit_licenf_find_feature() failed for fid: %d with status %d\n", feature_id, (unsigned int)status);
                return status;
            }

        } while (ftr_ctx.feature_info.product_id != product_id);
    }

    status = fit_licenf_start_consume_feature(&ftr_ctx, 0);
    if (status == FIT_STATUS_OK)
    {
        printf("\n\t\t fit_licenf_start_consume_feature() for Feature_ID: %d with Product_ID: %d was SUCCESSFUL with status %d...\n",
             feature_id, (uint32_t)ftr_ctx.feature_info.product_id, (unsigned int)status);
    }
    else
    {
        printf("\n\t\t fit_licenf_start_consume_feature() for Feature_ID: %d with Product_ID: %d FAILED with status %d...\n",
            feature_id, (uint32_t)ftr_ctx.feature_info.product_id, (unsigned int)status);
        return status;
    }

    status = fit_licenf_end_consume_feature(&ftr_ctx);
    if (status == FIT_STATUS_OK)
    {
        printf("\n\t\t fit_licenf_end_consume_feature()   for Feature_ID: %d with Product_ID: %d was SUCCESSFUL with status %d...\n",
            feature_id, (uint32_t)ftr_ctx.feature_info.product_id, (unsigned int)status);
    }
    else
    {
        printf("\n\t\t fit_licenf_end_consume_feature()   for Feature_ID: %d with Product_ID: %d FAILED with status %d...\n",
            feature_id, (uint32_t)ftr_ctx.feature_info.product_id, (unsigned int)status);
        return status;
    }

    printf("\n");

    return status;
}

void print_help()
{
    printf("\nSample Usage: validate_sample.exe <Path to Fit license> [Optional Parameters]\n");
    printf("\nOptional Paramters: ");
    printf("\n -d <device_id> : device_id used for generating the fingerprint [default value: 'abcdefghijklmn']");
    printf("\n -f <feature_id>: To specify feature ids for login(space seperated list)");
    printf("\n -h             : Display help for sample usage");
    printf("\n");

    return;
}

/**
 *	get_fp_str
 *	
 *	This Function can be used to get fingerprint string that is associated with a device fingerprint info 
 *
 * @param IN  \b  fp_info   \n  Contains the pointer to the fingerprint data and it's corresponding length
 *
 * @param OUT  \b  fpstr    \n  Pointer to the buffer where fingerprint string out would be copied
 *
 */
uint32_t get_fp_str(fit_pointer_t fp_info, unsigned char *fpstr)
{
    fit_status_t status = FIT_STATUS_OK;

    uint32_t ret = 0;
    size_t fp_length = 0;

    uint8_t *ptr = NULL;

    ptr = (uint8_t *)fp_info.data;

    ret = mbedtls_base64_encode(NULL, 0, &fp_length, ptr, sizeof(fit_fingerprint_t));
    ret = mbedtls_base64_encode(fpstr, fp_length, &fp_length, ptr, sizeof(fit_fingerprint_t));

    return ret;
}

/**
 *	set_device_id
 *	
 *	This Function can be used to set device_id that will be used to compute fingeprint by Fit-Core
 *
 * @param IN  \b  dev_id   \n  Device id that need to be set on device
 *
 * @param IN  \b  len    \n  length of the device_id; Valid Length = (4-64)
 *
 */
void set_device_id(char* dev_id, uint16_t len)
{
    memset(&fit_dev_id, 0, FIT_DEVID_MAXLEN);
    memcpy(&fit_dev_id, dev_id, len);
    fit_dev_id_len = len;
    return;
}


void getKeyArray(fit_pointer_t key[])
{

//rsa_algorithm.num_of_alg = 1;
//rsa_algorithm.algorithm_guid = &aes_algo_guid[0];
//aes_algorithm.num_of_alg = 1;
//aes_algorithm.algorithm_guid[0] = &aes_algo_guid;

    aes_key_data.key = (uint8_t *)key[1].data;
    aes_key_data.key_length = key[1].length;
    aes_key_data.algorithms = &aes_algorithm;

    rsa_key_data.key = (uint8_t *)key[0].data;
    rsa_key_data.key_length = key[0].length;
    rsa_key_data.algorithms = &rsa_algorithm;

    keys_array = (fit_key_array_t *)calloc(1,sizeof(fit_key_array_t) + 2 * sizeof(fit_key_data_t *));
	if( keys_array == NULL ){
		printf("fatal error: cannot allocate %d bytes of memory -> exit\n",sizeof(fit_key_array_t) + 2 * sizeof(fit_key_data_t *));
		exit(1);
	}
    keys_array->keys[0] = &rsa_key_data;
    keys_array->keys[1] = &aes_key_data;
    keys_array->read_byte = FIT_READ_KEY_BYTE;
    keys_array->number_of_keys = 2;

    return;
}


/**
 * setKey
 *			This function will be used initialize the key_array against the vendor_id specified
 *
 * @param IN  \b  vid   \n  vendor_id of the vendor whose keys needs to be initialized
 *
 */
int setKey(uint32_t vid)
{

    //***************************VENDOR***************************************
    if (vid == FIT_VENDOR_ID)
    {
        strcpy(vendor_global, FIT_VENDOR_GLOBAL);

        key[0].data = (uint8_t *)VENDOR_RSA_pubkey;
        key[0].length = sizeof(VENDOR_RSA_pubkey);

        key[1].data = (uint8_t *)VENDOR_AES_128;
        key[1].length = sizeof(VENDOR_AES_128);
        getKeyArray(key);
    }

    else
    {
        printf("\n\t VendorKeys not found for Vendor %d", vid);
        return 1;
    }
    

    return 0;
} //End of int setkey(uint32_t vid)

/****************************************************************************/



int license_fit_check(void)
{
    return licensefile_fit_check(LIC_PATH);
}


int licensefile_fit_check(char *filepath)
{

    fit_status_t status = FIT_STATUS_OK;
    fit_pointer_t licptr = {0};

    fit_feature_ctx_t ftr_ctx = {0};
    fit_license_t licobj = {0};
    fit_key_array_t fitkeys = {0};

    fit_info_item_t item;
    fit_pointer_t fp_ptr = {0};
    fit_lic_scope_t item_path;

    int ret = 0;
    int i = 0;
    int nof = 0; //8;

    uint32_t *ftr_list = NULL;
/*    ftr_list = calloc(8, sizeof(uint32_t));
	ftr_list[0] = 1;
	ftr_list[1] = 2;
	ftr_list[2] = 3;
	ftr_list[3] = 4;
	ftr_list[4] = 5;
	ftr_list[5] = 6;
	ftr_list[6] = 22;
	ftr_list[7] = 100;
*/
    uint8_t *ptr = NULL;

    uint8_t fit_major_ver	 = 0;
    uint8_t fit_minor_ver	 = 0;
    uint8_t fit_revision_ver = 0;


    size_t liclen = 0;

    char *device_id = NULL;
    char dev_id_from_core[FIT_DEVID_MAXLEN] = {0}; 
    char fp[FP_MAX_BUFFER_SIZE] = {0};
    uint32_t fp_length = 0;

    unsigned char fp_buff[FP_MAX_BUFFER_SIZE] = {0};

    fp_length = 0;

    if(filepath == NULL)
    {
        printf("\n\t License file name is NULL...\n");
        return(SAMPLE_FAILURE_EXIT_CODE);
    }
		
    status = fit_licenf_init();
    if(status != FIT_STATUS_OK)
    {
        printf("\n\t fit_licenf_init() failed with status: %d\n", status);
        exit(0);
    }

    (void)fit_memset(&item, 0, sizeof(fit_info_item_t));
    status = fit_licenf_initialize_scope(&item_path);
    if(status != FIT_STATUS_OK)
    {
        printf("\n\t fit_licenf_initialize_scope() failed with status: %d\n", status);
        exit(0);
    }

    setup(); /* initialize UART and LED ports */

    status = fit_licenf_get_version(&fit_major_ver, &fit_minor_ver, &fit_revision_ver);
    if(status != FIT_STATUS_OK)
    {
        printf("\n\t fit_licenf_get_version() failed with status: %d\n", status);
        exit(0);
    }

    printf("\n\t ================================");
    printf("\n\t |   Fit Core Version: %d.%d.%d", fit_major_ver, fit_minor_ver, fit_revision_ver);
    printf("\n\t --------------------------------");
    printf("\n\t |   Runtime Version : %d", FIT_RUN_TIME_VERSION);
    printf("\n\t ================================\n");

    /* Reading the license binary */
    ret = load_license(filepath, &licptr);
    if(ret != 0)
    {
        printf("\n\t Cannot read file %s ...\n", filepath);
        return(SAMPLE_FAILURE_EXIT_CODE);
    }

    setKey(FIT_VENDOR_ID);

    if (device_id != NULL)
    {
        if (strlen(device_id) >= FIT_DEVID_MINLEN && strlen(device_id) <= FIT_DEVID_MAXLEN)
        {
            set_device_id(device_id, strlen(device_id));
        }
        else
        {
            printf("\n\t Invalid length for Input Device Id, Valid Length: (4-64)\n");
            return (SAMPLE_FAILURE_EXIT_CODE);
        }
    }

    printf("\n\t | Vendor Keys Used : %s |\n", vendor_global);

    printf("\n\t | Device ID used : %s |\n", fit_dev_id);

    /*
     * Fetch Fingerprint info from device
     */

    fp_length = sizeof(fp);

    // Get the buffer length required for fingerprint.
    status = fit_licenf_get_fingerprint(NULL, &fp_length);

    if ((status == FIT_STATUS_BUFFER_OVERRUN) && (fp_length > 0))
    {
        // if returned length is bigger that buffer
        if( fp_length > FP_MAX_BUFFER_SIZE )
        {
            printf("\n\t Error: Required fingerprint length is greater than available buffer length i.e. %d", FP_MAX_BUFFER_SIZE);
        }
        else
        {
            // Get the fingerprint.
            status = fit_licenf_get_fingerprint(fp, &fp_length);
            if(status == FIT_STATUS_OK)
            {
                printf("\n\t |  Device Fingerprint : %s |", fp);
            }
            else
            {
                printf("\n\t |  fit_licenf_get_fingerprint() failed with status %d |", status);
            }
        }
    }

    memset(&fp_ptr,  0, sizeof(fp_ptr));
    memset(&fp_buff, 0, sizeof(fp_buff));

    status = fit_licenf_construct_license(&licptr, keys_array, &licobj);
    if (status != FIT_STATUS_OK)
    {
        printf("\n\t Failed to contruct License object...");
        return (SAMPLE_FAILURE_EXIT_CODE);
    }

    status = fit_licenf_prepare_license_update(NULL, &licobj);
    if(status != FIT_STATUS_OK)
    {
        printf("\n\t fit_licenf_prepare_license_update() failed for current license with status %d\n", status);
        return(SAMPLE_FAILURE_EXIT_CODE);
    }

    /*
     * Fetch Fingerprint info from License
     */
    item.type	= FIT_STRING;
    item.tag_id = FIT_FP_TAG_ID;

    status = fit_licenf_find_item(&licobj, FIT_LICENF_LICENSE_SCOPE_GLOBAL, &item_path, FIT_FIND_ITEM_FIRST, &item);
    if(status == FIT_STATUS_OK)
    {
        ret = get_fp_str(item.object.data_ptr, fp_buff);
        printf("\n\t | License Fingerprint : %s |\n", fp_buff);
    }

    memset(&item, 0, sizeof(fit_info_item_t));
    fit_licenf_initialize_scope(&item_path);

    /*
     * Fetch Algorithm ID used from License
     */
    item.type	= FIT_INTEGER;
    item.tag_id = FIT_ALGORITHM_ID_TAG_ID;


    status = fit_licenf_get_license_info(&licobj, FIT_LICENF_LICENSE_SCOPE_GLOBAL, &item);
    //status = fit_licenf_find_item(&licobj, FIT_LICENF_LICENSE_SCOPE_GLOBAL, &item_path, FIT_FIND_ITEM_FIRST, &item);
    if(status == FIT_STATUS_OK)
    {
        printf("\n\t | License Algorithm ID: %lld |\n", item.object.intval);
    }

#if 0
    if (ftr_list)
    {
        printf("\n");
        printf("\n\t\t ----------------------------------------");
        printf("\n\t\t ---|Consume for Specific Feature IDs|---");
        printf("\n\t\t ----------------------------------------");

        i = 0;

        while (i < nof)
        {
            status = do_single_consume(ftr_list[i++], &licobj, NO_PRODUCT_ID_SPECIFIED);
            if (status != FIT_STATUS_OK)
            {
                break;
            }
        }

        free(ftr_list);
    }

    else
        status = do_all_consume(&licobj);
#endif
    printf("\n\t STATUS: %d\n", status);

    if(licptr.data)
        free(licptr.data);

    if(keys_array)
        free(keys_array);

    return status;
}


int license_fit_check_for_specific_feature(uint32_t feature_id)
{

    fit_status_t status = FIT_STATUS_OK;
    fit_pointer_t licptr = {0};

    fit_feature_ctx_t ftr_ctx = {0};
    fit_license_t licobj = {0};
    fit_key_array_t fitkeys = {0};

    fit_info_item_t item;
    fit_pointer_t fp_ptr = {0};
    fit_lic_scope_t item_path;

    int ret = 0;
    int i = 0;
    int nof = 0;

    uint32_t *ftr_list = NULL;
    ftr_list = calloc(1, sizeof(uint32_t));
	ftr_list[0] = feature_id;

    uint8_t *ptr = NULL;

    uint8_t fit_major_ver	 = 0;
    uint8_t fit_minor_ver	 = 0;
    uint8_t fit_revision_ver = 0;


    size_t liclen = 0;

    char *device_id = NULL;
    char dev_id_from_core[FIT_DEVID_MAXLEN] = {0}; 
    char fp[FP_MAX_BUFFER_SIZE] = {0};
    uint32_t fp_length = 0;

    unsigned char fp_buff[FP_MAX_BUFFER_SIZE] = {0};

	fp_length = 0;
    status = fit_licenf_init();
    if(status != FIT_STATUS_OK)
    {
        printf("\n\t fit_licenf_init() failed with status: %d\n", status);
        exit(0);
    }

    (void)fit_memset(&item, 0, sizeof(fit_info_item_t));
    status = fit_licenf_initialize_scope(&item_path);
    if(status != FIT_STATUS_OK)
    {
        printf("\n\t fit_licenf_initialize_scope() failed with status: %d\n", status);
        exit(0);
    }

    setup(); /* initialize UART and LED ports */

    status = fit_licenf_get_version(&fit_major_ver, &fit_minor_ver, &fit_revision_ver);
    if(status != FIT_STATUS_OK)
    {
        printf("\n\t fit_licenf_get_version() failed with status: %d\n", status);
        exit(0);
    }

    printf("\n\t ================================");
    printf("\n\t |   Fit Core Version: %d.%d.%d", fit_major_ver, fit_minor_ver, fit_revision_ver);
    printf("\n\t --------------------------------");
    printf("\n\t |   Runtime Version : %d", FIT_RUN_TIME_VERSION);
    printf("\n\t ================================\n");

    /* Reading the license binary */
    ret = load_license(LIC_PATH, &licptr);
    if(ret != 0)
    {
        printf("\n\t Cannot read file %s ...\n", LIC_PATH);
        return(SAMPLE_FAILURE_EXIT_CODE);
    }

    setKey(FIT_VENDOR_ID);

    if (device_id != NULL)
    {
        if (strlen(device_id) >= FIT_DEVID_MINLEN && strlen(device_id) <= FIT_DEVID_MAXLEN)
        {
            set_device_id(device_id, strlen(device_id));
        }
        else
        {
            printf("\n\t Invalid length for Input Device Id, Valid Length: (4-64)\n");
            return (SAMPLE_FAILURE_EXIT_CODE);
        }
    }

    printf("\n\t | Vendor Keys Used : %s |\n", vendor_global);

    printf("\n\t | Device ID used : %s |\n", fit_dev_id);

    /*
     * Fetch Fingerprint info from device
     */

    fp_length = sizeof(fp);

    // Get the buffer length required for fingerprint.
    status = fit_licenf_get_fingerprint(NULL, &fp_length);

    if ((status == FIT_STATUS_BUFFER_OVERRUN) && (fp_length > 0))
    {
        // if returned length is bigger that buffer
        if( fp_length > FP_MAX_BUFFER_SIZE )
        {
            printf("\n\t Error: Required fingerprint length is greater than available buffer length i.e. %d", FP_MAX_BUFFER_SIZE);
        }
        else
        {
            // Get the fingerprint.
            status = fit_licenf_get_fingerprint(fp, &fp_length);
            if(status == FIT_STATUS_OK)
            {
                printf("\n\t |  Device Fingerprint : %s |", fp);
            }
            else
            {
                printf("\n\t |  fit_licenf_get_fingerprint() failed with status %d |", status);
            }
        }
    }

    memset(&fp_ptr,  0, sizeof(fp_ptr));
    memset(&fp_buff, 0, sizeof(fp_buff));

    status = fit_licenf_construct_license(&licptr, keys_array, &licobj);
    if (status != FIT_STATUS_OK)
    {
        printf("\n\t Failed to contruct License object...");
        return (SAMPLE_FAILURE_EXIT_CODE);
    }

    status = fit_licenf_prepare_license_update(NULL, &licobj);
    if(status != FIT_STATUS_OK)
    {
        printf("\n\t fit_licenf_prepare_license_update() failed for current license with status %d\n", status);
        return(SAMPLE_FAILURE_EXIT_CODE);
    }

    /*
     * Fetch Fingerprint info from License
     */
    item.type	= FIT_STRING;
    item.tag_id = FIT_FP_TAG_ID;

    status = fit_licenf_find_item(&licobj, FIT_LICENF_LICENSE_SCOPE_GLOBAL, &item_path, FIT_FIND_ITEM_FIRST, &item);
    if(status == FIT_STATUS_OK)
    {
        ret = get_fp_str(item.object.data_ptr, fp_buff);
        printf("\n\t | License Fingerprint : %s |\n", fp_buff);
    }

    memset(&item, 0, sizeof(fit_info_item_t));
    fit_licenf_initialize_scope(&item_path);

    /*
     * Fetch Algorithm ID used from License
     */
    item.type	= FIT_INTEGER;
    item.tag_id = FIT_ALGORITHM_ID_TAG_ID;


    status = fit_licenf_get_license_info(&licobj, FIT_LICENF_LICENSE_SCOPE_GLOBAL, &item);
    //status = fit_licenf_find_item(&licobj, FIT_LICENF_LICENSE_SCOPE_GLOBAL, &item_path, FIT_FIND_ITEM_FIRST, &item);
    if(status == FIT_STATUS_OK)
    {
        printf("\n\t | License Algorithm ID: %lld |\n", item.object.intval);
    }

    if (ftr_list)
    {
        printf("\n");
        printf("\n\t\t ----------------------------------------");
        printf("\n\t\t ---|Consume for Specific Feature IDs|---");
        printf("\n\t\t ----------------------------------------");

        i = 0;

        status = do_single_consume(ftr_list[i++], &licobj, NO_PRODUCT_ID_SPECIFIED);

        free(ftr_list);
    }

    printf("\n\t STATUS: %d\n", status);

    if(licptr.data)
        free(licptr.data);

    if(keys_array)
        free(keys_array);

    return status;
}

/****************************************************************************/


int license_rmm_status(void)
{

    fit_status_t status = FIT_STATUS_OK;
    fit_pointer_t licptr = {0};

    fit_feature_ctx_t ftr_ctx = {0};
    fit_license_t licobj = {0};
    fit_key_array_t fitkeys = {0};

    fit_info_item_t item;
    fit_pointer_t fp_ptr = {0};
    fit_lic_scope_t item_path;

    int ret = 0;
    int i = 0;

    uint8_t *ptr = NULL;

    uint8_t fit_major_ver	 = 0;
    uint8_t fit_minor_ver	 = 0;
    uint8_t fit_revision_ver = 0;


    size_t liclen = 0;

    char *device_id = NULL;
    char dev_id_from_core[FIT_DEVID_MAXLEN] = {0}; 
    char fp[FP_MAX_BUFFER_SIZE] = {0};
    uint32_t fp_length = 0;

    unsigned char fp_buff[FP_MAX_BUFFER_SIZE] = {0};

	fp_length = 0;
    status = fit_licenf_init();
    if(status != FIT_STATUS_OK)
    {
        printf("\n\t fit_licenf_init() failed with status: %d\n", status);
        exit(0);
    }

    (void)fit_memset(&item, 0, sizeof(fit_info_item_t));
    status = fit_licenf_initialize_scope(&item_path);
    if(status != FIT_STATUS_OK)
    {
        printf("\n\t fit_licenf_initialize_scope() failed with status: %d\n", status);
        exit(0);
    }

    setup(); /* initialize UART and LED ports */

    status = fit_licenf_get_version(&fit_major_ver, &fit_minor_ver, &fit_revision_ver);
    if(status != FIT_STATUS_OK)
    {
        printf("\n\t fit_licenf_get_version() failed with status: %d\n", status);
        exit(0);
    }

    printf("\n\t ================================");
    printf("\n\t |   Fit Core Version: %d.%d.%d", fit_major_ver, fit_minor_ver, fit_revision_ver);
    printf("\n\t --------------------------------");
    printf("\n\t |   Runtime Version : %d", FIT_RUN_TIME_VERSION);
    printf("\n\t ================================\n");

    /* Reading the license binary */
    ret = load_license(LIC_PATH, &licptr);
    if(ret != 0)
    {
        printf("\n\t Cannot read file %s ...\n", LIC_PATH);
        return(SAMPLE_FAILURE_EXIT_CODE);
    }

    setKey(FIT_VENDOR_ID);

    if (device_id != NULL)
    {
        if (strlen(device_id) >= FIT_DEVID_MINLEN && strlen(device_id) <= FIT_DEVID_MAXLEN)
        {
            set_device_id(device_id, strlen(device_id));
        }
        else
        {
            printf("\n\t Invalid length for Input Device Id, Valid Length: (4-64)\n");
            return (SAMPLE_FAILURE_EXIT_CODE);
        }
    }

    printf("\n\t | Vendor Keys Used : %s |\n", vendor_global);

    printf("\n\t | Device ID used : %s |\n", fit_dev_id);

    /*
     * Fetch Fingerprint info from device
     */

    fp_length = sizeof(fp);

    // Get the buffer length required for fingerprint.
    status = fit_licenf_get_fingerprint(NULL, &fp_length);

    if ((status == FIT_STATUS_BUFFER_OVERRUN) && (fp_length > 0))
    {
        // if returned length is bigger that buffer
        if( fp_length > FP_MAX_BUFFER_SIZE )
        {
            printf("\n\t Error: Required fingerprint length is greater than available buffer length i.e. %d", FP_MAX_BUFFER_SIZE);
        }
        else
        {
            // Get the fingerprint.
            status = fit_licenf_get_fingerprint(fp, &fp_length);
            if(status == FIT_STATUS_OK)
            {
                printf("\n\t |  Device Fingerprint : %s |", fp);
            }
            else
            {
                printf("\n\t |  fit_licenf_get_fingerprint() failed with status %d |", status);
            }
        }
    }

    memset(&fp_ptr,  0, sizeof(fp_ptr));
    memset(&fp_buff, 0, sizeof(fp_buff));

    status = fit_licenf_construct_license(&licptr, keys_array, &licobj);
    if (status != FIT_STATUS_OK)
    {
        printf("\n\t Failed to contruct License object...");
        return (SAMPLE_FAILURE_EXIT_CODE);
    }

    status = fit_licenf_prepare_license_update(NULL, &licobj);
    if(status != FIT_STATUS_OK)
    {
        printf("\n\t fit_licenf_prepare_license_update() failed for current license with status %d\n", status);
        return(SAMPLE_FAILURE_EXIT_CODE);
    }

    /*
     * Fetch Fingerprint info from License
     */
    item.type	= FIT_STRING;
    item.tag_id = FIT_FP_TAG_ID;

    status = fit_licenf_find_item(&licobj, FIT_LICENF_LICENSE_SCOPE_GLOBAL, &item_path, FIT_FIND_ITEM_FIRST, &item);
    if(status == FIT_STATUS_OK)
    {
        ret = get_fp_str(item.object.data_ptr, fp_buff);
        printf("\n\t | License Fingerprint : %s |\n", fp_buff);
    }

    memset(&item, 0, sizeof(fit_info_item_t));
    fit_licenf_initialize_scope(&item_path);

    /*
     * Fetch Algorithm ID used from License
     */
    item.type	= FIT_INTEGER;
    item.tag_id = FIT_ALGORITHM_ID_TAG_ID;


    status = fit_licenf_get_license_info(&licobj, FIT_LICENF_LICENSE_SCOPE_GLOBAL, &item);
    //status = fit_licenf_find_item(&licobj, FIT_LICENF_LICENSE_SCOPE_GLOBAL, &item_path, FIT_FIND_ITEM_FIRST, &item);
    if(status == FIT_STATUS_OK)
    {
        printf("\n\t | License Algorithm ID: %lld |\n", item.object.intval);
    }

	return status;
}

#endif // FIT_BUILD_SAMPLE


