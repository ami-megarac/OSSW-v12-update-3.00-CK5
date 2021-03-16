/****************************************************************************\
**
** fit_krypto.c
**
** Contains definition for keys array used in Sentinel Fit for krypto related
** operations.
** 
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#include "fit_keys.h"
#include "fit_types.h"
#include "fit_hwdep.h"

#ifdef FIT_USE_AES_SIGNING

/* Definitions below are used by several fit_demo programs, thus supressing
   lint info 765 "external symbol could be made static"
*/

FIT_PROGMEM_CONST uint16_t aes_alg_guid FIT_PROGMEM = ((uint16_t)FIT_KEY_SCOPE_SIGN << 12 | (uint16_t)FIT_AES_128_OMAC_ALG_ID); /*lint !e765 */
FIT_PROGMEM_CONST fit_algorithm_list_t aes_algorithms FIT_PROGMEM = { /*lint !e765 */
    /** Number of algorithm supported crypto/signing key. */
     1,
     /** GUID having algorithm id and its scope
      * algorithm_id = 12 bits | key scope = 4 bits => algorithm_guid
      * Sentinel Fit supports upto 16 scopes and 4095 algorithms
      */
     {&aes_alg_guid,0,0,0}
};

FIT_PROGMEM_CONST fit_key_data_t aes_data FIT_PROGMEM = { /*lint !e765 */
    /** Key data used for license verification or crypto purposes */
     (uint8_t*)aes_128_omac_sign_key,
     /** Length of above key */
     sizeof(aes_128_omac_sign_key),
     /** List of algorithm that above key will support and its scope */
     (fit_algorithm_list_t *)&aes_algorithms
};

#endif /* FIT_USE_AES_SIGNING */

#ifdef FIT_USE_RSA_SIGNING

const uint16_t rsa_256_key_len = sizeof(rsa_256_sign_pubkey)/sizeof(rsa_256_sign_pubkey[0]); /*lint !e765 */

uint16_t rsa_alg_guid = ((uint16_t)FIT_KEY_SCOPE_SIGN << 12 |         /*lint !e765 */
                         (uint16_t)FIT_RSA_2048_ADM_PKCS_V15_ALG_ID);

FIT_PROGMEM_CONST fit_algorithm_list_t rsa_algorithms FIT_PROGMEM = { /*lint !e765 */
    /** Number of algorithm supported crypto/signing key. */
     1,
     /** GUID having algorithm id and its scope
      * algorithm_id = 12 bits | key scope = 4 bits => algorithm_guid
      * Sentinel Fit supports upto 16 scopes and 4095 algorithms
      */
     {&rsa_alg_guid,0,0,0}
};

FIT_PROGMEM_CONST fit_key_data_t rsa_data FIT_PROGMEM = { /*lint !e765 */
    /** Key data used for license verification or crypto purposes */
    (uint8_t*)rsa_256_sign_pubkey,
    /** Length of above key */
    sizeof(rsa_256_sign_pubkey),
    /** List of algorithm that above key will support and its scope */
    &rsa_algorithms
};

#endif /* FIT_USE_RSA_SIGNING */

#if defined (FIT_USE_AES_SIGNING) && defined (FIT_USE_RSA_SIGNING)

FIT_PROGMEM_CONST fit_key_array_t fit_keys FIT_PROGMEM  = { /*lint !e765 */
    /** pointer to read byte function for reading key part.*/
    (fit_read_byte_callback_t)FIT_READ_KEY_BYTE,
    /** Number of supported keys */
    2,
    /** Array of fit_key_data_t structures */
    {&aes_data,&rsa_data,0},
    /* vendor id corresponding to key data */
    FIT_VENDOR_ID
};

#elif defined (FIT_USE_AES_SIGNING) && !defined (FIT_USE_RSA_SIGNING)

FIT_PROGMEM_CONST fit_key_array_t fit_keys FIT_PROGMEM = { /*lint !e765 */
    /** pointer to read byte function for reading key part.*/
    (fit_read_byte_callback_t) FIT_READ_KEY_BYTE,
    /** Number of supported keys */
    1,
    /** Array of fit_key_data_t structures */
    {&aes_data},
    /* vendor id corresponding to key data */
    FIT_VENDOR_ID
};

#elif defined (FIT_USE_RSA_SIGNING) && !defined (FIT_USE_AES_SIGNING)

FIT_PROGMEM_CONST fit_key_array_t fit_keys FIT_PROGMEM = { /*lint !e765 */
    /** pointer to read byte function for reading key part.*/
    (fit_read_byte_callback_t)FIT_READ_KEY_BYTE,
    /** Number of supported keys */
    1,
    /** Array of fit_key_data_t structures */
    {&rsa_data},
    /* vendor id corresponding to key data */
    FIT_VENDOR_ID
};

#endif // if defined (FIT_USE_AES_SIGNING) && defined (FIT_USE_RSA_SIGNING)

/**
 *
 * \skip fit_get_vendor_id
 *
 * This fn will return the vendor id with which fit core is build.
 *
 * @return vendor id.
 *
 */
uint32_t fit_get_vendor_id(void)
{
    uint32_t vendorid = 0;

    vendorid = (uint32_t)FIT_VENDOR_ID;

    return vendorid;
}
