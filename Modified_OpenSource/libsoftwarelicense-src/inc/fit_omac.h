/****************************************************************************\
**
** fit_omac.h
**
** Contains declaration for macros, constants and functions used in implementation
** for OMAC algorithm
** 
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_OMAC_H__
#define __FIT_OMAC_H__

/* Required Includes ********************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#ifdef FIT_USE_AES_SIGNING

#include "fit.h"
#include "fit_aes.h"

/* Constants ****************************************************************/

/** OMAC size in bytes [128 bits] */
#define OMAC_SIZE                           0x10
#define OMAC_MAX_CIPHER_BLOCK_SIZE          0x10
#define OMAC_BLOCK_LENGTH                   0x10
#define OMAC_KEY_LENGTH                     0xB0
#define fit_math_min(_a, _b) (((_a) < (_b)) ? (_a) : (_b))

/* Types ********************************************************************/

/** Structure describing OMAC state */
typedef struct omac_state
{
    uint8_t buflen;
    uint8_t blklen;
    uint8_t block[OMAC_MAX_CIPHER_BLOCK_SIZE];
    uint8_t prev[OMAC_MAX_CIPHER_BLOCK_SIZE];
    uint8_t Lu[2][OMAC_MAX_CIPHER_BLOCK_SIZE];
    uint8_t key[OMAC_KEY_LENGTH];
    uint8_t state[4][4];
} omac_state_t;


/* Function Prototypes ******************************************************/

/** Get OMAC of data passed in. OMAC will internally use AES 128 encryption. */
fit_status_t fit_omac_memory(uint16_t blocklength,
                             const fit_pointer_t *key,
                             const fit_pointer_t *indata,
                             uint8_t *out,
                             uint32_t *outlen);

/*
 * This function will be used to validate omac value present in license binary
 * against calculated omac against license data. If caching is enabled then omac
 * value present in license data is compared against cached omac value.
 */
fit_status_t fit_validate_omac_signature(fit_pointer_t* license,
                                         fit_pointer_t* aeskey,
                                         fit_pointer_t *sigdata);


/* fit_verify_aes_key
 *
 * Do a "weak" verification of an AES key by checking:
 *   - key length is one of the supported ones
 *   - key is not all 00 (blank RAM)
 *   - key is not all FF (blank Flash/EEPROM)
*/
 fit_status_t fit_verify_aes_key( fit_pointer_t *aeskey );


#endif // ifdef FIT_USE_AES_SIGNING
#endif // __FIT_OMAC_H__

