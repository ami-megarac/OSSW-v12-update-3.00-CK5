/****************************************************************************\
**
** fit_aes.h
**
** Contains declaration for macros, constants and functions used in implementation
** for AES algorithm. Sentinel Fit support AES 128 and AES 256.
** 
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_AES_H__
#define __FIT_AES_H__

/* Required Includes ********************************************************/
#include "fit_types.h"
#include "fit_internal.h"

/* Constants ****************************************************************/

/** Key length in bytes [128 bits] */
#define FIT_AES_128_KEY_LENGTH      0x10
/** Key length in bytes [256 bits] */
#define FIT_AES_256_KEY_LENGTH      0x20
/** encrypted output size from AES algorithm */
#define FIT_AES_OUTPUT_DATA_SIZE    0x10
/** The number of columns comprising a state in AES. This is a constant in AES. Value=4 */
#define FIT_AES_NB                  0x4

/* Types ********************************************************************/

typedef struct fit_aes {
/** The number of 32 bit words in a key.*/
    uint16_t Nk;
/** The number of rounds in AES Cipher.*/
    uint16_t Nr;
/** Key size (128 or 256 bits) */
    uint16_t keylen;
} fit_aes_t;

/* Function Prototypes ******************************************************/

/** Performs encryption on given input data and key and produce encrypted data.*/
void fit_aes_encrypt(const fit_aes_t *aes,
                     uint8_t *input,
                     uint8_t *output,
                     const uint8_t *skey,
                     uint8_t *state);
fit_status_t fit_aes_setup(fit_aes_t *aes,
                           const fit_pointer_t *key,
                           uint8_t *skey);
void fit_shift_rows(uint8_t *state);
void fit_mix_columns(uint8_t *state);

#endif /* __FIT_AES_H__ */

