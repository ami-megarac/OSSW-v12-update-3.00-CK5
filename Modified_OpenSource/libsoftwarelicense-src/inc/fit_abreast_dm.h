/****************************************************************************\
**
** fit_abreast_dm.h
**
** Contains declaration for strctures, enum, constants and functions used in
** abreast dm hash implementation. Abreast DM hash is performed over license data
** and internally uses AES 256 for encryption.
**
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_ABREAST_DM_H__
#define __FIT_ABREAST_DM_H__

/* Required Includes ********************************************************/

#include "fit_alloc.h"
#include "fit_types.h"

/* Constants ****************************************************************/
 
/** Abreast DM hash output size */
#define FIT_ABREAST_DM_HASH_SIZE        0x20
#define FIT_ABREAST_DM_BLK_SIZE         0x10
#define FIT_ROUNDS_256BIT_KEY_LENGTH        240

/* Types ********************************************************************/

typedef struct fit_abdm_ctx {
    /* contains abreast dm hash of data passed in */
    uint8_t hash[FIT_ABREAST_DM_HASH_SIZE];
    /* data for which abreast dm hash is to be calculated */
    uint8_t data[FIT_ABREAST_DM_BLK_SIZE];
    /* absolute index in above data buffer */
    uint8_t index;
    /* total length of data for which hash is calculated + hash size*/
    uint32_t length;

} fit_abdm_ctx_t;

/* Function Prototypes ******************************************************/

/** This function will get the abreast dm hash of the data passed in.*/
fit_status_t fit_get_abreastdm_hash(fit_pointer_t *msg, uint8_t *hash);

/* This function will initialize hash data to default initial value. */
void fit_abreastDM_init (fit_abdm_ctx_t* ctx);
/* This function will update the ABreastDM hash for incoming data  */
fit_status_t fit_abreastDM_update(fit_abdm_ctx_t* ctx, uint8_t* data, uint32_t len);
/* This function will perform final update on hash of the data */
fit_status_t fit_abreastDM_final(fit_abdm_ctx_t* ctx);

#endif /* __FIT_ABREAST_DM_H__ */
