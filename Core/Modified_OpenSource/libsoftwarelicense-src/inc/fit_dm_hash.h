/****************************************************************************\
**
** fit_dm_hash.h
**
** Contains declaration for macros, constants and functions used in implementation
** for Davies Meyer hash function.
** 
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_DM_HASH_H__
#define __FIT_DM_HASH_H__

/* Required Includes ********************************************************/

#include "fit_alloc.h"
#include "fit_types.h"

/* Constants ****************************************************************/

/* Types ********************************************************************/

/* Function Prototypes ******************************************************/

/** This function will be used to get the davies meyer hash of the data passed in */
fit_status_t fit_davies_meyer_hash(fit_pointer_t *pdata,
                                   fit_pointer_t *mdata,
                                   uint8_t *dmhash);

/*
 * This function will be used to pad the data to make it’s length be an even
 * multiple of the block size and include a length encoding
 */
void fit_dm_hash_init(uint8_t *pdata, uint32_t *pdatalen, uint32_t msgfulllen);

#endif /* __FIT_DM_HASH_H__ */
