/*****************************************************************************
 *
 * fit_hw_persist.h
 *
 * Sentinel Fit persistent storage - Hardware dependent part
 * MSVC
 *
 * Copyright (C) 2019, SafeNet, Inc. All rights reserved.
 *
 *****************************************************************************/

#ifndef FIT_HW_PERSIST_H_
#define FIT_HW_PERSIST_H_

/* Required Includes ********************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#include "fit_types.h"
#include "fit_status.h"

#ifdef FIT_USE_PERSISTENT

/* Constants ****************************************************************/

#define FIT_PERSIST_STORAGE_SIZE  (1*1024)

#define FIT_PERSIST_RAM            1
#define FIT_PERSIST_FLASH          2
#define FIT_PERSIST_25LC256        3

//#define FIT_PERSIST_STORAGE FIT_PERSIST_25LC256
#define FIT_PERSIST_STORAGE FIT_PERSIST_RAM
//#define FIT_PERSIST_STORAGE FIT_PERSIST_FLASH


#ifndef FIT_PERSIST_STORAGE
#warning "set FIT_PERSIST_STORAGE to one of the following: FIT_PERSIST_RAM, FIT_PERSIST_FLASH, FIT_PERSIST_25LC256"
#error "FIT_PERSIST_STORAGE not defined"
#endif

#define FIT_PERSIST_FILE_NAME "persist.dat"

#endif /* #ifdef FIT_USE_PERSISTENT */
#endif /* FIT_HW_PERSIST_H_ */

