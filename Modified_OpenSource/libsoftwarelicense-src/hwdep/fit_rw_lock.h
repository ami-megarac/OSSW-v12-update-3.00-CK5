/****************************************************************************\
**
** fit_rw_lock.h
**
** Contains declaration for strctures, enum, constants and functions used in implementing
** read write lock in fit core environment
**
** Copyright (C) 2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_RW_LOCK_H__
#define __FIT_RW_LOCK_H__

#ifdef FIT_USE_MULTI_THREAD

#include "fit_config.h"
#include "fit_types.h"

/* Constants ****************************************************************/


/* Types ********************************************************************/


/* Function Prototypes ******************************************************/

fit_status_t fit_acquire_shared_lock(void);
fit_status_t fit_acquire_exclusive_lock(void);
fit_status_t fit_rw_unlock(void);

#endif // #ifdef FIT_USE_MULTI_THREAD

#endif /* __FIT_RW_LOCK_H__ */
