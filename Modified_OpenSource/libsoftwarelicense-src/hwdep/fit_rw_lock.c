/****************************************************************************\
**
** fit_rw_lock.c
**
** Defines functionality for read write lock for fit core.
** 
** Copyright (C) 2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

/* Constants ****************************************************************/

/* Required Includes ********************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#ifdef FIT_USE_MULTI_THREAD

#include "fit_debug.h"
#include "fit_types.h"
#include <pthread.h>

/* Global Data  *************************************************************/

static pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;/*lint !e708 */

/* Forward Declarations *****************************************************/

/* Function Definitions *****************************************************/

/**
 *
 * \skip fit_acquire_shared_lock
 *
 * This function acquires a Read lock on read-write lock
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_acquire_shared_lock(void)
{
    fit_status_t status = FIT_STATUS_OK;

    int retval = -1;

    retval = pthread_rwlock_rdlock(&rwlock);
    if (retval != 0)
    {
        return FIT_STATUS_THREAD_SHARED_LOCK_ERROR;
    }

    return status;
}

/**
 *
 * \skip fit_acquire_exclusive_lock
 *
 * This function acquires a Write lock on read-write lock
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_acquire_exclusive_lock(void)
{
    fit_status_t status = FIT_STATUS_OK;

    int retval = -1;

    retval = pthread_rwlock_wrlock(&rwlock);
    if (retval != 0)
    {
        return FIT_STATUS_THREAD_EXCLUSIVE_LOCK_ERROR;
    }

    return status;
}

/**
 *
 * \skip fit_rw_unlock
 *
 * This function Unlock a read-write lock
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_rw_unlock(void)
{
    fit_status_t status = FIT_STATUS_OK;

    int retval = -1;

    retval = pthread_rwlock_unlock(&rwlock);
    if (retval != 0)
    {
        return FIT_STATUS_THREAD_UNLOCK_ERROR;
    }

    return status;
}

#endif // #ifdef FIT_USE_MULTI_THREAD
