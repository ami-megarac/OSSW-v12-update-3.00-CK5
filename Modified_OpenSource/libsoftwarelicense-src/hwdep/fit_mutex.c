/****************************************************************************\
**
** fit_mutex.c
**
** Defines functionality for performing safe multi thread operations.
** 
** Copyright (C) 2018-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

/* Required Includes ********************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#ifdef FIT_USE_MULTI_THREAD

#include "fit_mutex.h"
#include "fit_alloc.h"
#include "fit_debug.h"

/* Function Definitions *****************************************************/

/**
 *
 * \skip fit_mutex_create
 *
 * This function is used for creating a new mutex lock.
 *
 * @param   IO  fit_mutex   \n Pointer at the mutex to be initialized.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_mutex_create(fit_mutex_t *fit_mutex)
{
    return FIT_STATUS_OK;
}

/**
 *
 * fit_mutex_lock
 *
 * Lock a mutex.
 *
 * @param   IN  fit_mutex   \n Pointer at the mutex.
 *
 * @return FIT_TRUE on success; otherwise FIT_FALSE.
 *
 */
fit_boolean_t fit_mutex_lock(fit_mutex_t *fit_mutex)
{
    uint16_t result = 0;

    result = pthread_mutex_lock(fit_mutex); //lint !e732 !e734 !e838
    if (result)
    {
        DBG(FIT_TRACE_CRITICAL, "[fit_mutex_lock]: Failed to acquire mutex lock (!init)\n");
        return FIT_FALSE;
    }

    return FIT_TRUE;
}

/**
 *
 * fit_mutex_unlock
 *
 * Unlock a mutex.
 *
 * @param   IN  fit_mutex   \n Pointer at the mutex to be unlock.
 *
 * @return FIT_TRUE on success; otherwise FIT_FALSE.
 *
 */
fit_boolean_t fit_mutex_unlock(fit_mutex_t *fit_mutex)
{
    if (pthread_mutex_unlock(fit_mutex))
    {
        DBG(FIT_TRACE_CRITICAL, "[fit_mutex_unlock]: Failed to release mutex lock (!init)\n");
        return FIT_FALSE;
    }

    return FIT_TRUE;
}

/**
 *
 * fit_mutex_destroy
 *
 * Destroy a fit_mutex.
 *
 * @param   IN  mutex   \n Pointer at the mutex to be deleted.
 *
 */
void fit_mutex_destroy(fit_mutex_t *fit_mutex)
{
    DBG(FIT_TRACE_INFO, "[fit_mutex_destroy]: Mutex destroyed successfully");
    (void)pthread_mutex_destroy(fit_mutex);
}

#endif // #ifdef FIT_USE_MULTI_THREAD
