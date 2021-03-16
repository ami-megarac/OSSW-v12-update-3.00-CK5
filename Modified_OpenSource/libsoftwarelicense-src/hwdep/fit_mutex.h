/****************************************************************************\
**
** fit_mutex.h
**
** Defines functionality for performing safe multi thread operations.
** 
** Copyright (C) 2018-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

/* Required Includes ********************************************************/

#ifndef __FIT_MUTEX_H__
#define __FIT_MUTEX_H__

#ifdef FIT_USE_MULTI_THREAD

/* Required Includes ********************************************************/
#include "fit_types.h"
#include "fit_hwdep.h"
#include <pthread.h>

/* Constants ****************************************************************/

/* Forward Declarations *****************************************************/

/* Types ********************************************************************/

typedef pthread_mutex_t fit_mutex_t;
#define INITITIAL_MUTEX_VALUE   PTHREAD_MUTEX_INITIALIZER

/* Structure defining safe threading implementation for fit */

/* Function Prototypes ******************************************************/

fit_status_t fit_mutex_create(fit_mutex_t * mutex);
fit_boolean_t fit_mutex_lock(fit_mutex_t* mutex);
fit_boolean_t fit_mutex_unlock(fit_mutex_t* mutex);
void fit_mutex_destroy(fit_mutex_t* mutex);

#endif // #ifdef FIT_USE_MULTI_THREAD
#endif /* __FIT_MUTEX_H__ */
