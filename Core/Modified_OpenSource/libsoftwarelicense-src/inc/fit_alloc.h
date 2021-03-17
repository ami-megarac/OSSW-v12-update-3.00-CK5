/****************************************************************************\
**
** fit_alloc.h
**
**
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_ALLOC_H__
#define __FIT_ALLOC_H__

/* Required Includes ********************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#include <stdlib.h>

#ifdef FIT_DEBUG_HEAP
extern int  max_alloc;
extern int  curr_alloc;
extern int  n_alloc;
extern int  max_n_alloc;
extern int  err_alloc;
#endif

void fit_reset_alloc(void);
void *fit_calloc(size_t nitems, size_t size);
void fit_free(void *ptr);

#endif /* __FIT_ALLOC_H__ */
