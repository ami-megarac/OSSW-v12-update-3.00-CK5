/****************************************************************************\
**
** fit_alloc.h
**
**
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

/* Required Includes ********************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#include <stdlib.h>
#include <string.h>

#include "fit_alloc.h"
#include "fit_debug.h"

#ifndef FIT_DEBUG_HEAP

void *fit_calloc(unsigned int nitems, unsigned int size)
{
    return calloc(nitems, size);
}

void fit_free(void *ptr)
{
    free(ptr);
}

#else

static int alloc_size[1000] = {0};
static void *alloc_ptr[1000] = {NULL};
int  max_alloc = 0;
int  curr_alloc = 0;
int  n_alloc = 0;
int  max_n_alloc = 0;
int  err_alloc = 0;

void fit_reset_alloc(void)
{
    max_alloc = 0;
    max_n_alloc = 0;
    curr_alloc = 0;
    n_alloc = 0;
    err_alloc = 0;
    (void)memset(alloc_size, 0, (size_t)sizeof(alloc_size));
    (void)memset(alloc_ptr, 0, (size_t)sizeof(alloc_ptr));
}

void *fit_calloc(size_t nitems, size_t size)
{
    int i;
    void *p;

    p = calloc(nitems, size);
    if (p) {
        ++n_alloc;
        if (n_alloc > max_n_alloc) {
        	max_n_alloc = n_alloc;
        }
        curr_alloc+=(int)(nitems * size);
        if (curr_alloc > max_alloc) {
        	max_alloc = curr_alloc;
        }
        for (i=0; i<1000; i++) {
            if (alloc_size[i] == 0) {
               alloc_size[i] = (int)(nitems * size);
               alloc_ptr[i] = p;
               break;
            }
        }
    } else {
      ++err_alloc;
    }

    return p;
}

void fit_free (void *ptr)
{
    int i;

    if (ptr==0) {
    	return;
    }

    --n_alloc;
    for (i=0; i<1000; i++) {
      if (alloc_ptr[i] == ptr) {
        curr_alloc-= alloc_size[i];
        alloc_size[i] = 0;
        alloc_ptr[i] = NULL;
        free(ptr);
        return;
      }
    }

    free(ptr);
    ++err_alloc;
}

#endif
