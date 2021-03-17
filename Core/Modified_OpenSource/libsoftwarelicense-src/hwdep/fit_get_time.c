/****************************************************************************\
**
** fit_get_time.c
**
** Contains function definitions for time based sentinel fit license
** 
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#include "fit_get_time.h"
#include <time.h>

/**
 *
 * fit_time_get
 *
 * This function returns the current time
 *
 */
uint32_t fit_time_get (void)
{
    uint32_t timeval = (uint32_t)time(NULL);

    return timeval;
}

/**
 *
 * fit_time_set
 *
 * This function set the current unix time for hardware board.
 * Does nothing on Linux because time is handled by the OS
 *
 */
void fit_time_set (uint32_t settime)
{
    (void)settime;
}

