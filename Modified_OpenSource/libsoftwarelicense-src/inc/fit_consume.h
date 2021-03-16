/****************************************************************************\
**
** fit_consume.h
**
** Contains declaration for macros, constants and functions for consuming licenses
** for embedded devices.
**
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_CONSUME_LIC_H__
#define __FIT_CONSUME_LIC_H__

/* Required Includes ********************************************************/
#include "fit_types.h"
#include "fit_parser.h"

/* Constants ****************************************************************/

/* Forward Declarations *****************************************************/

/* Types ********************************************************************/

/* Function Prototypes ******************************************************/

#ifdef FIT_USE_PERSISTENT
/** This function is used get each element of persistent data from the licenses model passed in. */
fit_status_t fit_get_lic_prst_data(fit_pointer_t *licprop,
                                   fit_pointer_t *license,
                                   void *prstdata);
#endif // #ifdef FIT_USE_PERSISTENT

#endif /* __FIT_CONSUME_LIC_H__ */

