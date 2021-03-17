/****************************************************************************\
**
** fit_version.c
**
** Defines sentinel fit core versioning functionality
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

#include "stddef.h"
#include "fit_types.h"
#include "fit_internal.h"
#include "fit_version.h"

/* Function Definitions *****************************************************/

/**
 *
 * \skip fit_licenf_get_version
 *
 * This function used for getting information about sentinel fit core versioning
 * information.
 *
 * @param OUT   \b  major_version   \n On return it will contain the sentinel fit
 *                                     core major version data.
 *
 * @param OUT   \b  minor_version   \n On return it will contain the sentinel fit
 *                                     core minor version data.
 *
 * @param OUT   \b  revision        \n On return it will contain the sentinel fit
 *                                     core revision data.
 *
 * @return FIT_STATUS_OK on success; otherwise, returns appropriate error code.
 *
 */
fit_status_t fit_licenf_get_version(uint8_t *major_version,
                                    uint8_t *minor_version,
                                    uint8_t *revision)
{
    fit_status_t status = FIT_STATUS_INTERNAL_ERROR;

    /* Validate function parameters */
    if (major_version == NULL) {
        return FIT_STATUS_INVALID_PARAM_1;
    }
    if (minor_version == NULL) {
        return FIT_STATUS_INVALID_PARAM_2;
    }
    if (revision == NULL) {
        return FIT_STATUS_INVALID_PARAM_3;
    }

    /* check the init flag. fit_licenf_init should be called before use of any fit api */
    status = fit_check_init_status();
    if (status != FIT_STATUS_OK)
    {
        return status;
    }

    *major_version = FIT_MAJOR_VERSION;
    *minor_version = FIT_MINOR_VERSION;
    *revision = (uint8_t)FIT_REVISION_VERSION;

    return status;
}
