/****************************************************************************\
**
** fit_get_info.c
**
** Defines functionality for getting license information for embedded devices.
** 
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

/* Required Includes ******************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#ifdef FIT_USE_LEGACY_API
#include "fit_alloc.h"
#include "fit_parser.h"
#include "fit_internal.h"
#include "fit_debug.h"

/* Function Definitions *****************************************************/

/**
 *
 * \skip fit_licenf_get_info
 *
 * This function will parse the license binary passed to it and call the user provided
 * callback function for every field data. User can take any action on receiving
 * license field data like storing values in some structure or can take some action
 * like calling consume license api with feature id etc.
 *
 * @param IN    license     \n Start address of the license in binary format, depending
 *                             on your READ_LICENSE_BYTE definition e.g. in case of RAM,
 *                             this can just be the memory address of the license
 *                             variable 
 *
 * @param IN    callback_fn     \n User provided callback function to be called by fit
 *                                 core.
 *
 * @param IN    context     \n Pointer to user provided data structure.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_licenf_get_info(fit_pointer_t *license,   /*lint !e765*/
                                 fit_get_info_callback callback_fn,
                                 void *context)
{
    fit_op_data_t  getinfo={0};
    fit_status_t         status = FIT_STATUS_UNKNOWN_ERROR;
    DBG(FIT_TRACE_INFO, "[fit_licenf_get_info]: pdata=0x%p \n", license);

    /* Validate parameters */
    if (callback_fn == NULL) {
        return FIT_STATUS_INVALID_PARAM_2;
    }
    if (context == NULL) {
        return FIT_STATUS_INVALID_PARAM_3;
    }

    /* Initialize operational data for get info operation. */
    getinfo.operation = (uint8_t)FIT_OP_GET_LICENSE_INFO_DATA;
    getinfo.parserdata.getinfodata.callback_fn = callback_fn;
    getinfo.parserdata.getinfodata.get_info_data = context;

    /* Parse license data and call the user provided callback fn for each field. */
    status = fit_license_parser(license, (void *)&getinfo);

    if (status != FIT_STATUS_OK) {
        DBG(FIT_TRACE_ERROR, "[fit_licenf_get_info]: return with error code %d \n",
            (unsigned int)status);
        return status;
    }

    return FIT_STATUS_OK;
}
#endif // #ifdef FIT_USE_LEGACY_API
