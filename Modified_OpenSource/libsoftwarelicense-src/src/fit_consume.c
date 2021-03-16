/****************************************************************************\
**
** fit_consume.c
**
** Defines functionality for consuming licenses for embedded devices.
** 
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#ifdef FIT_USE_SYSTEM_CALLS
#include <string.h>
#endif

#include "fit_consume.h"
#include "fit_internal.h"
#include "fit_hwdep.h"
#include "fit_debug.h"
#include "fit_mem_read.h"
#include "fit_api.h"
#ifdef FIT_USE_PERSISTENT
#include "fit_persist.h"
#endif // #ifdef FIT_USE_PERSISTENT

/* Forward Declarations *****************************************************/

/**
 *
 * \skip fit_getunixtime
 *
 * This function is used for calling hardware dependent callback fn which will
 * return the current time in unix. If callback function is NULL or not defined
 * then return "license expiration not supported" error.
 *
 * @param IO    unixtime    \n Pointer to integer that will contain the current time.
 *
 */
fit_status_t fit_getunixtime(uint32_t *unixtime)
{
    fit_status_t status = FIT_STATUS_UNKNOWN_ERROR;
#ifdef FIT_USE_CLOCK
    uint32_t timeval;

    /* Call hardware board specific time function */
    timeval = FIT_TIME_GET();
    *unixtime = timeval;

    status = FIT_STATUS_OK;
#else
    status = FIT_STATUS_NO_CLOCK_SUPPORT;
#endif

    return status;
}

/**
 *
 * \skip fit_licenf_end_consume_feature
 *
 * This function ends the consumption of a feature referenced by the context
 *
 * @param IN  \b  context   \n  Structure containing the feature context. Used as
 *                              a handle for a feature
 *
 */
fit_status_t fit_licenf_end_consume_feature(fit_feature_ctx_t *context)/*lint !e818 */
{
    fit_status_t status = FIT_STATUS_INTERNAL_ERROR;

    if (context == NULL || context->lic_data.keys == NULL || 
        context->lic_data.license->read_byte == NULL || context->lic_data.keys->read_byte == NULL)
    {
        return FIT_STATUS_INVALID_PARAM_1;
    }
    if (context->lic_verified_marker != FIT_LIC_VERIFIED_MAGIC_NUM )
    {
        return FIT_STATUS_INVALID_FEATURE_CONTEXT;
    }

    /* check the init flag. fit_licenf_init should be called before use of any fit api */
    status = fit_check_init_status();
    if (status != FIT_STATUS_OK)
    {
        return status;
    }

    /* Returns FIT_STATUS_OK for time being, this function wil be used to handle specific
     * cases like user wants to consume a license for say 10 hours and after the time is
     * over it would make the feature handle invalid and for like similar cases.
     */

    return FIT_STATUS_OK;
}

/**
 *
 * \skip fit_internal_start_consume_feature
 *
 * This function starts the consumption of a feature referenced by the context
 *
 * @param IN  \b  context   \n  Structure containing the feature context. Used as
 *                              a handle for a feature
 *
 * @param IN  \b  flags    \n  for future use.
 *
 */
fit_status_t fit_internal_start_consume_feature(fit_feature_ctx_t *context,
                                                uint32_t flags)/*lint !e715 */
{
    fit_status_t status     = FIT_STATUS_UNKNOWN_ERROR;
    uint32_t curtime        = 0;
    fit_licensemodel_t licensemodel = {0};

    if (context == NULL || context->lic_data.keys == NULL || 
        context->lic_data.license->read_byte == NULL || context->lic_data.keys->read_byte == NULL)
    {
        return FIT_STATUS_INVALID_PARAM_1;
    }
    if (context->lic_verified_marker != FIT_LIC_VERIFIED_MAGIC_NUM )
    {
        return FIT_STATUS_INVALID_FEATURE_CONTEXT;
    }

    if (fit_memcpy((uint8_t *)&licensemodel, sizeof(fit_licensemodel_t),
        (uint8_t *)&(context->feature_info.license_model), sizeof(fit_licensemodel_t)) != 0)
    {
        return FIT_STATUS_BUFFER_OVERRUN;
    }

    /* check the init flag. fit_licenf_init should be called before use of any fit api */
    status = fit_check_init_status();
    if (status != FIT_STATUS_OK)
    {
        return status;
    }

    /* Verify the license string against signing key data present in keys array */
    status = fit_check_license_validity(&(context->lic_data), FIT_TRUE);
    if (status != FIT_STATUS_OK)
    {
        return status;
    }

    /* Get the current time in unixtime for time based licenses. */
    if ((licensemodel.startdate != FIT_INVALID_START_DATE) ||
            (licensemodel.enddate != FIT_INVALID_END_DATE))
    {
        status = fit_getunixtime(&curtime);
        /* Return error if board does not support clock */
        // disable lint warning - comes due FIT_TIME_GET macro definition
        if (status != FIT_STATUS_OK) //lint !e774
        {
            return status;
        }
    }

    /*
     * Start date can be present in license string even if license is perpetual one.
     * Validate start date against current time and some past time.
     */
    if (licensemodel.startdate != FIT_INVALID_START_DATE)
    {
        /*
         * Current time should be greater than some past time. Here 1449571095 
         * represent past time i.e. Dec 2015. Time interval on hardware boards
         * increments by 1 in unix time, so an valid current time would be
         * greater than some past time.
         */
        if (curtime <= 1449571095u)
        {
            DBG(FIT_TRACE_ERROR, "No real time clock is present on board\n");
            return FIT_STATUS_RTC_NOT_PRESENT;
        }
        if (curtime < licensemodel.startdate)
        {
            DBG(FIT_TRACE_ERROR, "Curtime %d, license start date %d\n", curtime, licensemodel.startdate);
            return FIT_STATUS_INACTIVE_LICENSE;
        }
    }

    /*
     * Behavior of consume license is different for each type of license.
     * See if license is perpertual.
     */
    DBG(FIT_TRACE_INFO, "Check if license is perpetual one, is_perpetual=%d.\n",
        licensemodel.isperpetual);
    if (licensemodel.isperpetual == (fit_boolean_t)FIT_TRUE)
    {
        /*
         * For perpetual licenses, return status FIT_STATUS_OK if feature id is found
         * else return FIT_STATUS_FEATURE_NOT_FOUND.
         */
        DBG(FIT_TRACE_INFO, "Consume License operation completed succesfully.\n");
        return FIT_STATUS_OK;
    }
    /* Validate the expiration based license data */
    else if (licensemodel.enddate != FIT_INVALID_END_DATE) /* non-zero value means license is expiration based.*/
    {
        /* Validate expiration time agaist current time and start time(if present)
         * Current time should be greater than start date (time)
         */
        if (curtime < licensemodel.startdate)
        {
            DBG(FIT_TRACE_ERROR, "Curtime %d, license start date %d", curtime, licensemodel.startdate);
            return FIT_STATUS_INACTIVE_LICENSE;
        }

        if (licensemodel.enddate < curtime)
        {
            return FIT_STATUS_FEATURE_EXPIRED;
        }
        else
        {
            return FIT_STATUS_OK;
        }
    }

    return FIT_STATUS_INVALID_FEATURE_CONTEXT;
}

/**
 *
 * \skip fit_licenf_start_consume_feature
 *
 * This function starts the consumption of a feature referenced by the context
 *
 * @param IN  \b  context   \n  Structure containing the feature context. Used as
 *                              a handle for a feature
 *
 * @param IN  \b  flags    \n  for future use.
 *
 */
fit_status_t fit_licenf_start_consume_feature(fit_feature_ctx_t *context, uint32_t flags)/*lint !e715 */
{
    fit_status_t status             = FIT_STATUS_UNKNOWN_ERROR;

#ifdef FIT_USE_MULTI_THREAD
    fit_status_t threadret          = FIT_STATUS_UNKNOWN_ERROR;

    /* acquire read lock on read/write lock */
    threadret = FIT_ACQUIRE_SHARED_LOCK();
    if (threadret != FIT_STATUS_OK)
    {
        return threadret;
    }
#endif // #ifdef FIT_USE_MULTI_THREAD

    /* call internal start consume feature api that will do actual api task */
    status = fit_internal_start_consume_feature(context, flags);

#ifdef FIT_USE_MULTI_THREAD
    /* release read lock on read/write lock */
    threadret = FIT_RW_UNLOCK();
    if (threadret != FIT_STATUS_OK)
    {
        return threadret;
    }
#endif // #ifdef FIT_USE_MULTI_THREAD

    return status;
}
