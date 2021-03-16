/****************************************************************************\
**
** fit_fingerprint.c
**
** get raw data for fingerprint
**
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fit_types.h"
#include "fit_debug.h"
#include "fit_mem_read.h"
#include "fit_hwdep.h"
#include "fit_internal.h"

char fit_dev_id[FIT_DEVID_MAXLEN] = FIT_DEVICE_ID;
uint16_t fit_dev_id_len = sizeof(FIT_DEVICE_ID) - 1;

/**
 * fit_device_id_get
 *
 * This Function can be used to get unique device id that is associated with a device.
 *
 * @param OUT   rawdata   \n  Pointer to data that will contain the device id.
 *
 * @param IN    rawdata_size    \n  Length of above data.
 *
 * @param OUT   datalen \n  device id len.
 *
 */
fit_status_t fit_device_id_get(uint8_t *rawdata,
                               uint8_t rawdata_size,
                               uint16_t *datalen)
{
    DBG(FIT_TRACE_INFO, "Fetching deviceid: ");
    if (rawdata_size < fit_dev_id_len)
    {
        return FIT_STATUS_INVALID_DEVICE_ID_LEN;
    }

    if (fit_memcpy(rawdata, rawdata_size, (uint8_t *)fit_dev_id, fit_dev_id_len) != 0)
    {
        return FIT_STATUS_BUFFER_OVERRUN;
    }

    *datalen = fit_dev_id_len;

    return FIT_STATUS_OK;
}
