/****************************************************************************\
**
** fit_debug.c
**
** Defines functionality for printing debug messages or fit core logging.
** 
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#include <stdlib.h>

#include "fit_debug.h"
#include "fit_hwdep.h"
#include "fit_internal.h"

/* Global Data **************************************************************/

uint32_t fit_trace_flags = FIT_TRACE_ALL;

/**
 *
 * \skip fit_putc
 *
 * This function will send/print the character to output screen
 *
 * @param IN    \b  c \n character to be send/print to output screen.
 *
 */
void fit_putc(char c)
{
    if (c == '\n') {
        FIT_UART_WRITECHAR('\r');
    }

    FIT_UART_WRITECHAR((unsigned char) c);
}

/**
 *
 * \skip fit_printf
 *
 * This function will print the data to output screen
 *
 * @param IN    \b  trace_flags \n Logging type (Info, error, critical etc)
 *
 * @param IN    \b  format \n Data to be send/print to output screen.
 *
 */

#define FIT_PRINTF_BUFFER_SIZE 256
static char write_buffer[FIT_PRINTF_BUFFER_SIZE];

EXTERNC void fit_printf(uint32_t trace_flags, const char *format, ...)
{
    char *s;
    int len = 0;
    va_list arg;
    
    if ( (fit_trace_flags & trace_flags) || (trace_flags == 0) )
    {
        s = write_buffer;
        va_start (arg, format);
#ifdef USE_VSPRINTF_P
        len = vsnprintf_P (write_buffer, FIT_PRINTF_BUFFER_SIZE, format, arg);
#else
        len = vsnprintf(write_buffer, FIT_PRINTF_BUFFER_SIZE, format, arg);
        if (len < 0) /// return in case of error
            return;
#endif
        va_end (arg);

        if (len > FIT_PRINTF_BUFFER_SIZE) {
            len = FIT_PRINTF_BUFFER_SIZE;
        }

        if(len)
        {
#if defined(FIT_USE_COMX) && !defined(FIT_USE_LINUX)
            comx_pkt_transaction(LWDATA, (uint8_t *) write_buffer, len, NULL);
            (void)s;
#else
            while (*s)
            {
                fit_putc(*s++);
            }
#endif // FIT_USE_COMX
        }
    }
}

/**
 *
 * \skip fit_get_error_str
 *
 * This function gets descriptive string for a fit status code
 *
 * @param IN    \b  st \n Sentinel Fit status code.
 *
 */
const char *fit_get_error_str (fit_status_t st)
{
    const char *p;
    switch (st)
    {
        case FIT_STATUS_OK:                            p = "FIT_STATUS_OK"; break;
        case FIT_STATUS_INSUFFICIENT_MEMORY:           p = "FIT_STATUS_INSUFFICIENT_MEMORY"; break;
        case FIT_STATUS_INVALID_FEATURE_ID:            p = "FIT_STATUS_INVALID_FEATURE_ID"; break;
        case FIT_STATUS_INVALID_V2C:                   p = "FIT_STATUS_INVALID_V2C"; break;
        case FIT_STATUS_ACCESS_DENIED:                 p = "FIT_STATUS_ACCESS_DENIED"; break;
        case FIT_STATUS_INVALID_VALUE:                 p = "FIT_STATUS_INVALID_VALUE"; break;
        case FIT_STATUS_REQ_NOT_SUPPORTED:             p = "FIT_STATUS_REQ_NOT_SUPPORTED"; break;
        case FIT_STATUS_UNKNOWN_ALGORITHM:             p = "FIT_STATUS_UNKNOWN_ALGORITHM"; break;
        case FIT_STATUS_KEY_NOT_PRESENT:			   p = "FIT_STATUS_KEY_NOT_PRESENT"; break;
        case FIT_STATUS_FEATURE_NOT_FOUND:             p = "FIT_STATUS_FEATURE_NOT_FOUND"; break;
        case FIT_STATUS_RESERVED_2:                    p = "FIT_STATUS_RESERVED_2"; break;
        case FIT_STATUS_RESERVED_3:                    p = "FIT_STATUS_RESERVED_3"; break;
        case FIT_STATUS_RESERVED_4:                    p = "FIT_STATUS_RESERVED_4"; break;
        case FIT_STATUS_INVALID_LICGEN_VER:            p = "FIT_STATUS_INVALID_LICGEN_VER"; break;
        case FIT_STATUS_INVALID_SIG_ID:                p = "FIT_STATUS_INVALID_SIG_ID"; break;
        case FIT_STATUS_FEATURE_EXPIRED:               p = "FIT_STATUS_FEATURE_EXPIRED"; break;
        case FIT_STATUS_LIC_CACHING_ERROR:             p = "FIT_STATUS_LIC_CACHING_ERROR"; break;
        case FIT_STATUS_INVALID_PRODUCT:               p = "FIT_STATUS_INVALID_PRODUCT"; break;
        case FIT_STATUS_INVALID_PARAM:                 p = "FIT_STATUS_INVALID_PARAM"; break;
        case FIT_STATUS_INVALID_PARAM_1:               p = "FIT_STATUS_INVALID_PARAM_1"; break;
        case FIT_STATUS_INVALID_PARAM_2:               p = "FIT_STATUS_INVALID_PARAM_2"; break;
        case FIT_STATUS_INVALID_PARAM_3:               p = "FIT_STATUS_INVALID_PARAM_3"; break;
        case FIT_STATUS_INVALID_PARAM_4:               p = "FIT_STATUS_INVALID_PARAM_4"; break;
        case FIT_STATUS_INVALID_PARAM_5:               p = "FIT_STATUS_INVALID_PARAM_5"; break;
        case FIT_STATUS_RESERVED_5:					   p = "FIT_STATUS_RESERVED_5"; break;
        case FIT_STATUS_RESERVED_6:                    p = "FIT_STATUS_RESERVED_6"; break;
        case FIT_STATUS_INVALID_WIRE_TYPE:             p = "FIT_STATUS_INVALID_WIRE_TYPE"; break;
        case FIT_STATUS_INTERNAL_ERROR:                p = "FIT_STATUS_INTERNAL_ERROR"; break;
        case FIT_STATUS_INVALID_KEYSIZE:               p = "FIT_STATUS_INVALID_KEYSIZE"; break;
        case FIT_STATUS_INVALID_VENDOR_ID:             p = "FIT_STATUS_INVALID_VENDOR_ID"; break;
        case FIT_STATUS_INVALID_PRODUCT_ID:            p = "FIT_STATUS_INVALID_PRODUCT_ID"; break;
        case FIT_STATUS_INVALID_CONTAINER_ID:          p = "FIT_STATUS_INVALID_CONTAINER_ID"; break;
        case FIT_STATUS_LIC_FIELD_PRESENT:             p = "FIT_STATUS_LIC_FIELD_PRESENT"; break;
        case FIT_STATUS_INVALID_LICENSE_TYPE:          p = "FIT_STATUS_INVALID_LICENSE_TYPE"; break;
        case FIT_STATUS_LIC_EXP_NOT_SUPP:              p = "FIT_STATUS_LIC_EXP_NOT_SUPP"; break;
        case FIT_STATUS_INVALID_START_DATE:            p = "FIT_STATUS_INVALID_START_DATE"; break;
        case FIT_STATUS_INVALID_END_DATE:              p = "FIT_STATUS_INVALID_END_DATE"; break;
        case FIT_STATUS_INACTIVE_LICENSE:              p = "FIT_STATUS_INACTIVE_LICENSE"; break;
        case FIT_STATUS_RTC_NOT_PRESENT:               p = "FIT_STATUS_RTC_NOT_PRESENT"; break;
        case FIT_STATUS_NO_CLOCK_SUPPORT:              p = "FIT_STATUS_NO_CLOCK_SUPPORT"; break;
        case FIT_STATUS_INVALID_FIELD_LEN:             p = "FIT_STATUS_INVALID_FIELD_LEN"; break;
        case FIT_STATUS_DATA_MISMATCH_ERROR:           p = "FIT_STATUS_DATA_MISMATCH_ERROR"; break;
        case FIT_STATUS_NODE_LOCKING_NOT_SUPP:         p = "FIT_STATUS_NODE_LOCKING_NOT_SUPP"; break;
        case FIT_STATUS_FP_MAGIC_NOT_VALID:            p = "FIT_STATUS_FP_MAGIC_NOT_VALID"; break;
        case FIT_STATUS_UNKNOWN_FP_ALGORITHM:          p = "FIT_STATUS_UNKNOWN_FP_ALGORITHM"; break;
        case FIT_STATUS_FP_MISMATCH_ERROR:             p = "FIT_STATUS_FP_MISMATCH_ERROR"; break;
        case FIT_STATUS_INVALID_DEVICE_ID_LEN:         p = "FIT_STATUS_INVALID_DEVICE_ID_LEN"; break;
        case FIT_STATUS_INVALID_SIGNATURE:             p = "FIT_STATUS_INVALID_SIGNATURE"; break;
        case FIT_STATUS_UNKNOWN_ERROR:                 p = "FIT_STATUS_UNKNOWN_ERROR"; break;
        case FIT_STATUS_NO_RSA_SUPPORT:                p = "FIT_STATUS_NO_RSA_SUPPORT"; break;
        case FIT_STATUS_NO_AES_SUPPORT:                p = "FIT_STATUS_NO_AES_SUPPORT"; break;
        case FIT_STATUS_INVALID_KEY_SCOPE:             p = "FIT_STATUS_INVALID_KEY_SCOPE"; break;    
        case FIT_STATUS_INVALID_SIGNING_KEY:           p = "FIT_STATUS_INVALID_SIGNING_KEY"; break;
        case FIT_STATUS_BUFFER_OVERRUN:                p = "FIT_STATUS_BUFFER_OVERRUN"; break;
        case FIT_STATUS_MAX_LEVEL_EXCEEDS:             p = "FIT_STATUS_MAX_LEVEL_EXCEEDS"; break;
        case FIT_STATUS_LIC_REQ_NOT_SUPP:              p = "FIT_STATUS_LIC_REQ_NOT_SUPP"; break;
        case FIT_STATUS_BASE64_ENCODING_ERROR:         p = "FIT_STATUS_BASE64_ENCODING_ERROR"; break;
        case FIT_STATUS_BASE64_DECODING_ERROR:         p = "FIT_STATUS_BASE64_DECODING_ERROR"; break;
        case FIT_STATUS_INVALID_TAGID:                 p = "FIT_STATUS_INVALID_TAGID"; break;
        case FIT_STATUS_ITEM_NOT_FOUND:                p = "FIT_STATUS_ITEM_NOT_FOUND"; break;
        case FIT_STATUS_CONCUR_LIMIT_EXCEEDS:          p = "FIT_STATUS_CONCUR_LIMIT_EXCEEDS"; break;
        case FIT_STATUS_WIRE_TYPE_MISMATCH:            p = "FIT_STATUS_WIRE_TYPE_MISMATCH"; break;
        case FIT_STATUS_BASE64_INVAL_CHARACTER:        p = "FIT_STATUS_BASE64_INVAL_CHARACTER"; break;
        case FIT_STATUS_PARTIAL_INFO:				   p = "FIT_STATUS_PARTIAL_INFO"; break;
        case FIT_STATUS_LIC_UPDATE_ERROR:              p = "FIT_STATUS_LIC_UPDATE_ERROR"; break;
        case FIT_STATUS_INVALID_FEATURE_CONTEXT:       p = "FIT_STATUS_INVALID_FEATURE_CONTEXT"; break;
        case FIT_STATUS_SKIP_ELEMENT_DATA:             p = "FIT_STATUS_SKIP_ELEMENT_DATA"; break;
        case FIT_STATUS_UNINITIALIZED_MUTEX_ERROR:     p = "FIT_STATUS_UNINITIALIZED_MUTEX_ERROR"; break;
        case FIT_STATUS_LOCK_MUTEX_ERROR:              p = "FIT_STATUS_LOCK_MUTEX_ERROR"; break;
        case FIT_STATUS_UNLOCK_MUTEX_ERROR:            p = "FIT_STATUS_UNLOCK_MUTEX_ERROR"; break;
        case FIT_STATUS_SCOPE_NOT_INITIALIZED:         p = "FIT_STATUS_SCOPE_NOT_INITIALIZED"; break; 
        case FIT_STATUS_INVALID_FIND_NEXT_TAGID:       p = "FIT_STATUS_INVALID_FIND_NEXT_TAGID"; break; 
        case FIT_STATUS_CONTAINER_ID_MISMATCH:         p = "FIT_STATUS_CONTAINER_ID_MISMATCH"; break;
        case FIT_STATUS_FEATURE_ID_FOUND:              p = "FIT_STATUS_FEATURE_ID_FOUND"; break;
        case FIT_STATUS_INVALID_LM_VER:                p = "FIT_STATUS_INVALID_LM_VER"; break;
        case FIT_STATUS_PRST_ID_NOT_FOUND:             p = "FIT_STATUS_PRST_ID_NOT_FOUND"; break;
        case FIT_STATUS_UPDATE_COUNT_MISMATCH:         p = "FIT_STATUS_INVALID_UPDATE_COUNT"; break;
        case FIT_STATUS_PRST_ITEM_TOO_BIG:             p = "FIT_STATUS_PRST_ITEM_TOO_BIG"; break;
        case FIT_STATUS_PRST_CORRUPT:                  p = "FIT_STATUS_PRST_CORRUPT"; break;
        case FIT_STATUS_PRST_INSUFFICIENT_MEMORY:      p = "FIT_STATUS_PRST_INSUFFICIENT_MEMORY"; break;
        case FIT_STATUS_PRST_WRITE_ERROR:              p = "FIT_STATUS_PRST_WRITE_ERROR"; break; 
        case FIT_STATUS_PRST_READ_ERROR:               p = "FIT_STATUS_PRST_READ_ERROR"; break; 
        case FIT_STATUS_PRST_ERASE_ERROR:              p = "FIT_STATUS_PRST_ERASE_ERROR"; break;
        case FIT_STATUS_PRST_BLOCK_EMPTY:              p = "FIT_STATUS_PRST_BLOCK_EMPTY"; break;
        case FIT_STATUS_PRST_ILLEGAL_IN_TRANSACTION:   p = "FIT_STATUS_PRST_ILLEGAL_IN_TRANSACTION"; break;
        case FIT_STATUS_PRST_NOT_IN_TRANSACTION:       p = "FIT_STATUS_PRST_NOT_IN_TRANSACTION"; break;
        case FIT_STATUS_PRST_TRANSACTION_ABORTED:      p = "FIT_STATUS_PRST_TRANSACTION_ABORTED"; break;
        case FIT_STATUS_PRST_MISMATCH_ERROR:           p = "FIT_STATUS_PRST_MISMATCH_ERROR"; break;
        case FIT_STATUS_PRST_NOT_INIT:                 p = "FIT_STATUS_PRST_NOT_INIT"; break;
        case FIT_STATUS_LIC_ALREADY_APPLIED:           p = "FIT_STATUS_LIC_ALREADY_APPLIED"; break;
        case FIT_STATUS_PRST_INSUFFICIENT_STORAGE:     p = "FIT_STATUS_PRST_INSUFFICIENT_STORAGE"; break;
        case FIT_STATUS_PRST_ID_ALREADY_PRESENT:       p = "FIT_STATUS_PRST_ID_ALREADY_PRESENT"; break;
        case FIT_STATUS_THREAD_SHARED_LOCK_ERROR:      p = "FIT_STATUS_THREAD_SHARED_LOCK_ERROR"; break;
        case FIT_STATUS_THREAD_EXCLUSIVE_LOCK_ERROR:   p = "FIT_STATUS_THREAD_EXCLUSIVE_LOCK_ERROR"; break;
        case FIT_STATUS_THREAD_UNLOCK_ERROR:           p = "FIT_STATUS_THREAD_UNLOCK_ERROR"; break;
        case FIT_STATUS_PRST_CANNOT_WRITE:             p = "FIT_STATUS_PRST_CANNOT_WRITE"; break;
        case FIT_STATUS_PRST_NOT_FOUND:                p = "FIT_STATUS_PRST_NOT_FOUND"; break;
        case FIT_STATUS_NOT_INITIALIZED:               p = "FIT_STATUS_NOT_INITIALIZED"; break;

        default:
            p = "UNKNOWN ERROR"; break;
    }
    return p;
}

