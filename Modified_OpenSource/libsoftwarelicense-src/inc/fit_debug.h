/****************************************************************************\
**
** fit_debug.h
**
** Contains declarations for printing debug messages or sentinel fit core logging.
** 
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_DEBUG_H__
#define __FIT_DEBUG_H__

/* Required Includes ********************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#include <stdarg.h>
#include <stdio.h> 

#include "fit_types.h"

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif /* ifdef __cplusplus__ */

/* Forward Declarations *****************************************************/

/* Function Prototypes ******************************************************/
/*
 * get descriptive string for a sentinel fit status code
 */
EXTERNC const char *fit_get_error_str (fit_status_t st);

#ifdef FIT_USE_COMX
#include "comx.h"
#include "comx_pkt.h"
#endif // FIT_USE_COMX

extern uint32_t fit_trace_flags;

#define FIT_TRACE_OUTPUT        0x00000000u
#define FIT_TRACE_INFO          0x00000001u
#define FIT_TRACE_ERROR         0x00000002u
#define FIT_TRACE_CRITICAL      0x00000004u
#define FIT_TRACE_FATAL         0x00000008u
#define FIT_TRACE_LIC_PARSE     0x00000010u
#define FIT_TRACE_PRST          0x00000020u
#define FIT_TRACE_ALL           0xFFFFFFFFu

/* Below trace flags are specific to comx communication */
/* Don't use them in sentinel fit core debug */
#define FIT_TRACE_RX_TX         0x10000000u
#define FIT_TRACE_ECHO          0x20000000u
#define FIT_TRACE_COMX          0x40000000u

EXTERNC void fit_printf(uint32_t trace_flags, const char *format, ...);
EXTERNC void fit_putc(char c);

#ifdef  FIT_USE_DEBUG_MSG


#ifdef USE_VSPRINTF_P
#define DBG(trace, format, args...) fit_printf(trace, PSTR(format), ## args)
#define PRINT(format, args...) fit_printf(0, PSTR(format), ## args)
#else

#ifdef __linux__
#define DBG(trace, format, ...) fit_printf(trace, format, ##__VA_ARGS__)
#define PRINT printf
#else

#ifdef _MSC_VER
#define DBG(X, ...) { if(fit_trace_flags & X) { \
                    char buf[256+1] = {0}; \
                    sprintf_s(buf, 256, __VA_ARGS__); \
                    printf("%s", buf); } }
#define PRINT printf

#else
#define DBG(trace, format, args...) fit_printf(trace, format, ## args)
#define PRINT(format, args...) fit_printf(0, format, ## args)
#endif /* #ifdef __linux__    */
#endif /* #ifdef _MSC_VER */
#endif /* #ifdef USE_VSPRINTF_P */

#else
#define DBG(...)
#ifdef _MSC_VER
#define PRINT printf
#else

#ifdef USE_VSPRINTF_P
#define PRINT(format, args...) fit_printf(0, PSTR(format), ## args)
#else
#define PRINT(format, args...) fit_printf(0, format, ## args)
#endif /* USE_VSPRINTF_P */

#endif

#endif /* FIT_USE_DEBUG_MSG */
#endif /*__FIT_DEBUG_H__ */
