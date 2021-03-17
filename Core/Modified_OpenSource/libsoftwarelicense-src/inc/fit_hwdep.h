/****************************************************************************\
**
** fit_hwdep.h
**
** Defines hardware dependent functions.
**
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_HW_DEP_H__
#define __FIT_HW_DEP_H__

/* Required Includes ********************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#include "fit_status.h"
#include "fit_types.h"

#ifdef FIT_USE_MULTI_THREAD
#include "fit_rw_lock.h"
#include "fit_mutex.h"
#ifdef WIN32
#include <windows.h>
#elif defined __linux__
#include <pthread.h>
#endif // #ifdef WIN32
#endif // FIT_USE_MULTI_THREAD

#ifndef _MSC_VER
#include <stdint.h>
#endif

/* Constants ****************************************************************/

/* Max and min length for device id */
#define FIT_DEVID_MINLEN        0x04
#define FIT_DEVID_MAXLEN        0x40

/* Macro Functions **********************************************************/
#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

#define FIT_DEVICE_ID "abcdefghijklmn"

extern char fit_dev_id[FIT_DEVID_MAXLEN];
extern uint16_t fit_dev_id_len;

/*
 * read memory specific defines
 *
 * change values for READ_AESKEY_BYTE and READ_LICENSE_BYTE
 * according to your hardware and the storage type where you 
 * decide to store the license and the aes/rsa key.
 */
#define FIT_READ_BYTE_RAM          fit_read_ram_u8
#define FIT_READ_BYTE_FLASH        fit_read_flash_u8
#define FIT_READ_BYTE_E2           fit_read_eeprom_u8

EXTERNC uint8_t  FIT_READ_BYTE_RAM  (const uint8_t *p);
EXTERNC uint8_t  FIT_READ_BYTE_FLASH  (const uint8_t *p);
EXTERNC uint8_t  FIT_READ_BYTE_E2  (const uint8_t *p);

/*
 * Time specific defines
 */
#ifdef FIT_USE_CLOCK
#define FIT_TIME_GET           fit_time_get
#define FIT_TIME_SET(x)        fit_time_set(x)
#define FIT_TIME_INIT          fit_time_init

EXTERNC uint32_t FIT_TIME_GET(void);
EXTERNC void FIT_TIME_SET(uint32_t settime);
EXTERNC uint32_t FIT_TIME_INIT(void);

#else
#define FIT_TIME_GET        NULL
#define FIT_TIME_SET(x)
#define FIT_TIME_INIT()
#endif

#if defined (FIT_USE_FLASH) && !defined (FIT_USE_E2)
#define FIT_READ_KEY_BYTE       FIT_READ_BYTE_FLASH
#define FIT_READ_LIC_BYTE       FIT_READ_BYTE_FLASH
#elif defined (FIT_USE_E2) && !defined (FIT_USE_FLASH)
#define FIT_READ_KEY_BYTE       FIT_READ_BYTE_E2
#define FIT_READ_LIC_BYTE       FIT_READ_BYTE_E2
#else
#define FIT_READ_KEY_BYTE       FIT_READ_BYTE_RAM
#define FIT_READ_LIC_BYTE       FIT_READ_BYTE_RAM
#endif // if defined (FIT_USE_FLASH) && !defined(FIT_USE_E2)

#ifdef FIT_USE_MULTI_THREAD
/** Mutex (for safe multithreading) related operation */

#define FIT_MUTEX_CREATE        fit_mutex_create
#define FIT_MUTEX_LOCK          fit_mutex_lock
#define FIT_MUTEX_UNLOCK        fit_mutex_unlock
#define FIT_MUTEX_DESTROY       fit_mutex_destroy

#ifdef WIN32
typedef HANDLE fit_mutex_t;
#elif defined __linux__
typedef pthread_mutex_t fit_mutex_t;
#endif // #ifdef WIN32
EXTERNC fit_status_t fit_mutex_create(fit_mutex_t *fit_mutex);
EXTERNC fit_boolean_t fit_mutex_lock(fit_mutex_t *fit_mutex);
EXTERNC fit_boolean_t fit_mutex_unlock(fit_mutex_t *fit_mutex);
EXTERNC void fit_mutex_destroy(fit_mutex_t *fit_mutex);

#define FIT_ACQUIRE_SHARED_LOCK         fit_acquire_shared_lock
#define FIT_ACQUIRE_EXCLUSIVE_LOCK      fit_acquire_exclusive_lock
#define FIT_RW_UNLOCK                   fit_rw_unlock

EXTERNC fit_status_t fit_acquire_shared_lock(void);
EXTERNC fit_status_t fit_acquire_exclusive_lock(void);
EXTERNC fit_status_t fit_rw_unlock(void);

#endif // #ifdef FIT_USE_MULTI_THREAD

/*
 * Node lock specific defines
 */
#ifdef FIT_USE_NODE_LOCKING

/*
 * Fill buffer with board's unique deviceid and its length
 */
#define FIT_DEVICE_ID_GET      fit_device_id_get

EXTERNC fit_status_t FIT_DEVICE_ID_GET(uint8_t *rawdata,
                                       uint8_t rawdata_size,
                                       uint16_t *datalen);
#else
#define FIT_DEVICE_ID_GET        NULL
#endif

/* Types ********************************************************************/

/* Function Prototypes ******************************************************/

/*
 * Initialize UART (used for debug/info output)
 */

#define FIT_UART_INIT fit_uart_init
EXTERNC void FIT_UART_INIT(unsigned int baudrate);

/*
 * write character to console prototype
 *  void FIT_UART_WRITECHAR(char data)
 */
#define FIT_UART_WRITECHAR fit_uart_putc
EXTERNC void FIT_UART_WRITECHAR(unsigned char data);

#define FIT_UART_GETCHAR fit_uart_getchar
EXTERNC unsigned char FIT_UART_GETCHAR(void);


/*
 * Specific board initialization
 */
EXTERNC void fit_board_setup(void);

/*
 * get unixtime
 */
EXTERNC uint32_t fit_time_get(void);

/*
 * Initialize LED pin
 */
EXTERNC void fit_led_init(void);
EXTERNC void fit_led_deinit(void);
/*
 * switch led off/on
 */
EXTERNC void fit_led_off(void);
EXTERNC void fit_led_on(void);


#endif /* __FIT_HW_DEP_H__ */
