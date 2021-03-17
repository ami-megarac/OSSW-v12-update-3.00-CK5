/****************************************************************************\
**
** fit_config.h
**
** This set of compile-time options may be used to enable or disable features
** selectively, and reduce the global memory footprint.
**
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_CONFIG_H__
#define __FIT_CONFIG_H__

/* Constants ****************************************************************/

/**
 * \def FIT_USE_RSA_SIGNING
 *
 * Sentinel fit supports multiple algorithms for license verification  This is used
 * to verify the validity license data using RSA algorithm.
 *
 * Comment if Sentinel Fit core does not use RSA for license signing verification.
 */
#define FIT_USE_RSA_SIGNING

/**
 * \def FIT_USE_PEM
 *
 * With this define, an RSA can be presented in PEM or binary format.
 * Without it, only binary format is accepted

 * Commenting is saves some flash and RAM memory
*/
#define FIT_USE_PEM

/**
 * \def FIT_USE_AES_SIGNING
 *
 * Sentinel fit supports multiple algorithms for license verification  This is used
 * to verify the validity of license data using OMAC algorithm.
 *
 * Comment if Sentinel Fit core does not use OMAC for license signing verification.
 */
#define FIT_USE_AES_SIGNING

/**
 * \def FIT_USE_FLASH
 *
 * Sentinel fit based licenses and aeskey can be stored in FLASH. Enable this
 * macro to test license and aeskey storage in FLASH
 *
 * Comment if user does not want to test license and aes key storage in flash
 */
//#define FIT_USE_FLASH

/**
 * \def FIT_USE_E2
 *
 * Sentinel fit based licenses and aeskey can be stored in EEPROM. Enable this
 * macro to test license and aeskey storage in EEPROM
 *
 * Comment if user does not want to test license and aes key storage in EEPROM
 */
//#define FIT_USE_E2


/**
 * \def FIT_USE_CLOCK
 *
 * To use expiration based licenses enable this macro and implement the function to
 * get the time.
 *
 * Comment if user does not want to use expiration based licenses.
 */
#define FIT_USE_CLOCK

/**
 * \def FIT_USE_PERSISTENT
 *
 * Use this option to enable or disable the use of persistent storage.
 * This option must be enable if user wants to use count, time etc based models.
 *
 * Comment if user does not want storage based model, this option must be disable.
 */
//#define FIT_USE_PERSISTENT

/**
 * \def FIT_USE_NODE_LOCKING
 *
 * Sentinel fit licenses may contain device fingerprint to locked licenses to
 * particular device. To use Node locked licenses enable this macro.
 *
 * Comment if user does not want to use node locked licenses.
 */
#define FIT_USE_NODE_LOCKING

/**
 * \def FIT_USE_SYSTEM_CALLS
 *
 * User can implement his own memory related and system defined functions.
 * However if you wan to use only system defined calls then enable this macro.
 *
 * Comment if user want to use his own implemented system define calls and memory
 * related functions.
 */
//#define FIT_USE_SYSTEM_CALLS

/**
 * \def FIT_USE_MULTI_THREAD
 *
 * Using this option to support multi threading in sentinel fit.
 * 
 * Comment if user does not want to enable multi threading capability, disable this option.
 */
//#define FIT_USE_MULTI_THREAD

/**
 * \def FIT_USE_DEBUG_MSG
 *
 * Using this option debug messages can be enable or disable.
 * If this option is enable the final binary size will be bigger
 *
 * Comment if user does not want debug messages, disable this option.
 */
//#define FIT_USE_DEBUG_MSG

/**
 * \def FIT_PUBKEY_BINARY
 *
 * TODO
 * 
 *
 * Comment .
 */
//#define FIT_PUBKEY_BINARY

/**
 * \def FIT_BUILD_TEST
 *
 * Sentinel fit internel use only, ISV's are requested to never enable this option.
 * If by mistake enable, may result in lot's of build error.
 *
 * Comment FOR INTERNEL USE ONLY.
 */
//#define FIT_BUILD_TEST

/**
 * \def FIT_BUILD_SAMPLE_UNITTEST
 *
 * Sentinel fit sdk contains unit test sample to be used for - how to include and use unit test.
 * User can enable this option to build the unit test sample.
 *
 * Comment if user wants to build the unit test sample, this option must be enable.
 *         Also FIT_USE_UNIT_TESTS must be enabled.
 */
//#define FIT_BUILD_SAMPLE_UNITTEST

/**
 * \def FIT_BUILD_SAMPLE
 *
 * Sentinel fit sdk contains sample to be used for know, how fit API works.
 * User can enable this option to build the sample.
 *
 * Comment if user wants to build the sample, this option must be enable.
 */
#define FIT_BUILD_SAMPLE

#ifdef __AVR__

/*
 * DBG() allows printf-like formatted debug output
 * on AVR8, format string is PROGMEM to save RAM
 */
#include <avr/pgmspace.h>
#define USE_VSPRINTF_P

#undef FIT_USE_RSA_SIGNING
#undef FIT_USE_PEM
#undef FIT_USE_PERSISTENT
#ifdef FIT_USE_FLASH
#define FIT_PROGMEM_CONST const
#define FIT_PROGMEM PROGMEM
#else
#define FIT_PROGMEM_CONST
#define FIT_PROGMEM
#endif // #ifdef FIT_USE_FLASH
#else

#define FIT_DEBUG_HEAP
#define FIT_PROGMEM
#define PROGMEM
#define FIT_PROGMEM_CONST
#ifndef pgm_read_byte
#define pgm_read_byte(x) x
#endif

#endif // ifdef __AVR__

#include "fit_check_config.h"

#endif /* __FIT_CONFIG_H__ */

