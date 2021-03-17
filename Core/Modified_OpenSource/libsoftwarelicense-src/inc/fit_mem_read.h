/****************************************************************************\
**
** fit_mem_read.h
**
** Contains declaration for memory related functions used in sentinel fit project
**
** memory related fiunctions are used to read data from the license and the 
** encryption key only. The license and the keys are stored in low endian format !
**
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_MEM_READ_H__
#define __FIT_MEM_READ_H__

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

/* Required Includes ********************************************************/

#include "fit_types.h"

/* Constants ****************************************************************/

/* Forward Declarations *****************************************************/

/* Types ********************************************************************/

/* Macro Functions **********************************************************/

/* Function Prototypes ******************************************************/

/**
 *
 * read_byte
 *
 * Reads 1 byte data from data pointer passed in.
 *
 * @param   address --> pointer to data.
 * @param   clbk_read_byte --> function pointer to read byte.
 *
 */
EXTERNC uint8_t fit_read_byte(const uint8_t *address,
                  fit_read_byte_callback_t clbk_read_byte);

/**
 *
 * fit_read_word
 *
 * Reads 2 byte data from data pointer passed in.
 *
 * @param   address --> pointer to data.
 * @param   clbk_read_byte --> function pointer to read byte.
 *
 */
EXTERNC uint16_t fit_read_word(const uint8_t *address,
                   fit_read_byte_callback_t clbk_read_byte);

/**
 *
 * fit_read_dword
 *
 * Reads 4 byte data (1 word) from data pointer passed in.
 *
 * @param   address --> pointer to data.
 * @param   clbk_read_byte --> function pointer to read byte.
 *
 */
EXTERNC uint32_t fit_read_dword(const uint8_t *address,
                    fit_read_byte_callback_t clbk_read_byte);

/**
 *
 * fit_read_ulonglong
 *
 * Reads 8 byte long long integer from data pointer passed in.
 *
 * @param   address --> pointer to data.
 * @param   clbk_read_byte --> function pointer to read byte.
 *
 */
EXTERNC uint64_t fit_read_ulonglong(const uint8_t *address,
                    fit_read_byte_callback_t clbk_read_byte);

/**
 *
 * fit_probe_address
 *
 * Validate if address/byte range is within valid byte range.
 *
 * @param   address --> start of address to be validated.
 * @param   read_length --> range of address to be validated.
 * @param   clbk_read_byte --> function pointer to read byte.
 *
 */
EXTERNC fit_status_t fit_probe_address(const uint8_t *address,
						  	  	  	   uint32_t read_length,
									   const fit_pointer_t *range);

/**
 *
 * fit_read_word_safe
 *
 * Reads 2 byte data from data pointer passed in.
 * Before reading bytes, validation is performed to check
 * if bytes belongs to valid range.
 *
 * @param   address --> pointer to data.
 * @param   clbk_read_byte --> function pointer to read byte.
 * @param   range --> pointer to valid data range.
 * @param   out --> ouput where valid word will be returned.
 *
 */
EXTERNC fit_status_t fit_read_word_safe(const uint8_t *address,
        								fit_read_byte_callback_t clbk_read_byte,
										const fit_pointer_t *range,
										uint16_t *out);

/**
 *
 * fit_read_dword_safe
 *
 * Reads 4 byte data from data pointer passed in.
 * Before reading bytes, validation is performed to check
 * if bytes belongs to valid range.
 *
 * @param   address --> pointer to data.
 * @param   clbk_read_byte --> function pointer to read byte.
 * @param   range --> pointer to valid data range.
 * @param   out --> ouput where valid dword will be returned.
 *
 */
EXTERNC fit_status_t fit_read_dword_safe(const uint8_t *address,
        								 fit_read_byte_callback_t clbk_read_byte,
										 const fit_pointer_t *range,
										 uint32_t *out);

/**
 *
 * fit_read_ulonglong_safe
 *
 * Reads 8 byte data from data pointer passed in.
 * Before reading bytes, validation is performed to check
 * if bytes belongs to valid range.
 *
 * @param   address --> pointer to data.
 * @param   clbk_read_byte --> function pointer to read byte.
 * @param   range --> pointer to valid data range.
 * @param   out --> ouput where valid ulonglong will be returned.
 *
 */
EXTERNC fit_status_t fit_read_ulonglong_safe(const uint8_t *address,
        									 fit_read_byte_callback_t clbk_read_byte,
											 const fit_pointer_t *range,
											 uint64_t *out);

#endif /* __FIT_MEM_READ_H__ */

