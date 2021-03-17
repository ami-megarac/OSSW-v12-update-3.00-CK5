/****************************************************************************\
**
** fit_mem_read.c
**
** Defines functionality for memory related operations for Sentinel fit project.
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

#include "fit_mem_read.h"

/* Function Definitions *****************************************************/

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
uint8_t fit_read_byte(const uint8_t *address,
                  fit_read_byte_callback_t clbk_read_byte)
{
    return clbk_read_byte(address);
}

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
uint16_t fit_read_word(const uint8_t *address,
                   fit_read_byte_callback_t clbk_read_byte)
{
    uint16_t x;

    x = (uint16_t)clbk_read_byte(address); 
    x+= (uint16_t)clbk_read_byte(address+1) << 8;
    return x;
}

/**
 *
 * fit_read_dword
 *
 * Reads 4 byte data (1 dword) from data pointer passed in.
 *
 * @param   address --> pointer to data.
 * @param   clbk_read_byte --> function pointer to read byte.
 *
 */
uint32_t fit_read_dword(const uint8_t *address,
                    fit_read_byte_callback_t clbk_read_byte)
{
    uint32_t x;
   
    x = (uint32_t)clbk_read_byte(address); 
    x+= (uint32_t)((uint32_t)(clbk_read_byte(address+1))) << 8; 
    x+= (uint32_t)((uint32_t)(clbk_read_byte(address+2))) << 16; 
    x+= (uint32_t)((uint32_t)(clbk_read_byte(address+3))) << 24;
    return x;
}

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
uint64_t fit_read_ulonglong(const uint8_t *address,
                    fit_read_byte_callback_t clbk_read_byte)
{
    uint64_t x;

    x = (uint64_t)clbk_read_byte(address); 
    x+= (uint64_t)((uint64_t)(clbk_read_byte(address+1))) << 8; 
    x+= (uint64_t)((uint64_t)(clbk_read_byte(address+2))) << 16;
    x+= (uint64_t)((uint64_t)(clbk_read_byte(address+3))) << 24; 
    x+= (uint64_t)((uint64_t)(clbk_read_byte(address+4))) << 32; 
    x+= (uint64_t)((uint64_t)(clbk_read_byte(address+5))) << 40; 
    x+= (uint64_t)((uint64_t)(clbk_read_byte(address+6))) << 48; 
    x+= (uint64_t)((uint64_t)(clbk_read_byte(address+7))) << 56;
    return x;
}

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
fit_status_t fit_probe_address(const uint8_t *address,
							   uint32_t read_length,
							   const fit_pointer_t *range)
{
	if(address >= range->data && ((address + read_length) <= (range->data + range->length)))
	{
		return FIT_STATUS_OK;
	}

	return FIT_STATUS_INVALID_V2C;
}

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
fit_status_t fit_read_word_safe(const uint8_t *address,
        						fit_read_byte_callback_t clbk_read_byte,
								const fit_pointer_t *range,
								uint16_t *out)
{
    fit_status_t status;

    status = fit_probe_address(address, sizeof(uint16_t), range);
	if(status == FIT_STATUS_OK)
	{
		*out = fit_read_word(address, clbk_read_byte);
	}

	return status;
}

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
fit_status_t fit_read_dword_safe(const uint8_t *address,
        						fit_read_byte_callback_t clbk_read_byte,
								const fit_pointer_t *range,
								uint32_t *out)
{
    fit_status_t status;

    status = fit_probe_address(address, sizeof(uint32_t), range);
	if(status == FIT_STATUS_OK)
	{
		*out = fit_read_dword(address, clbk_read_byte);
	}

	return status;
}

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
fit_status_t fit_read_ulonglong_safe(const uint8_t *address,
        						fit_read_byte_callback_t clbk_read_byte,
								const fit_pointer_t *range,
								uint64_t *out)
{
    fit_status_t status;

    status = fit_probe_address(address, sizeof(uint64_t), range);
	if(status == FIT_STATUS_OK)
	{
		*out = fit_read_ulonglong(address, clbk_read_byte);
	}

	return status;
}

