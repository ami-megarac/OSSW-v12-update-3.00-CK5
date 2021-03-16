/****************************************************************************\
**
** fit_memory.c
**
** Contains memory related function declaration for msvc compiler.
** 
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#include "fit_types.h"
#include "fit_hwdep.h"

#ifdef FIT_USE_E2
#ifdef FIT_TEST_VIRTUAL_E2

#ifdef FIT_USE_AES_SIGNING
const unsigned char license_aes[] = {
				   0x00,0x00,0x14,0x01,
                   0x02,0x00,0x00,0x00,0x00,0x00,0x74,0x00,0x00,0x00,
                   0x02,0x00,0x00,0x00,0x00,0x00,0x06,0x00,0x00,0x00,
                   0x02,0x00,0x22,0x02,0x02,0x02,0x60,0x00,0x00,0x00,
                   0x5c,0x00,0x00,0x00,0x02,0x00,0x09,0x00,0x00,0x00,
                   0x52,0x00,0x00,0x00,0x4e,0x00,0x00,0x00,0x02,0x00,
                   0x00,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x8b,0x92,
                   0x00,0x00,0x3c,0x00,0x00,0x00,0x03,0x00,0x0c,0x00,
                   0x01,0x00,0x00,0x00,0x30,0x00,0x00,0x00,0x2c,0x00,
                   0x00,0x00,0x02,0x00,0x0c,0x00,0x00,0x00,0x22,0x00,
                   0x00,0x00,0x02,0x00,0x00,0x00,0x04,0x00,0x18,0x00,
                   0x00,0x00,0x04,0x00,0x00,0x00,0x01,0x00,0x04,0x00,
                   0x04,0x00,0x00,0x00,0x01,0x00,0x06,0x00,0x04,0x00,
                   0x00,0x00,0x01,0x00,0x08,0x00,0x20,0x00,0x00,0x00,
                   0x1c,0x00,0x00,0x00,0x03,0x00,0x03,0x00,0x06,0x00,
                   0x00,0x00,0x10,0x00,0x00,0x00,0x70,0xa0,0x19,0xfa,
                   0x0f,0x9e,0xf1,0x3c,0x65,0x79,0xbb,0x8b,0xe0,0x26,
                   0x1a,0xe9 };
#endif // #ifdef FIT_USE_AES_SIGNING

#ifdef FIT_USE_RSA_SIGNING
const unsigned char license_rsa[] = {
                   0x00,0x00,0x14,0x01,
                   0x02,0x00,0x00,0x00,0x00,0x00,0x6c,0x00,0x00,0x00,
                   0x02,0x00,0x00,0x00,0x00,0x00,0x06,0x00,0x00,0x00,
                   0x02,0x00,0xca,0x00,0x92,0x01,0x58,0x00,0x00,0x00,
                   0x54,0x00,0x00,0x00,0x02,0x00,0x09,0x00,0x00,0x00,
                   0x4a,0x00,0x00,0x00,0x46,0x00,0x00,0x00,0x02,0x00,
                   0x00,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x8b,0x92,
                   0x00,0x00,0x34,0x00,0x00,0x00,0x03,0x00,0x04,0x00,
                   0x01,0x00,0x00,0x00,0x28,0x00,0x00,0x00,0x24,0x00,
                   0x00,0x00,0x02,0x00,0x04,0x00,0x00,0x00,0x1a,0x00,
                   0x00,0x00,0x02,0x00,0x00,0x00,0x04,0x00,0x10,0x00,
                   0x00,0x00,0x04,0x00,0x00,0x00,0x01,0x00,0x04,0x00,
                   0x04,0x00,0x00,0x00,0x01,0x00,0x06,0x00,0x10,0x01,
                   0x00,0x00,0x0c,0x01,0x00,0x00,0x03,0x00,0x03,0x00,
                   0x04,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x43,0x3c,
                   0x03,0x86,0x72,0x4c,0xeb,0x72,0x88,0xcf,0xdb,0x63,
                   0x90,0x67,0xcc,0x38,0x12,0xaf,0xfc,0x89,0xb5,0xac,
                   0x4f,0x1d,0x1e,0x8a,0xde,0x5f,0x0d,0xae,0xf1,0xa2,
                   0x05,0xf6,0xef,0x5a,0xbe,0x53,0x6b,0xb2,0x0f,0xaf,
                   0x05,0xcd,0x10,0x3f,0x34,0x73,0xe5,0xc7,0x6c,0x0e,
                   0xa4,0xf3,0xdd,0x52,0x7c,0xd9,0x2f,0xc6,0x0f,0xd2,
                   0xab,0x95,0x54,0x1e,0x3e,0xf2,0x01,0x26,0x40,0x3f,
                   0x5e,0x8c,0x7d,0xff,0x8b,0x21,0xe2,0xfa,0xab,0xe6,
                   0x33,0x22,0xe0,0x42,0x4e,0x8f,0xe4,0xec,0xbb,0x6e,
                   0x7d,0x68,0xa9,0x64,0x86,0xe7,0x6a,0x41,0xe1,0x51,
                   0x64,0x0e,0x66,0xf4,0x94,0x88,0x44,0x1f,0x73,0x2b,
                   0x17,0xdf,0x9a,0x8e,0x5f,0x5b,0xbb,0x41,0x67,0x15,
                   0x43,0x4a,0xa2,0x0e,0x3e,0xc8,0xc1,0x99,0x62,0xbb,
                   0x3a,0xc4,0x27,0x42,0x10,0x4f,0x4b,0xb0,0x15,0x52,
                   0x06,0x23,0x16,0x51,0x7e,0x1e,0xee,0x5c,0xbd,0xd2,
                   0x0d,0xf9,0x28,0x11,0x26,0xf5,0xfe,0xee,0xed,0xa4,
                   0x56,0x82,0xd8,0xd9,0x64,0xaa,0x78,0xd7,0x02,0x3d,
                   0x3c,0x45,0xec,0x50,0xe0,0xa2,0xa1,0xc2,0xce,0xf5,
                   0xb0,0x98,0x64,0xb4,0x16,0xfe,0x0b,0x7e,0x7d,0xf7,
                   0xfb,0x07,0xd1,0x27,0x9c,0x04,0x3a,0xa9,0xcf,0x9c,
                   0xd9,0xbb,0x6f,0x1d,0x65,0x54,0xf1,0x4f,0x99,0x25,
                   0x85,0x82,0xfc,0x93,0x73,0xf3,0x9d,0xdc,0xd4,0xaa,
                   0xc4,0x6c,0xb9,0xf9,0xd7,0x5f,0xc8,0xba,0xab,0xd4,
                   0x41,0x4d,0x72,0xee,0xb2,0xc1,0x8c,0x20,0x88,0x8c,
                   0xd0,0x01,0x0b,0x92,0x01,0xe9,0xce,0xf3,0x89,0x6a,
                   0x6d,0x17,0x96,0x87 };
#endif // #ifdef FIT_USE_RSA_SIGNING

uint8_t fit_read_eeprom_u8 (const uint8_t *datap)
{
    uint16_t offset = (uint16_t)datap;

#if defined FIT_USE_AES_SIGNING
    return (uint8_t)*(license_aes+offset);
#elif defined FIT_USE_RSA_SIGNING
    return (uint8_t)*(license_rsa+offset);
#endif
}
#endif // #ifdef FIT_USE_E2
#endif // #ifdef FIT_TEST_VIRTUAL_E2

/**
 *
 * fit_read_ram_u8
 *
 * Reads 1 byte data from data pointer passed in.
 *
 * @param   datap --> pointer to data.
 *
 */
uint8_t fit_read_ram_u8 (const uint8_t *datap)
{
    return (uint8_t)*datap;
}

/**
 *
 * fit_read_flash_u8
 *
 * Reads 1 byte data from data pointer passed in.
 *
 * @param   datap --> pointer to data.
 *
 */
uint8_t fit_read_flash_u8 (const uint8_t *datap)
{
    return (uint8_t)*datap;
}

/**
 *
 * fit_read_ram_u16
 *
 * Reads 2 byte data from data pointer passed in.
 *
 * @param   datap --> pointer to data.
 *
 */
uint16_t fit_read_ram_u16 ( uint8_t *datap ) /*lint !e818 !e765*/
{
    uint16_t x = 0;

    x = (uint16_t)fit_read_ram_u8(datap); datap++;
    x+= (uint16_t)fit_read_ram_u8(datap) << 8;
    return x;
}

/**
 *
 * fit_read_ram_u32
 *
 * Reads 4 byte data (1 word) from data pointer passed in.
 *
 * @param   datap --> pointer to data.
 *
 */
uint32_t fit_read_ram_u32 (uint8_t *p) /*lint !e818 !e765*/
{
    uint32_t x;

    x = (uint8_t)*p++;
    x+= (uint32_t)((uint32_t)(fit_read_ram_u8(p))) << 8; p++;
    x+= (uint32_t)((uint32_t)(fit_read_ram_u8(p))) << 16; p++;
    x+= (uint32_t)((uint32_t)(fit_read_ram_u8(p))) << 24;
    return x;
}
