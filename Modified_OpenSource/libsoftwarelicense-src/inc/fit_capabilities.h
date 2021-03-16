/****************************************************************************\
**
** fit_capabilities.h
**
** Set of compile-time options used to know fit core capabilities
**
** Copyright (C) 2017-2018, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_CAPABILITIES_H__
#define __FIT_CAPABILITIES_H__

#include "fit_config.h"
#include "fit_types.h"

/* Constants ****************************************************************/

/**
 * Following bit (1st bit in 64 bit integer) would be set if core supports
 * signing/verification using RSA algorithm
 */
#define FIT_CAPB_RSA_SIGNING            0

/**
 * Following bit (2nd bit in 64 bit integer) would be set if RSA can be presented
 *  in PEM or binary format.
 */
#define FIT_CAPB_PEM                    1

/**
 * Following bit (3rd bit in 64 bit integer) would be set if core supports
 * signing/verification using AES algorithm
 */
#define FIT_CAPB_AES_SIGNING            2

/**
 * Following bit (4th bit in 64 bit integer) would be set if device has clock to 
 * support expiration/time based licenses.
 */
#define FIT_CAPB_CLOCK                  3

/**
 * Following bit (4th bit in 64 bit integer) would be set if device has support
 * for storing persistent elements.
 */
#define FIT_CAPB_USE_PERSISTENCE        4

/**
 * Following bit (5th bit in 64 bit integer) would be set if device has support
 * for getting unique id or something similar to generate unique fingerprints
 */
#define FIT_CAPB_NODE_LOCKING           5


/**
 * Total number of capabilities supported in fit core
 */
#define FIT_CAPB_TOTAL_NUM             FIT_CAPB_NODE_LOCKING


///////////////////////////////

#define FIT_CAPB_ENCODED_LEN        13
#define FIT_CAPB_DECODED_LEN        2

/* Types ********************************************************************/

/** Associate a base 64 encoded core capabilities string with its decoded value 
  * This is used for license generated for LM ver 1.44 or earlier.
  */
typedef struct fit_pre_def_base64_str {
    /** base 64 encoded string */
    char const base64encstr[FIT_CAPB_ENCODED_LEN];
    /** base 64 decoded string */
    char const base64decstr[FIT_CAPB_DECODED_LEN];
} fit_pre_def_base64_str_t;

/* Function Prototypes ******************************************************/

/**
 * This function will check the core capabilities against the requirements of the
 * license string.
 */
fit_status_t fit_check_core_capabilities(fit_pointer_t *license);

/* This function will get the license requirement in the form of string. */
fit_status_t fit_get_lic_capb_str(fit_pointer_t *pdata,
                                  char *string,
                                  uint16_t stringlen,
                                  fit_pointer_t *license);

/* This function is used to know what all capabilities fit core supports. */
fit_status_t fit_get_core_capabilities(uint8_t *capbstr, uint16_t *len);

/* Returns decoded value of encoded core capabilities string. */
fit_status_t get_dec_str_from_enc_str (const uint8_t *enc_str,
                                       uint16_t enc_len,
                                       uint8_t *dec_str,
                                       uint16_t *dec_len);

#endif /* __FIT_CAPABILITIES_H__ */

