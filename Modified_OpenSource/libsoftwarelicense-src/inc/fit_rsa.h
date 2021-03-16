/****************************************************************************\
**
** fit_rsa.h
**
** Contains declaration for macros, constants and functions used in implementation
** for RSA algorithm
** 
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_RSA_H__
#define __FIT_RSA_H__

/* Required Includes ********************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#ifdef FIT_USE_RSA_SIGNING

#include "fit.h"
#include "fit_internal.h"

/* Constants ****************************************************************/

/* Types ********************************************************************/

/* Function Prototypes ******************************************************/

/** This function is used for verify RSA signing and license node locking verification */
fit_status_t fit_verify_rsa_signature(fit_pointer_t *license,
                                      fit_pointer_t *key,
                                      const fit_pointer_t *sigdata,
                                      fit_boolean_t check_cache);

/** This function is to validate rsa signature and hash against rsa public key. */
fit_status_t fit_validate_rsa_signature(const fit_pointer_t *signature,
                                        const uint8_t       *hash,
                                        const fit_pointer_t *key,
                                        uint16_t required_lm_version);

/*
 * This function will be used to check rsa signature value present in license
 * binary and update the hash table with davies meyer hash of license.
 */
fit_status_t fit_lic_do_rsa_verification(fit_pointer_t* license,
                                         fit_pointer_t* rsakey,
                                         const fit_pointer_t *sigdata);

#endif // #ifdef FIT_USE_RSA_SIGNING
#endif /* __FIT_RSA_H__ */

