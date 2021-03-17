/****************************************************************************\
**
** fit_parser.h
**
** Contains declaration for structures, enum, constants and functions used in
** parsing Sentinel fit based licenses.
**
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_PARSER_H__
#define __FIT_PARSER_H__

/* Required Includes ********************************************************/
#include "fit_types.h"

/* Constants ****************************************************************/

#ifdef __cplusplus
extern "C" {
#endif // #ifdef __cplusplus

#define FIT_LIC_VERIFIED_MAGIC_NUM  0x8c6b91D4U

/** size of object pointer */
#define FIT_POBJECT_SIZE            sizeof(uint32_t)
/** size of array pointer */
#define FIT_PARRAY_SIZE             sizeof(uint32_t)
/** size of string pointer */
#define FIT_PSTRING_SIZE            sizeof(uint32_t)
/** size of field in sproto schema.*/
#define FIT_PFIELD_SIZE             sizeof(uint16_t)
/** size of long integer in sproto schema.*/
#define FIT_PLONGINT_SIZE           sizeof(uint64_t)
/** RSA Signature length */
#define FIT_RSA_SIG_SIZE            0x100

/** fingerprint magic - 'fitF' */
#define FIT_FP_MAGIC                0x666D7446
/** Algorithm used for calculate hash for fingerprint data.*/
#define FIT_AES_FP_ALGID            0x1
/** Maximum number of fields in an sproto object.*/
#define FIT_MAX_FIELDS_IN_SPROTO_OBJ    0x40

/* Forward Declarations *****************************************************/

/* Types ********************************************************************/

/* Macro Functions **********************************************************/

/* Function Prototypes ******************************************************/

/** This function will parse the license data passed to it */
fit_status_t fit_license_parser(fit_pointer_t *pdata, void *opdata);

/** Return wire type associated with unique tag identifier. */
void fit_get_field_type_from_tagid (fit_tag_id_t tagid, fit_wire_type_t *wire_type);

/* This function will get the length of passed in sproto object. */
fit_status_t fit_get_object_len(fit_pointer_t* pdata, uint32_t *length, fit_pointer_t *license);

/* Clears all cache information stored */
void fit_clear_cache_data(void);

/* Gets integer data from the pointer to data passed in */
fit_status_t fit_get_integer_data(fit_pointer_t *pdata,
                                  uint32_t length,
                                  uint64_t *integer,
								  fit_pointer_t *license);

/** This function will parse the license data passed to it and fills feature  context data.*/
fit_status_t fit_license_parser_execute(fit_pointer_t *license,
                                        fit_lic_scope_t *lic_scope_ref,
                                        fit_lic_scope_t *lic_path,
                                        uint32_t flags,
                                        void *opdata);


fit_status_t fit_check_license_validity(fit_license_t *license, fit_boolean_t check_prst);

/** This function is used for parse license property present in data passed in and
 *  fill in fit_licensemodel_t structure.
 */
fit_status_t fit_get_lic_prop_data(fit_pointer_t *pdata,
                                   fit_licensemodel_t *licmodel,
                                   fit_pointer_t *license);

#ifdef __cplusplus
}
#endif // #ifdef __cplusplus
#endif /* __FIT_PARSER_H__ */

