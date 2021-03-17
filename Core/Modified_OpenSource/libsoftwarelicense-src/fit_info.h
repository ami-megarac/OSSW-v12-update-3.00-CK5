/****************************************************************************\
**
** fit_demo_getinfo.h
**
** Defines functionality for get info API on sentinel fit based licenses for
** embedded devices.
**
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef FIT_INFO_H_
#define FIT_INFO_H_

#include "fit_types.h"

#ifdef __cplusplus
extern "C" {
#endif

extern uint8_t fit_info_suppress_output; //lint !e759
extern fit_key_array_t fit_keys;

fit_status_t fit_info( fit_pointer_t *licenseData ); //lint !e759

int license_fit_check(void);
int license_fit_check_for_specific_feature(uint32_t);
int licensefile_fit_check(char *filepath);

#ifdef __cplusplus
}
#endif

#endif /* FIT_INFO_H_ */
