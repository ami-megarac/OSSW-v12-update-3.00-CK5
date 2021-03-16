/****************************************************************************\
**
** fit_check_config.h
**
** Sentinel FIT build configuration file. File contains with what feature to 
** build executable binary.
** 
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_CHECK_CONFIG_H__
#define __FIT_CHECK_CONFIG_H__

#if defined(FIT_BUILD_SAMPLE) && (defined(FIT_BUILD_SAMPLE_UNITTEST) || \
                                  defined(FIT_BUILD_TEST) ||            \
                                  defined(FIT_USE_UNIT_TESTS) ||        \
                                  defined(FIT_USE_COMX))
#error "FIT_BUILD_SAMPLE doesn't build with defining, FIT_BUILD_SAMPLE_UNITTEST or \
        FIT_BUILD_TEST or FIT_USE_UNIT_TESTS or FIT_USE_COMX"
#endif

#if defined(FIT_BUILD_SAMPLE_UNITTEST)
#define FIT_USE_UNIT_TESTS
#endif

#if defined(FIT_BUILD_SAMPLE_UNITTEST) && (defined(FIT_BUILD_SAMPLE) || \
                                           defined(FIT_BUILD_TEST) ||   \
                                           defined(FIT_USE_COMX))
#error "FIT_SAMPLE doesn't build with defining, FIT_BUILD_SAMPLE or FIT_BUILD_TEST or FIT_USE_COMX"
#endif

#if defined(FIT_BUILD_TEST) && (defined(FIT_BUILD_SAMPLE) || defined(FIT_BUILD_SAMPLE_UNITTEST))
#error "FIT_BUILD_TEST doesn't build with defining, FIT_BUILD_SAMPLE or FIT_BUILD_SAMPLE_UNITTEST"
#endif

#if defined(FIT_BUILD_TEST)
#define FIT_USE_COMX
#endif


#endif /* __FIT_CHECK_CONFIG_H__ */
