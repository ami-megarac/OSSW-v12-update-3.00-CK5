/*****************************************************************************
 *
 * fit_test_persist.h
 *
 * Sentinel Fit persistent storage engine
 *
 * Copyright (C) 2017, SafeNet, Inc. All rights reserved.
 *
 *****************************************************************************/

#ifndef __FIT_TEST_PERSIST_H__
#define __FIT_TEST_PERSIST_H__

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#ifdef FIT_USE_PERSISTENT

fit_status_t fit_prst_list (void);
void         fit_prst_dump(void);

fit_status_t  fit_prst_write32 ( uint32_t id, uint32_t data);
fit_status_t  fit_prst_read32  ( uint32_t id, uint32_t *data);
uint32_t      fit_prst_storage_size_calc ( uint32_t data_size );
void         fit_prst_error_print ( fit_status_t rc );
fit_status_t fit_prst_page_check (uint8_t block);
void         fit_prst_active_block_set (void);

void         fit_prst_item_dump ( uint8_t block,uint32_t addr );
void         fit_prst_status(void);
uint32_t     fit_prst_test_fill(void);

void         fit_prst_erase (uint8_t block);

void         fit_prst_test_corrupt(int error_type, uint32_t addr);


#endif // FIT_USE_PERSISTENT
#endif //__FIT_TEST_PERSIST_H__
