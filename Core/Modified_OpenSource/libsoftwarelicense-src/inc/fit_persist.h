/*****************************************************************************
 *
 * fit_persist.h
 *
 * Sentinel Fit persistent storage engine
 *
 * Copyright (C) 2019, SafeNet, Inc. All rights reserved.
 *
 *****************************************************************************/

#ifndef __FIT_PERSIST_H__
#define __FIT_PERSIST_H__

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif


#ifdef FIT_USE_PERSISTENT


/* Required Includes ********************************************************/
#include "fit_hwdep.h"
#include "fit_hw_persist.h"

/* data types ****************************************************************/
/* align an address to next 4-byte-border */

typedef struct persist_storage{
    uint32_t  block_size ;
	uint8_t  current_block_num;
    uint8_t*  storage_block[2];
}fit_persist_storage_t;

typedef struct fit_prst_header {
    uint32_t id;
    uint32_t total_size;   /* 4 + 4 + 4 = 12 */
    uint32_t count;
} fit_prst_header_t;

typedef struct fit_prst_item {
    uint32_t id;
    uint32_t total_size;
    uint8_t  data[4];
} fit_prst_item_t;

/* Constants ****************************************************************/

#define SIZE_ALIGN(x)              (((x+3)/4)*4)
#define FIT_PRST_ITEM_FIXED_SIZE   (sizeof(uint32_t) + sizeof(uint32_t))
#define FIT_PRST_ITEM_MAX_SIZE     1024
#define FIT_PRST_PG_SWITCH_TRIGGER  128 /* when less that 128 bytes is free we triger page switch */
#define FIT_PRST_HEADER_ID          0xFFFFFFFE

#define FIT_PRST_ELEM_ID_CREATE(key,index) ((((uint32_t)index & 0x000000FF)<<24 ) | ((uint32_t)key & 0x00FFFFFF) )

/*
 * possible flags values for fit_prst_hw_write
 */

#define FIT_PRST_HW_WRITE_FLAGS_NONE        0
#define FIT_PRST_HW_WRITE_FLAGS_NO_CACHE    1

/* Function Prototypes ******************************************************/

fit_status_t  fit_prst_init(void);

fit_status_t  fit_prst_read    ( uint32_t id, uint32_t *size, uint8_t *data );

fit_status_t  fit_prst_write   ( uint32_t id, uint32_t size,  uint8_t *data );

fit_status_t  fit_prst_delete  ( uint32_t id );
#ifdef FIT_USE_UNIT_TESTS
fit_status_t  fit_prst_erase_all (uint32_t *deleted_items);
#endif //FIT_USE_UNIT_TESTS

fit_status_t  fit_prst_cont_id_find    (const uint8_t *cont_id, uint32_t size, uint8_t *index );
void fit_index_and_prstid_get(uint8_t *address, uint8_t *index, uint32_t *prstid);

uint32_t      fit_prst_find_size ( void );

fit_status_t fit_prst_page_switch(uint8_t disable_old_page);

fit_status_t fit_check_prst_init(void);
#if defined(FIT_USE_UNIT_TESTS) || defined(FIT_TEST)
fit_status_t fit_prst_destroy(void);
fit_status_t fit_prst_delete_cont_id(const uint8_t *cont_id);
#endif //FIT_USE_UNIT_TESTS
fit_status_t fit_prst_id_find (uint32_t id,uint32_t* offset);
fit_status_t fit_get_prst_used_size (uint32_t *used_size);

void         fit_prst_select ( uint8_t block );
fit_status_t fit_prst_check (void);
fit_status_t fit_prst_cont_id_index_get(const uint8_t *cont_id,
                                        uint32_t cont_id_len,
                                        uint8_t *cont_id_indx);

fit_status_t fit_prst_lic_cont_id_create(const uint8_t *cont_id,
                                         uint32_t cont_id_len,
                                         uint8_t index);

fit_status_t fit_prst_element_get_seq(uint32_t *itemid, uint8_t *value, uint32_t *len);

/*
 * hardware dependent functions for persistence storage layer
 */
fit_status_t fit_prst_hw_init(fit_persist_storage_t * persist_data);
fit_status_t fit_prst_hw_read (uint8_t block,uint32_t offset, uint8_t *target, uint32_t size );
fit_status_t fit_prst_hw_write(uint8_t block,uint32_t offset, const uint8_t *data, uint32_t size, uint8_t flags);
fit_status_t fit_prst_hw_erase ( uint8_t block );
#ifdef FIT_USE_UNIT_TESTS
fit_status_t fit_prst_hw_destroy(void);
fit_status_t fit_prst_hw_erase_all (void);
#endif
fit_status_t fit_prst_hw_extend_size(uint32_t req_size);

#endif //FIT_USE_PERSISTENT
#endif //__FIT_PERSIST_H__

