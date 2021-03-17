/*****************************************************************************
 *
 * fit_test_persist.c
 *
 * Sentinel Fit persistent storage engine test functions
 *
 * Copyright (C) 2019, SafeNet, Inc. All rights reserved.
 *
 *****************************************************************************/
#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#ifdef FIT_USE_PERSISTENT

#include "fit_persist.h"

#include "string.h"
#include "stdlib.h"

#include "fit_debug.h"
#include "fit_alloc.h"
#include "fit_persistent.h"
#include "fit_internal.h"
#include "fit_mem_read.h"

#include "fit_hw_persist.h"
#include "fit_test_persist.h"

#ifdef FIT_PERSIST_TEST
#define FIT_PERSIST_STATIC
#else
#define FIT_PERSIST_STATIC static
#endif

#ifdef FIT_PERSIST_TEST

static uint32_t calculated_storage = 0;

/**
 * fit_prst_write
 *
 * Write 32bit data in first available storage block
 *
 * @param IN    id      \n  Item id
 *
 * @param IN    data    \n  ptr to item data buffer
 *
 */
fit_status_t fit_prst_write32 ( uint32_t id, uint32_t data)
{
    return fit_prst_write(id, 4, (uint8_t*)&data);
}

/**
 *
 * \skip fit_prst_hw_block_is_empty
 *
 * check if a storage block is empty
 *
 * @param IN    block     \n Block of storage to be checked.
 *
 * @param IN    size      \n Size of block
 *
 * @return 1 if empty or 0 if not
 */
int fit_prst_hw_block_is_empty (uint8_t block, uint32_t size)
{
    uint32_t i;
	uint8_t* addr;
    
    if( persist_data == NULL )
        return 0;
    
    if( block != 1 && block != 2 )
        return 0;
    
    addr = persist_data->storage_block[block-1];

    for (i=0; i < size >> 2; i++) {
        if (*(uint32_t*)addr != 0xFFFFFFFFul) return 0;
        addr += 4;
    }
    return 1;
}



uint32_t fit_prst_storage_size_calc(uint32_t data_size)
{
    uint32_t result;

    if (0 == data_size) {
        result = calculated_storage;
        calculated_storage = 0;
    } else {
        calculated_storage += SIZE_ALIGN(FIT_PRST_ITEM_FIXED_SIZE + data_size);
        result = calculated_storage;
    }
    return result;
}

fit_status_t fit_prst_read32  ( uint32_t id, uint32_t *data)
{
    uint32_t size = 4;
    fit_status_t rc;

    rc = fit_prst_read(id, &size, (uint8_t*)data);
    return rc;/*lint !e438 */
}

/*
fit_status_t fit_prst_write32 ( uint32_t id, uint32_t data)
{
    return fit_prst_write(id, 4, (uint8_t*)&data);
}
*/

void fit_prst_item_dump ( uint8_t block,uint32_t addr )
{
    uint32_t i, data_size=0, len=0;
    char     s[128]={0};
    char     elipsis[10]={0};

    uint32_t  id=0;
    uint32_t  total_size=0;
    uint32_t  count=0;
    uint8_t   data=0;

    (void)fit_prst_hw_read(block,addr, (uint8_t*)&id, 4);
    (void)fit_prst_hw_read(block,addr+4, (uint8_t*)&total_size, 4);
    data_size = total_size - FIT_PRST_ITEM_FIXED_SIZE;

    DBG(FIT_TRACE_PRST, " addr:%08X, id:%08X %10u, size:%4d/%4d, data: ",
                    addr, id, id, total_size, data_size);

    if (id == FIT_PRST_UPDATE_COUNT_REF_ID) {
        (void)fit_prst_hw_read(block,addr+8, (uint8_t*)&count, 4);
        DBG(FIT_TRACE_PRST, "(update counter: %u)\n", count);
        return;
    }

    if (id == 0xFFFFFFFE) {
        (void)fit_prst_hw_read(block,addr+8, (uint8_t*)&count, 4);
        DBG(FIT_TRACE_PRST, "(page counter: %u)\n", count);
        return;
    }

    if (data_size > 0) {
        len = data_size;
        elipsis[0] = '\0';
        if (len > 48) {
            len = 48;
            (void)strcpy(elipsis, "...");
        }
        for (i=0; i<len; i++) {
            (void)fit_prst_hw_read(block,addr+8+i, (uint8_t*)&data, 1);
            // DBG(FIT_TRACE_PRST, "%02X ", data);
            if ((data < ' ') || (data > 127)) {
                s[i] = '.';  /*lint !e661 */ /* len is limited to 48 above */
            } else {
                s[i] = data; /*lint !e661 */ /* len is limited to 48 above */
            }
            s[i+1] = '\0';   /*lint !e661 */ /* len is limited to 48 above */
        }
        DBG(FIT_TRACE_PRST, "%s%s", s, elipsis);

        if (data_size == 4) {
            uint32_t x;
            (void)fit_prst_hw_read(block,addr+8, (uint8_t*)&x, 4);
            DBG(FIT_TRACE_PRST, "  %04X %u", x, x);
        }
        DBG(FIT_TRACE_PRST, "\n");
    } else {
        DBG(FIT_TRACE_PRST, "(empty/deleted)\n");
    }
}

fit_status_t fit_prst_list (void)
{
    uint32_t *list=NULL;
    uint32_t size, c, i;
    uint32_t p = 0;

    DBG(FIT_TRACE_PRST, "=========================================================\n");
    size = prst_storage.block_size / 8;
    list = (uint32_t*)fit_calloc(1, size);

    if (list == NULL) {
        DBG(FIT_TRACE_PRST, "Cannot alloc mem for fit_prst_list\n");
        return FIT_STATUS_INSUFFICIENT_MEMORY;
    }

    c = list_items(list, size);
    qsort (list, c, 4, active_ids_comp);

    DBG(FIT_TRACE_PRST, "list block %u, item count: %u\n", prst_storage.current_block_num, c);

    // list found ids
    for (i=0; i<c; i++) {
        DBG(FIT_TRACE_PRST, "%4u: ", i);
		if (FIT_STATUS_OK == fit_prst_id_find(list[i],&p))
			fit_prst_item_dump(1,p);
    }
    fit_free(list);

    DBG(FIT_TRACE_PRST, "=========================================================\n");
    return FIT_STATUS_OK;
}


/* show status of current_block */
static void fit_prst_status1(void)
{

	uint32_t p, end;
    fit_prst_item_t item;
    fit_prst_header_t header;
    uint32_t used, active;

    DBG(FIT_TRACE_PRST, "Block %d  ", prst_storage.current_block_num);

    if (fit_prst_hw_block_is_empty(prst_storage.current_block_num, prst_storage.block_size)) {
    	DBG(FIT_TRACE_PRST, "  flash is completely empty\n");
        return;
    }

    read_header(prst_storage.current_block_num, &header);
    if (header.id != 0xFFFFFFFE) {
    	DBG(FIT_TRACE_PRST, "  has bad header id\n");
        return;
    }

    DBG(FIT_TRACE_PRST, "  counter: %u ", header.count);

    /* count non-empty items */

	p = 0;
    end = p + prst_storage.block_size - 16;
    used = 0;
    while (p < end) {
        (void)fit_prst_hw_read(prst_storage.current_block_num,p, (uint8_t*)&item, FIT_PRST_ITEM_FIXED_SIZE);
        if (item.id == 0xFFFFFFFF) break;
        if (item.id < 0xFFFFFFFE) used++;

        if (item.total_size < FIT_PRST_ITEM_FIXED_SIZE) {
        	DBG(FIT_TRACE_PRST, "FIT_STATUS_PRST_CORRUPT: total_size < FIT_PERSIST_ITEM_FIXED_SIZE: %08X %u\n", (uint32_t)p, item.total_size);
            break;
        }

        p += SIZE_ALIGN(item.total_size);/*lint !e679 */
    }

    /* count active items */
    active = count_items();

    DBG(FIT_TRACE_PRST, "  used: %u, active: %u, bytes used: %u, free: %u\n", used, active, p , end - p);
}

void fit_prst_status(void)
{
    uint8_t save_page = prst_storage.current_block_num;

    DBG(FIT_TRACE_PRST, "\n-------------------------------------------------------------------\n");

    fit_prst_select(1);
    if (1 == save_page) {
      DBG(FIT_TRACE_PRST, "active ");
    } else {
      DBG(FIT_TRACE_PRST, "       ");
    }
    fit_prst_status1();

    fit_prst_select(2);
    if (2 == save_page) {
      DBG(FIT_TRACE_PRST, "active ");
    } else {
      DBG(FIT_TRACE_PRST, "       ");
    }
    fit_prst_status1();

    fit_prst_select(save_page);
    DBG(FIT_TRACE_PRST, "-------------------------------------------------------------------\n");
}

void fit_prst_dump(void)
{
//    uint8_t *p, *end;
	uint32_t p,end;
    fit_prst_item_t item;
    uint32_t i=0;

    DBG(FIT_TRACE_PRST, "dump block %u:\n", prst_storage.current_block_num);

//    p = fit_prst_current_block;
	p = 0;
    end = p + prst_storage.block_size - 16;

    while (p < end) {
        (void)fit_prst_hw_read(prst_storage.current_block_num,p, (uint8_t*)&item, FIT_PRST_ITEM_FIXED_SIZE);  // just id and total_size
        if (item.id == 0xFFFFFFFF) break;

        DBG(FIT_TRACE_PRST, "%5d: ", i++);
        fit_prst_item_dump(prst_storage.current_block_num,(uint32_t)p);

        if (item.total_size < FIT_PRST_ITEM_FIXED_SIZE) {
            DBG(FIT_TRACE_PRST, "FIT_STATUS_PRST_CORRUPT: total_size < FIT_PERSIST_ITEM_FIXED_SIZE: %08X %u\n", (uint32_t)p, item.total_size);
            break;
        }
        if (item.total_size > FIT_PRST_ITEM_MAX_SIZE) {
            DBG(FIT_TRACE_PRST, "FIT_STATUS_PRST_CORRUPT: total_size > FIT_PERSIST_ITEM_MAX_SIZE: %08X %u\n", (uint32_t)p, item.total_size);
            break;
        }

        p += SIZE_ALIGN(item.total_size);/*lint !e679 */
    }

    // find next free item
    find_free(&p);
    DBG(FIT_TRACE_PRST, "Free: %08X\n", (uint32_t)p);

    i = fit_prst_find_size();
    DBG(FIT_TRACE_PRST, "Used: %d (0x%04X)\n", i, i);
}

fit_status_t fit_prst_page_check (uint8_t block)
{
    uint8_t saveblock = prst_storage.current_block_num;
//    uint8_t *p, *end;
	uint32_t p, end;
    fit_prst_item_t item;
    fit_prst_header_t header;
    uint32_t i=0;
    fit_status_t rc = FIT_STATUS_OK;

    fit_prst_select(block);

    read_header(block, &header);
    if ( (header.id != 0xFFFFFFFE) || (header.total_size != sizeof(fit_prst_header_t)) ) {
        DBG(FIT_TRACE_PRST, "page %d has bad header\n", block);
        rc = FIT_STATUS_PRST_CORRUPT;
        if (fit_prst_hw_block_is_empty(prst_storage.current_block_num, prst_storage.block_size)) {
            rc = FIT_STATUS_PRST_BLOCK_EMPTY;
        }
    }

    if (rc == FIT_STATUS_OK) {
        p = sizeof(fit_prst_header_t);
        end = prst_storage.block_size - 16;

        while (p < end) {
            rc = fit_prst_hw_read(prst_storage.current_block_num,p, (uint8_t*) &item, FIT_PRST_ITEM_FIXED_SIZE);// just id and total_size
            if (rc != FIT_STATUS_OK)
            {
                return rc;
            }
            if (item.id == 0xFFFFFFFF)
                break;

            //DBG(FIT_TRACE_PRST, "%5d: ", i++);
#ifdef FIT_PERSIST_TEST
            fit_prst_item_dump(prst_storage.current_block_num,(uint32_t) p);
#endif

            if (item.total_size < FIT_PRST_ITEM_FIXED_SIZE) {
                DBG(FIT_TRACE_PRST,
                        "FIT_STATUS_PRST_CORRUPT: total_size < FIT_PERSIST_ITEM_FIXED_SIZE: %08X %u\n",
                        (uint32_t )p, item.total_size);
                rc = FIT_STATUS_PRST_CORRUPT;
                break;
            }
            if (item.total_size > FIT_PRST_ITEM_MAX_SIZE) {
                DBG(FIT_TRACE_PRST,
                        "FIT_STATUS_PRST_CORRUPT: total_size > FIT_PERSIST_ITEM_FIXED_SIZE: %08X %u\n",
                        (uint32_t )p, item.total_size);
                rc = FIT_STATUS_PRST_CORRUPT;
                break;
            }

            p += SIZE_ALIGN(item.total_size);/*lint !e679 */
        }
    }

    fit_prst_select(saveblock);

    DBG(FIT_TRACE_PRST, "page %u check: %u %s\n", block, (unsigned int)rc, fit_get_error_str(rc));/*lint !e534*/
    return rc;
}

static fit_status_t error0 (uint8_t block,uint32_t addr)
{
    fit_status_t rc;
    uint32_t     write_buf = 0;

    if (addr < 0x80000) {
    	DBG(FIT_TRACE_PRST, "addr to write %08X is not in allowed range\n", addr);
        return FIT_STATUS_INVALID_PARAM;
    }

    addr+=4; // target the "total_size" field

    DBG(FIT_TRACE_PRST, "writing 0 to %08X ... ", addr);
//    rc = Flash Program(&write_buf, addr, 4);
    rc = fit_prst_hw_write(block,addr,(uint8_t*)&write_buf, 4);
    fit_prst_error_print(rc);

    return rc;
}


static void errornoh(void)
{
    fit_status_t rc;
    uint32_t     write_buf = 0;

//    DBG(FIT_TRACE_PRST, "writing 0 to %08X ... ", (uint32_t)fit_prst_current_block);
//    rc = Flash Program(&write_buf, (uint32_t)current_block, 4);
    rc = fit_prst_hw_write(prst_storage.current_block_num,0,(uint8_t*)&write_buf, 4);
    fit_prst_error_print(rc);
}

void fit_prst_test_corrupt(int error_type, uint32_t addr)
{
    switch (error_type) {
      case 0: (void)error0(prst_storage.current_block_num,addr); break;
      case 1: (void)errornoh(); break;
      default:
    	  DBG(FIT_TRACE_PRST, "error type %d not defined\n");
    }
}
#endif // FIT_PERSIST_TEST
#endif // FIT_USE_PERSISTENT
