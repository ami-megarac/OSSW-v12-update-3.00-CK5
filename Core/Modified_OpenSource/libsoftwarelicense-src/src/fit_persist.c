/*****************************************************************************
 *
 * fit_persist.cpp
 *
 * Sentinel Fit persistent storage engine
 *
 * Copyright (C) 2017-2019, SafeNet, Inc. All rights reserved.
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

/* Forward Declarations *****************************************************/

static fit_status_t find_free (uint32_t* p);

static void read_header (uint8_t block, fit_prst_header_t *header);

void fit_prst_select ( uint8_t block );

static uint32_t get_block_count (uint8_t block);
static uint32_t get_next_count (void);
static fit_status_t write_count (void);
static void fit_prst_erase (uint8_t block);
static void fit_prst_active_block_set (void);

fit_status_t fit_prst_init_status = FIT_STATUS_PRST_NOT_INIT;

fit_persist_storage_t prst_storage={0};


#define fit_prst_error_print(x)

/* Function Definitions *****************************************************/


/**
 *
 * \skip fit_prst_cont_id_index_get
 *
 * Gets the index value associated with container id from persistent storage. Each
 * container is assigned a uniique index in persistent storage.
 *
 * @param IN    cont_id     \n Pointer to Container id data.
 *
 * @param IN    cont_id_len \n Length of container id.
 *
 * @param OUT   cont_id_indx    \n On return will contain the index value associated
 *                                 with container id.
 *
 */
fit_status_t fit_prst_cont_id_index_get(const uint8_t *cont_id,/*lint !e818 */
                                        uint32_t cont_id_len,
                                        uint8_t *cont_id_indx)
{
    fit_status_t status = FIT_STATUS_UNKNOWN_ERROR;

    if (cont_id == NULL)
    {
        return FIT_STATUS_INVALID_PARAM_1;
    }

    if (cont_id_len != FIT_CONT_ID_LEN)
    {
        return FIT_STATUS_INVALID_PARAM_2;
    }

    /* get index value of container id in persistent storage */
    status = fit_prst_cont_id_find(cont_id, cont_id_len, cont_id_indx);

    return status;
}

/**
 *
 * \skip fit_prst_lic_cont_id_create
 *
 * Create the entry for container id in persistent storage table.
 *
 * @param IN    cont_id     \n Pointer to Container id data.
 *
 * @param IN    cont_id_len \n Length of container id.
 *
 * @param IN    index    \n index value of conatiner id.
 *
 */
fit_status_t fit_prst_lic_cont_id_create(const uint8_t *cont_id,
                                         uint32_t cont_id_len,
                                         uint8_t index)
{
    fit_status_t status = FIT_STATUS_OK;
    uint32_t prst_elem_id = 0;

    DBG(FIT_TRACE_INFO, "[fit_prst_lic_cont_id_create] \n");

    if (cont_id == NULL)
    {
        return FIT_STATUS_INVALID_PARAM_1;
    }

    if (cont_id_len != FIT_CONT_ID_LEN)
    {
        return FIT_STATUS_INVALID_PARAM_2;
    }

    /* create the persistent element id corresponding to container id */
    prst_elem_id = FIT_PRST_ELEM_ID_CREATE(FIT_PRST_CONT_UUID_REF_ID, index); /*lint !e648 !e835 !e845*/

    status = fit_prst_write(prst_elem_id, FIT_CONT_ID_LEN, (uint8_t*)cont_id);

    return status;
}

/**
 *
 * \skip read_header
 *
 * Read header data from active block.
 *
 * @param IN    block     \n Active block
 *
 * @param OUT   header    \n persistent header data
 *
 */
static void read_header (uint8_t block, fit_prst_header_t *header)
{

    (void)fit_prst_hw_read(block,0, (uint8_t*)header, sizeof(fit_prst_header_t));
}

/**
 *
 * \skip fit_prst_select
 *
 * Based on active block initialize persistent related variables and pointers.
 *
 * @param IN    block     \n Active block
 *
 */
void fit_prst_select ( uint8_t block )
{
    prst_storage.current_block_num = 1;

    if (block == 2)
    {
        prst_storage.current_block_num = 2;
    }
}

/**
 *
 * \skip get_block_count
 *
 * Get count of active block.
 *
 * @param IN    block     \n Active block
 *
 */
static uint32_t get_block_count (uint8_t block)
{
    fit_prst_header_t header;
    uint32_t count = 0;

    read_header(block, &header);

    if (header.id == FIT_PRST_HEADER_ID)
    {
        if (header.total_size == sizeof(fit_prst_header_t)) {
            count = header.count;
        }
    }

    //DBG(FIT_TRACE_PRST, "block %u counter: %u\n", block, count);
    return count;
}
/**
 *
 * \skip get_next_count
 *
 * Gets the next free available data block
 *
 * On return will give next free entry
 *
 */
static uint32_t get_next_count (void)
{
    uint32_t a, b;

    a = get_block_count(1);
    b = get_block_count(2);

    if (a > b)
    {
        return a+1;
    }

    return b+1;
}
/**
 *
 * \skip fit_prst_active_block_set
 *
 * select current persistence data storage block based on the number of active entries in it
 *
 */

static void fit_prst_active_block_set (void)
{
    uint32_t a, b;

    a = get_block_count(1);
    b = get_block_count(2);

    if ( (a == 0) && (b == 0) )
    {
        fit_prst_erase(1);
        fit_prst_select(1);
        a = get_block_count(1);
    }

    if (a == 0)
    {
        fit_prst_select(2);
    }
    else if (b == 0)
    {
        fit_prst_select(1);
    }
    else if (b < a)
    {
        fit_prst_select(2);
    }
    else
    {
        fit_prst_select(1);
    }
}


/**
 *
 * \skip fit_index_and_prstid_get
 *
 * This function will get index (1 byte) and prst id (3 byte) from 4 byte value.
 *
 * @param IN    address \n Pointer to item id (4 byte value)
 *
 * @param OUT   index   \n on return will contain the value of index associated with prst id.
 *
 * @param OUT   prstid  \n on return will contain the value of prst id.
 *
 */
void fit_index_and_prstid_get(uint8_t *address, uint8_t *index, uint32_t *prstid)/*lint !e818 */
{
    uint32_t x;

    x = (uint32_t)((uint32_t)(FIT_READ_BYTE_RAM(address)));         /*lint !e2662 */
    x+= (uint32_t)((uint32_t)(FIT_READ_BYTE_RAM(address+1))) << 8;  /*lint !e2662 */
    x+= (uint32_t)((uint32_t)(FIT_READ_BYTE_RAM(address+2))) << 16; /*lint !e2662 */
 
    /* ref id consists of 3 byte data */
    *prstid = x;

    *index = (uint8_t)((FIT_READ_BYTE_RAM(address + 3)) & 0xFF); /*lint !e2662 */
 

}
/**
 *
 * \skip fit_get_prst_used_size
 *
 * This function returns amount of size used from persistence
 *
 * @param OUT    used_size  number of bytes used
 *
 *
 */
fit_status_t fit_get_prst_used_size (uint32_t *used_size)
{

    fit_prst_item_t item;
    fit_status_t status = FIT_STATUS_OK;

	uint32_t p = 0, end;
    end = p + prst_storage.block_size - 16;

    /*
     * loop from beginning of active block till end of the block and check each entry value
     */
    while (p < end)
    {
        status = fit_prst_hw_read(prst_storage.current_block_num,p, (uint8_t*)&item, FIT_PRST_ITEM_FIXED_SIZE);
        if (status != FIT_STATUS_OK)
        {
            return status;
        }

        if (item.id == 0xFFFFFFFF) break; // we have reached an unused entry
        if (item.total_size < FIT_PRST_ITEM_FIXED_SIZE)
        {
            DBG(FIT_TRACE_PRST, "FIT_STATUS_PRST_CORRUPT: total_size < FIT_PERSIST_ITEM_FIXED_SIZE: %08X %u\n", (uint32_t)p, item.total_size);/*lint !e507 */
            status = FIT_STATUS_PRST_CORRUPT;
            break;
        }

        *used_size += item.total_size;
        p += SIZE_ALIGN(item.total_size);/*lint !e679 */
    }

    return FIT_STATUS_OK;
}

/**
 *
 * \skip fit_check_prst_init
 *
 * This function checks if persistence is initialized
 *
 * @return - FIT_STATUS_OK if initialized or FIT_STATUS_PRST_NOT_INIT if not initialized
 */

fit_status_t fit_check_prst_init(void)
{
    /* check if persistence is initialized */
    if ( prst_storage.block_size == 0 )
    {
        return FIT_STATUS_PRST_NOT_INIT;
    }
    else
    {
        return FIT_STATUS_OK;
    }
}

/**
 *
 * \skip fit_prst_init
 *
 * This function will initialize the persistent storage. Users has to call this
 * fn in order to make persistent storage usable.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_prst_init()
{
    fit_status_t rc;

    DBG(FIT_TRACE_PRST, "[fit_prst_init]\n");
    rc = fit_prst_hw_init(&prst_storage);
    if (rc == FIT_STATUS_OK)
    {
      fit_prst_active_block_set();
    }
    return rc;
}


/**
 * fit_prst_id_find
 *
 * return last instance of id, or NULL it not found or size is 0
 *
 * @param IN  id  id to search for
 *
 * @param OUT offset - offset in sstorage where item was found
 *
 * @return  FIT_STATUS_OK if found or FIT_STATUS_PRST_ID_NOT_FOUND 
 *
 */
fit_status_t fit_prst_id_find (uint32_t id,uint32_t* offset)
{
	uint32_t p = 0, end = 0;
	uint32_t was_found = 0;
	uint32_t found = 0;
    fit_prst_item_t item = {0};

    end = p + prst_storage.block_size - 16;

    //loops untile end of block and read each entry
    while (p < end) {
        if (fit_prst_hw_read(prst_storage.current_block_num,p, (uint8_t*)&item, FIT_PRST_ITEM_FIXED_SIZE)
            != FIT_STATUS_OK)
        {
			*offset = found;
            return FIT_STATUS_OK;
        }

        if (item.id == 0xFFFFFFFF) break; // reached first unused entry
        if (item.total_size < FIT_PRST_ITEM_FIXED_SIZE) {
        	DBG(FIT_TRACE_PRST, "FIT_STATUS_PRST_CORRUPT: total_size < FIT_PERSIST_ITEM_FIXED_SIZE: %08X %u\n", (uint32_t)p, item.total_size);/*lint !e507 */
            break;
        }
        if (item.id == id) { // we have a match
			was_found = 1;
			found = p;
		}
        p += SIZE_ALIGN(item.total_size);/*lint !e679 */
    }

	*offset = found;
	if( !was_found )
		return FIT_STATUS_PRST_ID_NOT_FOUND;

    return FIT_STATUS_OK;
}


/**
 * fit_prst_read
 *
 * Read data of item with specified id
 *
 * @param IN    id      \n  requested id_list
 *
 * @param IO    size   IN: max. size of data buffer, OUT: size of returned data_size
 *
 * @param IN    data   ptr to item data buffer; if NULL, only size is returned
 *
 */
fit_status_t fit_prst_read(uint32_t id, uint32_t *size, uint8_t *data)
{
	uint32_t p = 0;
    uint32_t  found_size;
    fit_prst_item_t item;
    fit_status_t status = FIT_STATUS_OK;

    /* look for id in persistent storage */
    status = fit_prst_id_find(id,&p);
    if (status != FIT_STATUS_OK)
    {
        return FIT_STATUS_PRST_ID_NOT_FOUND;
    }

    // read item at found offset
    status = fit_prst_hw_read( prst_storage.current_block_num,p, (uint8_t*)&item, FIT_PRST_ITEM_FIXED_SIZE);
    if (status != FIT_STATUS_OK)
    {
        return status;
    }

    if (item.total_size <= FIT_PRST_ITEM_FIXED_SIZE) {
        *size = 0;
        return FIT_STATUS_PRST_ID_NOT_FOUND;
    }

    found_size = item.total_size - FIT_PRST_ITEM_FIXED_SIZE;

    if (found_size > *size) {
        *size = found_size;
        return FIT_STATUS_PRST_ITEM_TOO_BIG;
    }
    if (data) {
		status = fit_prst_hw_read(prst_storage.current_block_num, p + FIT_PRST_ITEM_FIXED_SIZE,
            data, found_size );
        if (status != FIT_STATUS_OK)
        {
            return status;
        }
    }

    *size = found_size;

    return FIT_STATUS_OK;
}

/**
 * get_mem_free
 *
 * @return still available free size in persistence storage
 *
 */
// __attribute__ ((__section__(".text.ram")))
static uint32_t get_mem_free (void)
{
	uint32_t p,end;
    fit_prst_item_t item;

	p = 0;
    end = p + prst_storage.block_size - 16;


    while (p < end) {

        if (fit_prst_hw_read(prst_storage.current_block_num,p, (uint8_t*)&item, FIT_PRST_ITEM_FIXED_SIZE) != FIT_STATUS_OK)
        {
            return 0;
        }

        if (item.id == 0xFFFFFFFF) return (uint32_t)(end - p); // empty ID found return value

        if (item.total_size < FIT_PRST_ITEM_FIXED_SIZE) {
        	DBG(FIT_TRACE_PRST, "FIT_STATUS_PRST_CORRUPT: total_size < FIT_PERSIST_ITEM_FIXED_SIZE: %08X %u\n", (uint32_t)p, item.total_size);/*lint !e507 */
            break;
        }
        if (item.total_size >= prst_storage.block_size) {
        	DBG(FIT_TRACE_PRST, "FIT_STATUS_PRST_CORRUPT: total_size > %u: %08X %u\n", prst_storage.block_size, (uint32_t)p, item.total_size);/*lint !e507 */
            break;
        }

        p += SIZE_ALIGN(item.total_size);/*lint !e679 */
    }

    return 0; /* no empty space found */
}

/**
 * fit_prst_error_clean
 *
 * Function cleanup the persistence and set block 2 as current block
 *
 */
static void fit_prst_error_clean(void)
{
    (void)fit_prst_hw_erase(1);
    (void)fit_prst_hw_erase(2);
    fit_prst_select(2);
}

/**
 * fit_prst_check
 *
 * Function checks if persistence is consistent
 *
 */
// __attribute__ ((__section__(".text.ram")))
fit_status_t fit_prst_check (void)
{
	uint32_t p, end;
    fit_prst_item_t item;

    DBG(FIT_TRACE_PRST, "fit_prst_check ");
	p = 0;
    end = p + prst_storage.block_size - 16;

    //loops through all entries in persistence storage
    while (p < end) {
        // read element at offset p
        if (fit_prst_hw_read(prst_storage.current_block_num,p, (uint8_t*)&item, FIT_PRST_ITEM_FIXED_SIZE) != FIT_STATUS_OK)
        {
            DBG(FIT_TRACE_PRST, "FIT_STATUS_PRST_CORRUPT (hw_read != OK)\n");
            return FIT_STATUS_PRST_CORRUPT;
        }
        if (item.id == 0xFFFFFFFF) { //found empty element - return ok
          DBG(FIT_TRACE_PRST, "OK\n");
          return FIT_STATUS_OK;
        }

        if (item.total_size < FIT_PRST_ITEM_FIXED_SIZE) { 
        	DBG(FIT_TRACE_PRST, "FIT_STATUS_PRST_CORRUPT: total_size < FIT_PERSIST_ITEM_FIXED_SIZE: %08X %u\n", (uint32_t)p, item.total_size);/*lint !e507 */
            fit_prst_error_clean();
            return FIT_STATUS_PRST_CORRUPT;
        }
        if (item.total_size >= prst_storage.block_size) {
        	DBG(FIT_TRACE_PRST, "FIT_STATUS_PRST_CORRUPT: total_size > %u: %08X %u\n", prst_storage.block_size, (uint32_t)p, item.total_size);/*lint !e507 */
            fit_prst_error_clean();
            return FIT_STATUS_PRST_CORRUPT;
        }

        p += SIZE_ALIGN(item.total_size);/*lint !e679 */
    }

    DBG(FIT_TRACE_PRST, "OK\n");
    return FIT_STATUS_OK;
}

/**
 * fit_prst_write_prim
 *
 * Write data of item with specified id in first available storage block
 *
 * @param IN    id      \n  Item id
 *
 * @param IN    size    \n  size of data buffer
 *
 * @param IN    data    \n  ptr to item data buffer
 *
 * @param IN    flags     \n if FIT_PRST_HW_WRITE_FLAGS_NO_CACHE write uffer to file in case storage is on file
 *                           if FIT_PRST_HW_WRITE_FLAGS_NONE - data is written in memory storage only
 */
static fit_status_t fit_prst_write_prim(uint32_t id, uint32_t size, uint8_t *data, uint8_t flags)
{
    fit_status_t     rc = FIT_STATUS_OK;
    uint32_t         p = 0;
    uint32_t         write_size, free_mem;
    uint32_t         length;
    uint8_t          *write_buf = NULL;
    fit_prst_item_t  *item=NULL;
    fit_prst_header_t header={0};

    DBG(FIT_TRACE_PRST, "fit_prst_write_prim(id=%08X,...)\n", id);

    /* check current block and erase if necessary */
    read_header (prst_storage.current_block_num, &header);
    if ( (FIT_PRST_HEADER_ID != header.id) || (sizeof(fit_prst_header_t) != header.total_size) ) {
        DBG(FIT_TRACE_PRST, "block %u header not found - erasing\n", prst_storage.current_block_num);
        fit_prst_erase(prst_storage.current_block_num);
    }

    /* we check if we need to switch pages? */
    free_mem = get_mem_free();

    if (free_mem < size + FIT_PRST_PG_SWITCH_TRIGGER ) { /* check if we need to do a page switch */
        DBG(FIT_TRACE_PRST, "Low memory (%u bytes) - Switching pages\n", free_mem);
        rc = fit_prst_page_switch(1);
        if (rc)
        {
            fit_prst_error_print(rc);
        }
    }

    /* find free slot for new item */
    rc  = find_free(&p);
    if ( rc != FIT_STATUS_OK) {
        rc = FIT_STATUS_PRST_INSUFFICIENT_MEMORY;
        goto bail; /*lint !e801 */
    }
    DBG(FIT_TRACE_PRST, "Free slot: %08X, ", (uint32_t)p);/*lint !e507 */

    /* buffer for write data (must be ONE block */
    length = size + FIT_PRST_ITEM_FIXED_SIZE;
    write_size = SIZE_ALIGN(length);
    write_buf = (uint8_t*)fit_calloc(1, write_size);
    if (write_buf == NULL) {
        rc = FIT_STATUS_INSUFFICIENT_MEMORY;
        goto bail;/*lint !e801 */
    }

    /* construct item */
    (void)fit_memset(write_buf, 0, write_size);
    item = (fit_prst_item_t*)write_buf; /*lint !e2445 !e826 */
    item->id         = id;
    item->total_size = size + FIT_PRST_ITEM_FIXED_SIZE;

    if (fit_memcpy(item->data, size, data, size) != 0)
    {
        rc = FIT_STATUS_BUFFER_OVERRUN;
        goto bail;/*lint !e801 */
    }

    DBG(FIT_TRACE_PRST, "total_size %u, write_size %u \n", item->total_size, write_size);

    /* write item */
    rc = fit_prst_hw_write(prst_storage.current_block_num,p,write_buf,write_size, flags); /*lint !e507 */
    if (rc) {
      rc = FIT_STATUS_PRST_WRITE_ERROR;
      goto bail;/*lint !e801 */
    }

bail:
    if (write_buf)
    {
        fit_free(write_buf);
    }
    if (rc)
    {
        fit_prst_error_print(rc);
    }

    return rc;
}

/**
 * fit_prst_write
 *
 * Write data of item with specified id in first available storage block
 *
 * @param IN    id      \n  Item id
 *
 * @param IN    size    \n  size of data buffer
 *
 * @param IN    data    \n  ptr to item data buffer
 *
 */
fit_status_t fit_prst_write(uint32_t id, uint32_t size, uint8_t *data)
{
  fit_status_t rc;

  DBG(FIT_TRACE_PRST, "fit_prst_write(id=0x%08X,%u...)\n", id, size);

  rc = fit_prst_write_prim(id, size, data, FIT_PRST_HW_WRITE_FLAGS_NO_CACHE);
  if (rc != FIT_STATUS_OK)
      return rc;

  return rc;
}

/**
 *
 * \skip fit_prst_cont_id_find
 *
 * This function will look for container id in the persistent storage. If container
 * is present in persistent storage then function will return index corresponding to
 * container id. If container is not present in persistent storage then function will
 * return next free index available in persistent storage.
 *
 * @param IN    cont_id     \n Pointer to Container id data that to be looked in persistent
 *                             storage.
 *
 * @param IN    size        \n Length of container id.
 *
 * @param OUT   index       \n On return will contain the index corresponding to
 *                             container id or next free index.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t  fit_prst_cont_id_find (const uint8_t *cont_id,
                                     uint32_t size,/*lint !e715*/
                                     uint8_t *index)
{

    uint8_t value[FIT_CONT_ID_LEN];
    uint32_t len;
    uint32_t itemid=0;
    fit_status_t status = FIT_STATUS_OK;
    uint32_t prstid;

    if (size != FIT_CONT_ID_LEN)
        return FIT_STATUS_INVALID_PARAM_3;

    while (status == FIT_STATUS_OK)
    {
        len = FIT_CONT_ID_LEN;
        status = fit_prst_element_get_seq(&itemid, value, &len);

        if (status == FIT_STATUS_PRST_ITEM_TOO_BIG)
        {
            /*
             * we continue because we are not in case of container ID since we use container ID size in len
             */
            itemid++;
            status = FIT_STATUS_OK;
            continue;
        }

        if (status == FIT_STATUS_PRST_ID_NOT_FOUND)
        {
            /*
             * if nothing found anymore we return next free index
             */
            *index = *index + 1;
            goto bail; //lint !e801
        }

        /*
         * in case of error return error 
         */
        if (status != FIT_STATUS_OK)
            return status;

        /*
         *  extract index and reference id
         */
        fit_index_and_prstid_get((uint8_t*)&itemid, index, &prstid);/*lint !e818 */

        /*
         * if we found a container ID we check if is a match on the value
         */
        if (prstid == FIT_PRST_CONT_UUID_REF_ID)
        {
            if (!fit_memcmp(cont_id, value, FIT_CONT_ID_LEN))
            {
                /*
                 * match -> return success
                 */
                return FIT_STATUS_OK;
            }
        }
    }
bail:
    return status;
}

//#endif
/**
 *
 * \skip fit_prst_delete
 *
 * This function will delete (all zeros) the entry from persistent storage corresponding
 * to persistent id
 *
 * @param IN    id  \n Persistent id to be deleted.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_prst_delete(uint32_t id)
{
	uint32_t p;
    fit_prst_item_t item;
    fit_status_t status = FIT_STATUS_UNKNOWN_ERROR;

    status = fit_prst_id_find(id,&p);

    if (status != FIT_STATUS_OK) {
    	DBG(FIT_TRACE_PRST, "id %u not found\n",id);
        return FIT_STATUS_PRST_ID_NOT_FOUND;
    }

    status = fit_prst_hw_read(prst_storage.current_block_num,p, (uint8_t*)&item, FIT_PRST_ITEM_FIXED_SIZE);
    if (status != FIT_STATUS_OK)
    {
        return status;
    }
    if (item.total_size == FIT_PRST_ITEM_FIXED_SIZE ) {
        // treat zero size item as "not found)
    	DBG(FIT_TRACE_PRST, "id %u already has zero size\n",item.id);
        return FIT_STATUS_PRST_ID_NOT_FOUND;
    }

    // write new item with payload size == 0
    return fit_prst_write(id, 0, NULL); /*lint !e831 */
}

#ifdef FIT_USE_UNIT_TESTS
/**
 *
 * \skip fit_prst_delete_cont_id
 *
 * Delete container id data and its persistent elements data from persistent storage
 *
 * @param IN    cont_id     \n Pointer to Container id data that needs to be deleted
 *
 */
fit_status_t fit_prst_delete_cont_id(const uint8_t *cont_id)
{
    uint32_t p, end;
    fit_prst_item_t item;
    fit_status_t status = FIT_STATUS_UNKNOWN_ERROR;
    uint8_t cont_index  = 0;
    uint8_t prst_index  = 0;
    uint32_t prst_id    = 0;
    uint32_t     zero = 0;

    status = fit_prst_cont_id_find(cont_id, FIT_CONT_ID_LEN, &cont_index);
    if (status != FIT_STATUS_OK)
    {
        return status;
    }

    p = 0;
    end = p + prst_storage.block_size - 16;

    while (p < end) {
        status = fit_prst_hw_read(prst_storage.current_block_num,p, (uint8_t*)&item, FIT_PRST_ITEM_FIXED_SIZE);
        if (status != FIT_STATUS_OK)
        {
            return status;
        }

        if (item.id == 0xFFFFFFFF)
        {
            break;
        }
        if (item.total_size < FIT_PRST_ITEM_FIXED_SIZE)
        {
            DBG(FIT_TRACE_PRST, "FIT_STATUS_PRST_CORRUPT: total_size < FIT_PERSIST_ITEM_FIXED_SIZE: %08X %u\n", (uint32_t)p, item.total_size);/*lint !e507 */
            break;
        }

        fit_index_and_prstid_get((uint8_t *)&(item.id), &prst_index, &prst_id);

        if (prst_index == cont_index)
        {
            status = fit_prst_hw_write(prst_storage.current_block_num,p,(uint8_t*)&zero, item.total_size, FIT_PRST_HW_WRITE_FLAGS_NO_CACHE);/*lint !e507 */
            if (status != FIT_STATUS_OK)
            {
                return status;
            }
        }
        p += SIZE_ALIGN(item.total_size);/*lint !e679 */
    }

    return status;/*lint !e438 */
}
#endif //FIT_USE_UNIT_TESTS

/**
 *
 * \skip count_items
 *
 *  #return - number of items in the storage 
 *
 */

static uint32_t count_items (void)
{
    uint32_t itemid;
    uint32_t count = 0;
    uint32_t data_size = FIT_CONT_ID_LEN;
    uint8_t* value = NULL ;
    uint32_t prev_itemid;
    uint32_t len;
    fit_status_t status = FIT_STATUS_OK;


    /* read list of active items from source */
    itemid = 0;

    value = fit_calloc(1, data_size);
    if (value == NULL)
    {
        count = 0;
        goto bail;/*lint !e801 */
    }

    /*
    * we enumerate all items and we write them to target page
    */
    while (status == FIT_STATUS_OK)
    {
        len = data_size;
        prev_itemid = itemid;
        status = fit_prst_element_get_seq(&itemid, value, &len);
        if (status == FIT_STATUS_PRST_ITEM_TOO_BIG)
        {
            fit_free(value);
            data_size = len;
            value = fit_calloc(1, data_size);
            if (value == NULL)
            {
                status = FIT_STATUS_PRST_INSUFFICIENT_MEMORY;
                count = 0;
                goto bail;/*lint !e801 */
            }
            itemid = prev_itemid;
            status = fit_prst_element_get_seq(&itemid, value, &len);
        }
        
        if (status == FIT_STATUS_OK)
        {
            count++;
            continue;
        }

        if (status == FIT_STATUS_PRST_ID_NOT_FOUND)
        {
            goto bail;//lint !e801
        }

        /*
         * we got an error - return 0
         */
        count = 0;
        break;
    }

bail:

    if (value) fit_free(value);
    return count;

}

/**
 *
 * \skip find_free
 *
 *  finds first free offset in persistence
 * 
 *  @param IN offset - pointer to the data where the offset is returned
 *
 *  @return FIT_STATUS_OK or error code if fails
 *
 */
static fit_status_t find_free (uint32_t *offset)
{
    uint32_t p, end;
    fit_prst_item_t item;


	p=0;
    end = p + prst_storage.block_size - 16;
    while (p < end) {
        if (fit_prst_hw_read(prst_storage.current_block_num,p, (uint8_t*)&item, FIT_PRST_ITEM_FIXED_SIZE) != FIT_STATUS_OK)
        {
			return FIT_STATUS_PRST_ID_NOT_FOUND;
        }
        if (item.id == 0xFFFFFFFF)
		{
			*offset = p;
			return FIT_STATUS_OK; // empty ID found
		}

        if (item.total_size < FIT_PRST_ITEM_FIXED_SIZE) {
        	DBG(FIT_TRACE_PRST, "FIT_STATUS_PRST_CORRUPT: total_size < FIT_PERSIST_ITEM_FIXED_SIZE: %08X %u\n", (uint32_t)p, item.total_size);/*lint !e507 */
            break;
        }

        p += SIZE_ALIGN(item.total_size);/*lint !e679 */
    }

	return FIT_STATUS_PRST_ID_NOT_FOUND; /* no empty space found */
}

/**
 *
 * \skip fit_prst_find_size
 *
 *  finds space used in persistence
 * 
 *  @param IN offset - pointer to the data where the offset is returned
 *
 *  @return FIT_STATUS_OK or error code if fails
 *
 */
uint32_t fit_prst_find_size (void)
{
    uint32_t p, end;
    uint32_t size = 0;
    fit_prst_item_t item;

	p = 0;
    end = p + prst_storage.block_size - 16;
    while (p < end) {
        if (fit_prst_hw_read(prst_storage.current_block_num,p, (uint8_t*)&item, FIT_PRST_ITEM_FIXED_SIZE) != FIT_STATUS_OK)
        {
            return 0;
        }
        if (item.id == 0xFFFFFFFF) return size; /* empty ID found */

        if (item.total_size < FIT_PRST_ITEM_FIXED_SIZE) {
        	DBG(FIT_TRACE_PRST, "FIT_STATUS_PRST_CORRUPT: total_size < FIT_PERSIST_ITEM_FIXED_SIZE: %08X %u\n", (uint32_t)p, item.total_size);/*lint !e507 */
            break;
        }

        size += SIZE_ALIGN(item.total_size); /*lint !e679 */
        p += SIZE_ALIGN(item.total_size);    /*lint !e679 */
    }

    return 0; /* no empty space found */
}

/**
 *
 * \skip write_count
 *
 *  write next in persistence header number of elements
 * 
 *  @param IN offset - pointer to the data where the offset is returned
 *
 *  @return FIT_STATUS_OK or error code if fails
 *
 */
static fit_status_t write_count (void)
{
    fit_prst_header_t new_header;
    uint32_t             write_size;
    fit_status_t         rc;

    (void)fit_memset(&new_header, 0xFF, sizeof(new_header));
    new_header.id = FIT_PRST_HEADER_ID;
    new_header.total_size = sizeof(fit_prst_header_t);
    new_header.count  = get_next_count();

    write_size = SIZE_ALIGN(new_header.total_size);/*lint !e845 */

    rc = fit_prst_hw_write(prst_storage.current_block_num,0,(uint8_t*)&new_header, write_size, FIT_PRST_HW_WRITE_FLAGS_NONE);/*lint !e507 */
    fit_prst_error_print(rc);
    return rc;
}

/**
 *
 * \skip abandon_page
 *
 *  write entire page with 0 
 * 
 *  @param IN page  - block number to be written with 0
 *
 */
static fit_status_t abandon_page ( uint8_t page )
{
    fit_status_t rc;
    uint32_t     zero = 0;
    uint32_t     write_size;
    uint8_t      save_page = prst_storage.current_block_num;

    fit_prst_select(page);

    write_size = SIZE_ALIGN(sizeof(zero));/*lint !e845 !e778 */

    rc = fit_prst_hw_write (prst_storage.current_block_num , 8,(uint8_t*)&zero, write_size, FIT_PRST_HW_WRITE_FLAGS_NONE);/*lint !e507 */

    fit_prst_error_print(rc);
    fit_prst_select(save_page);
    return rc;
}

/**
 *
 * \skip fit_prst_erase
 *
 * This function will erase block of storage
 *
 * @param IN   block            \n block number to be deleted
 *
 */
static void fit_prst_erase (uint8_t block)
{
    uint8_t save_page = prst_storage.current_block_num;

    if ( (block < 1) || (block > 2) ) return;
    fit_prst_select(block);

    (void)fit_prst_hw_erase(block);
    (void)write_count();

    fit_prst_select(save_page);
}

#if defined(FIT_USE_UNIT_TESTS) || defined(FIT_TEST)
/**
 *
 * \skip fit_prst_erase_all
 *
 * This function will erase all entries from persistent storage.
 *
 * @param OUT   deleted_items   \n will return the number of entries deleted from
 *                                 persistent storage.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_prst_erase_all (uint32_t *deleted_items)
{
    fit_status_t status;
    uint32_t item_count;

    item_count = count_items();
    if (item_count > 0) item_count--; // ignore the page counter

    DBG(FIT_TRACE_PRST, "fit_prst_erase_all() count: %u\n", item_count);

    status = fit_prst_hw_erase_all();

    if ( (deleted_items) && (status == FIT_STATUS_OK) ) {
        *deleted_items = item_count;
    }

    return status;
}

/**
 *
 * \skip fit_prst_destroy
 *
 * This function will make persistent storage unusable. User have to initialize persistent
 * storage in order to use persistent related api's.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_prst_destroy(void)
{
    fit_status_t status = FIT_STATUS_UNKNOWN_ERROR;

    status = fit_prst_erase_all(NULL);
    if (status != FIT_STATUS_OK)
    {
        return status;
    }

    prst_storage.block_size = 0;
    return fit_prst_hw_destroy();

}
#endif

/**
*
* \skip fit_prst_element_get_seq
*
* This function will enumerate all entries in the current persistence storage block
*
* @param IN/OUT itemid    \n pointer to internal id of the element. 
*                         \n on input contains the value of previous element found. If is zero we search for first element
*                         \n on output contains the id of the returned element
* 
* @param OUT value        \n pointer to buffer where value will be retrieved
*
* @param IN/OUT len       \n on input contains size of buffer pointed by value
*                         \n on out contains the number of bytes returned in the value buffer
* @return FIT_STATUS_OK on success; otherwise appropriate error code.
*
*/
fit_status_t fit_prst_element_get_seq(uint32_t *itemid, uint8_t *value, uint32_t *len)
{
    fit_status_t status = FIT_STATUS_OK;
    uint32_t p, end;
    fit_prst_item_t item;
    uint32_t  found_size=0;
    uint8_t read_data = 0;
    uint32_t req_refid = 0;
    uint8_t found ;
restart:
    /*  we memorise keyid value*/
    found = 0;
    req_refid = *itemid;
    *itemid = *itemid + 1;        /* set smallest possible next value */

    p = 0;
    end = p + prst_storage.block_size - 16;

    /* get the persistent id's associated with container index doing a loop over all storage block elements*/
    while (p < end) {
        status = fit_prst_hw_read(prst_storage.current_block_num, p, (uint8_t*)&item, FIT_PRST_ITEM_FIXED_SIZE);
        if (status != FIT_STATUS_OK)
        {
            return status;
        }

        if (item.id == 0xFFFFFFFF)
        {
            break;
        }
        if (item.total_size < FIT_PRST_ITEM_FIXED_SIZE)
        {
            DBG(FIT_TRACE_PRST, "FIT_STATUS_PRST_CORRUPT: total_size < FIT_PERSIST_ITEM_FIXED_SIZE: %08X %u\n",/*lint !e507 */
                (uint32_t)p, item.total_size);
            break;
        }
        if (item.id != FIT_PRST_HEADER_ID)
        {
            /* set flag to zero - we presume we won't need to read data*/
            read_data = 0;

            /* check if is first element searched first_found or if prst_id found is bigger than input and less then last found */
            /* we check here for the smallest possible element after keyid input value */
            if ( ((found == 0 && item.id > req_refid ) || (item.id > req_refid && item.id <= *itemid)) && (item.total_size >= FIT_PRST_ITEM_FIXED_SIZE) )
            { /* new entry found*/
                *itemid = item.id;
                read_data = 1;
                found = 1;
            }

            /* we read element */
            if (read_data) {
                found_size = item.total_size - FIT_PRST_ITEM_FIXED_SIZE;

                if (found_size > *len) {
                    *len = found_size;
                    return FIT_STATUS_PRST_ITEM_TOO_BIG;
                }
            
                if (value) {
                    status = fit_prst_hw_read(prst_storage.current_block_num, p + FIT_PRST_ITEM_FIXED_SIZE,
                           value, found_size);
                    if (status != FIT_STATUS_OK)
                    {
                        return status;
                    }
                }
            }
        }

        p += SIZE_ALIGN(item.total_size);/*lint !e679 */
    }
    /*'
     * check if we found a deleted item as last one  restart from beginning
     */
    if (found == 1 && found_size == 0)
    {
        goto restart; //lint !e801
    }

    if (found == 0)
    {
        *itemid = req_refid;
        return FIT_STATUS_PRST_ID_NOT_FOUND;
    }

    *len = found_size;
    return FIT_STATUS_OK;
 }


/**
 *
 * \skip fit_prst_page_switch
 *
 * This function will do a switch persistence active page and removes deleted entries from storage
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_prst_page_switch(uint8_t disable_old_page)
{
    fit_status_t status = FIT_STATUS_OK;
    uint8_t  source, target;
    uint32_t itemid = 0;
    uint32_t prev_itemid = 0;
    uint8_t* value = NULL;
    uint32_t len = 0;
    uint32_t data_size = FIT_CONT_ID_LEN; /* we start with size of container id in order to avoid memory fragmentation*/

    fit_prst_active_block_set();
    source = prst_storage.current_block_num;
    target = (uint8_t)(3 - source);

    fit_prst_erase(target);  // erase target and write header
    /* read list of active items from source */
    itemid = 0;

    value = fit_calloc(1,data_size);
    if (value == NULL)
    {
        status = FIT_STATUS_PRST_INSUFFICIENT_MEMORY;
        goto bail;/*lint !e801 */
    }

    /*
     * we enumerate all items and we write them to target page
     */
    while (status == FIT_STATUS_OK)
    {
        len = data_size;
        fit_prst_select(source);
        prev_itemid = itemid;
        status = fit_prst_element_get_seq(&itemid, value, &len);
        if (status == FIT_STATUS_PRST_ITEM_TOO_BIG)
        {
            fit_free(value);
            data_size = len;
            value = fit_calloc(1,data_size);
            if (value == NULL)
            {
                status = FIT_STATUS_PRST_INSUFFICIENT_MEMORY;
                goto bail;/*lint !e801 */
            }
            itemid = prev_itemid;
            status = fit_prst_element_get_seq(&itemid, value, &len);
        }

        if (status != FIT_STATUS_OK)
            break;

        fit_prst_select(target);

        status = fit_prst_write_prim(itemid, len, value, FIT_PRST_HW_WRITE_FLAGS_NONE);
        if (status != FIT_STATUS_OK)
        {
            fit_prst_error_print(rc);
        }

    }
    fit_prst_select(target);

    if (disable_old_page) {
        status = abandon_page(source);
    }

bail:
    if (value != NULL)
    {
        fit_free(value);
    }
    if ( status != FIT_STATUS_OK )
    {
        fit_prst_error_print(status);
    }

    return status;
}

#endif //FIT_USE_PERSISTENT
