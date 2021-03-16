/******************************************************************************
 *
 * fit_hw_persist_ram.c
 *
 * Sentinel Fit persistant storage - Hardware dependent part
 * Linux/raspi
 *
 * Copyright (C) 2017-2019, SafeNet, Inc. All rights reserved.
 *
 *****************************************************************************/

/* Required Includes ********************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#include "fit_status.h"
#include "fit_hw_persist.h"
#include "fit_internal.h"

#ifdef FIT_USE_PERSISTENT

#ifndef FIT_PERSIST_STORAGE
#error "FIT_PERSIST_STORAGE must be defined!"
#endif

#if FIT_PERSIST_STORAGE == FIT_PERSIST_RAM

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <stdio.h>

#include <string.h>

#include "fit_persist.h"
#include "fit_debug.h"

/* Global variables *********************************************************/

static fit_persist_storage_t* persist_data;

/* statically allocated RAM */
static uint8_t block1[FIT_PERSIST_STORAGE_SIZE];
static uint8_t block2[FIT_PERSIST_STORAGE_SIZE];

static char fit_prst_filename[128];


/* Function Definitions *****************************************************/
#if defined(FIT_USE_UNIT_TESTS) || defined(FIT_TEST)
/**
 *
 * \skip fit_prst_hw_file_delete
 * 
 * deletes the persistence file
 *
 * @return FIT_STATUS_OK or appropriate error
 */
static fit_status_t fit_prst_hw_file_delete(void)
{
    int err;

    err = remove(fit_prst_filename);
    if (err != 0 ) {
        if (errno == ENOENT) { /* file not found is ok here */
            return FIT_STATUS_OK;
        }
        DBG(FIT_TRACE_PRST,"[remove persistence file] %d - Error removing persistence file. Errno = %d\n",
            __LINE__, errno);
        return FIT_STATUS_PRST_ERASE_ERROR;
    }
    return FIT_STATUS_OK;
}
#endif //FIT_USE_UNIT_TESTS

/**
 *
 * \skip fit_prst_hw_file_write
 *
 * write ram storage to file
 *
 * @return FIT_STATUS_OK or appropriate error
 */
static fit_status_t fit_prst_hw_file_write (void)
{
    FILE *fd=NULL;
    int ret = 0;
    uint32_t size;
    uint8_t *what;


    DBG(FIT_TRACE_PRST, "[fit_prst_hw_file_write] (\"%s\") size = %u, %u\n",
        fit_prst_filename, sizeof(block2), fit_prst_find_size());

    if (persist_data == NULL || persist_data->block_size == 0 )
        return FIT_STATUS_PRST_NOT_INIT;

    what = persist_data->storage_block[persist_data->current_block_num-1];

    fd = fopen(fit_prst_filename, "w+b");
    if (fd == NULL) {
        DBG(FIT_TRACE_PRST, "[fit_prst_hw_file_write] %d - Failed to open persistence file. Errno = %d\n",
            __LINE__, errno);
        return FIT_STATUS_PRST_CANNOT_WRITE;
    }

    size = fit_prst_find_size();
    if (size != (uint32_t)fwrite(what, 1, size, fd) ) {
        (void)fclose(fd);
        return FIT_STATUS_PRST_CANNOT_WRITE;
    }

    ret = fclose(fd);
    if (ret) {
        return FIT_STATUS_PRST_CANNOT_WRITE;
    }

    return FIT_STATUS_OK;
}


/**
 *
 * \skip fit_prst_hw_file_read
 *
 * read persistence data into ram storage
 *
 * @return FIT_STATUS_OK or appropriate error
 */
static fit_status_t fit_prst_hw_file_read (void)
{
    FILE *fd=NULL;
    size_t data_size = 0;
    fit_status_t status;

    (void)fit_prst_hw_erase(1);
    (void)fit_prst_hw_erase(2);

    fit_prst_select(2);

    fd = fopen(fit_prst_filename, "rb");

    if (fd == NULL ) {
        DBG(FIT_TRACE_PRST, "[fit_prst_hw_file_read] %d - Failed to open persistence file - write error &d\n",__LINE__,errno);
        return FIT_STATUS_PRST_NOT_FOUND;
    }

    /* get file size */
    (void)fseek(fd, 0, SEEK_END);
    data_size = (uint32_t)ftell(fd);
    (void)fseek(fd, 0, SEEK_SET);


    if (data_size != 0)
    {
      if( FIT_PRST_ITEM_FIXED_SIZE > fread(persist_data->storage_block[persist_data->current_block_num - 1], 1, data_size, fd))
      {
          (void)fclose(fd);
          return FIT_STATUS_PRST_CORRUPT;
      }
      status = fit_prst_check();
      (void)fclose(fd);
      return status; 

    }
    (void)fclose(fd);
    return FIT_STATUS_OK;
}


/**
 *
 * \skip fit_prst_hw_erase
 *
 * Erase (== set to 0xFF) block of memory
 *
 * @param IN    block     \n Block of storage to be checked.
 *
 */
fit_status_t fit_prst_hw_erase (uint8_t block)
{
    if ( persist_data == NULL )
        return FIT_STATUS_PRST_NOT_INIT;
    
    if (1 != block && 2 != block)
       return FIT_STATUS_INVALID_PARAM_1;
   
    (void)fit_memset(persist_data->storage_block[block-1], 0xFF, persist_data->block_size);
    // DBG(FIT_TRACE_PRST, "RAM: erased %u (%u bytes)\n", block, persist_data->block_size);

    return FIT_STATUS_OK;
}

#if defined(FIT_USE_UNIT_TESTS) || defined(FIT_TEST)
/**
 *
 * \skip fit_prst_hw_erase_all
 *
 * Erase (== set to 0xFF) all blocks of memory
 *
 * @param IN    block     \n Block of storage to be checked.
 *
 * @return FIT_STATUS_OK or appropriate error
 */
fit_status_t fit_prst_hw_erase_all (void)
{

    fit_status_t status = FIT_STATUS_OK;
  
    (void)fit_prst_hw_erase(1);
    (void)fit_prst_hw_erase(2);

    DBG(FIT_TRACE_PRST, "[fit_prst_hw_erase_all] - Both persistence blocks were erased, no headers written.\n");
    status = fit_prst_hw_file_write();

    return status;
}
#endif

/**
 *
 * \skip fit_prst_hw_file_set
 * 
 * initialize persistence file
 *
 * @param IN    filename  \n file anme tobe used for persistence
 *
 * @return FIT_STATUS_OK or appropriate error
 */
static fit_status_t fit_prst_hw_file_set (char* filename)/*lint !e818 */
{
  FILE* fd=NULL;

  (void)strcpy(fit_prst_filename, filename);
  DBG(FIT_TRACE_PRST, "[fit_prst_hw_file_set] (\"%s\")\n", fit_prst_filename);

  /*
   * we check here if persistence file exist and if not we create it
   */
   fd = fopen(fit_prst_filename, "rb");
   if ( fd == NULL )
   {
      fd = fopen(fit_prst_filename, "wb");
      if ( fd == NULL ) {
          DBG(FIT_TRACE_PRST,"[fit_prst_hw_file_set] %d. Failed to create persistence file.\n", __LINE__);
          return FIT_STATUS_PRST_CANNOT_WRITE;
      }
      /*
       * we initialize the file here - so we have to set it to persistence size - we write a block to file
       */

  }
  (void)fclose(fd);
  DBG(FIT_TRACE_PRST, "[fit_prst_hw_file_set] - Persistence file succesfully initialized\n");

  return FIT_STATUS_OK;
}


/**
 *
 * \skip fit_prst_hw_init
 * 
 * initialize persistent storage
 *    since this is an emulation of flash/EE, all memory is set emtpy (==0xFF)
 *
 * @param IN    persist     \n pointer to upper layer persistence data
 *
 * @return FIT_STATUS_OK or appropriate error
 */

fit_status_t fit_prst_hw_init(fit_persist_storage_t* persist_storage_data)
{
    fit_status_t rc;
    
    if( persist_storage_data == NULL )
        return FIT_STATUS_INVALID_PARAM_1;
    
    persist_data = persist_storage_data;
    persist_data->block_size = sizeof(block1);
    persist_data->storage_block[0] = block1;
    persist_data->storage_block[1] = block2;

    (void)fit_prst_hw_erase(1);
    (void)fit_prst_hw_erase(2);

    (void)fit_prst_hw_file_set(FIT_PERSIST_FILE_NAME);
    rc = fit_prst_hw_file_read();

    return rc;
}


/**
 *
 * \skip fit_prst_hw_post_write
 *
 * does post write actions -
 *
 * @return FIT_STATUS_OK or appropriate error
 */
static fit_status_t fit_prst_hw_post_write(void)
{
    fit_status_t status;

    /*
     * whenever we do a write into the buffer we write also the file
     */
    DBG(FIT_TRACE_PRST, "fit_prst_hw_post_write()\n");

    status = fit_prst_page_switch(1);
    if (status == FIT_STATUS_OK)
        status = fit_prst_hw_file_write();
    return status;
}


fit_status_t fit_prst_hw_read ( uint8_t block,uint32_t offset, uint8_t *target, uint32_t size )
{
    if (!size) {
        DBG(FIT_TRACE_PRST, "ERROR calling fit_prst_hw_read() with size 0\n");
        return FIT_STATUS_OK;
    }
    
    if ( persist_data == NULL )
        return FIT_STATUS_PRST_NOT_INIT;
    
    if( block != 1 && block != 2 )
        return FIT_STATUS_INVALID_PARAM_1;
    
    if( offset + size > persist_data->block_size)
        return FIT_STATUS_BUFFER_OVERRUN;
    
    if (fit_memcpy(target, size, persist_data->storage_block[block-1] + offset, size) != 0)
    {
        return FIT_STATUS_BUFFER_OVERRUN;
    }

    return FIT_STATUS_OK;
}

/**
*
* \skip fit_prst_hw_write
*
* write data to  persistence block
*
* @param IN    block     \n persistence storage block where to read from
*
* @param IN    offset    \n offset into persistence storage block to read from
*
* @param IN    data      \n buffer containing data
*
* @param IN    size      \n length of data to read
*
* @param IN    flags     \n if FIT_PRST_HW_WRITE_FLAGS_NO_CACHE write uffer to file in case storage is on file
*                           if FIT_PRST_HW_WRITE_FLAGS_NONE - data is written in memory storage only
*
* @return FIT_STATUS_OK or appropriate error
*/
fit_status_t fit_prst_hw_write ( uint8_t block, uint32_t offset,const uint8_t *data, uint32_t size, uint8_t flags)
{
    fit_status_t status = FIT_STATUS_OK;

    if (!size) {
        DBG(FIT_TRACE_PRST, "ERROR calling fit_prst_hw_write() with size 0\n");
        return FIT_STATUS_OK;
    }
    
    if ( persist_data == NULL )
        return FIT_STATUS_PRST_NOT_INIT;
    
    if( block != 1 && block != 2 )
        return FIT_STATUS_INVALID_PARAM_1;
    
    if( offset + size > persist_data->block_size)
        return FIT_STATUS_BUFFER_OVERRUN;
    
    (void)memcpy((uint8_t*)persist_data->storage_block[block-1] + offset, data, size);
    DBG(FIT_TRACE_PRST, "fit_prst_hw_write(%u, %u, %08X, %u, %u)\n",
                        block, offset, data, size, flags);

    if (flags == FIT_PRST_HW_WRITE_FLAGS_NO_CACHE)
        status = fit_prst_hw_post_write();
	

    return status;
}

#if defined(FIT_USE_UNIT_TESTS) || defined(FIT_TEST)
fit_status_t fit_prst_hw_destroy(void)
{
    fit_status_t status = FIT_STATUS_OK;

    if ( persist_data == NULL ) /* in case was not initialized nothing to destroy */
        return FIT_STATUS_OK;

    persist_data->storage_block[0] = NULL;
    persist_data->storage_block[1] = NULL;
    persist_data->block_size = 0;
    persist_data = NULL;

    status = fit_prst_hw_file_delete();
    return status;
}
#endif

/**
 *
 * \skip fit_prst_hw_extend_size
 * 
 * extends persistence storage to req_size
 *
 * @param req_size = required size of the persistence storage
 *
 * @return FIT_STATUS_OK or appropriate error
 */
fit_status_t fit_prst_hw_extend_size(uint32_t req_size) /*lint !e715*/
{
    /*
     * in case of dynamic persistence allocation persist_data->block_size should be updated. In our reference implementation
     * we use static buffer allocation and will simply return not enough memory
     */
    
     return FIT_STATUS_INSUFFICIENT_MEMORY;
        
}


#endif // #if FIT_PERSIST_STORAGE == FIT_PERSIST_RAM
#endif // #ifdef FIT_USE_PERSISTENT

