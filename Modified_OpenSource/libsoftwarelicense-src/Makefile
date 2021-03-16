#--------------------------------------------------------------------------------------------------------------------
#                      Makefile to build libsoftwarelicense
#                 Copyright (c) 2020 American Megatrends Inc
#---------------------------------------------------------------------------------------------------------------------

#------- Comment/uncomment the following line to enable/disable debugging---------------
DEBUG = n
#---------------------------------------------------------------------------------------------------------------------
#TARGET = fit_demo
LIBRARY_NAME    = libsoftwarelicense
#---------------------------------------------------------------------------------------------------------------------
#---------------------- Change according to your files ----------------------------------------------------
SRC   = mbedtls/library/asn1parse.c mbedtls/library/base64.c mbedtls/library/bignum.c  mbedtls/library/md5.c  mbedtls/library/md.c  mbedtls/library/md_wrap.c  mbedtls/library/oid.c  mbedtls/library/pem.c  mbedtls/library/pk.c  mbedtls/library/pkparse.c  mbedtls/library/pk_wrap.c  mbedtls/library/rsa.c  mbedtls/library/sha256.c
SRC   += hwdep/fit_board_setup.c  hwdep/fit_hw_persist_ram.c  hwdep/fit_fingerprint.c  hwdep/fit_get_time.c  hwdep/fit_led.c hwdep/fit_memory.c  hwdep/fit_mutex.c hwdep/fit_rw_lock.c hwdep/fit_uart.c
SRC   += src/fit_abreast_dm.c  src/fit_capabilities.c  src/fit_dm_hash.c  src/fit_internal.c  src/fit_node_locking.c  src/fit_persist.c  src/fit_test_persist.c src/fit_aes.c  src/fit_consume.c src/fit_feature_context.c  src/fit_krypto.c  src/fit_omac.c src/fit_persistent.c  src/fit_validate.c  src/fit_alloc.c  src/fit_debug.c  src/fit_get_info.c  src/fit_mem_read.c  src/fit_parser.c  src/fit_rsa.c  src/fit_version.c
SRC   += fit.c fit_info.c fit_demo_getinfo.c
 
CFLAGS += -I./mbedtls/include/
CFLAGS += -I./inc
CFLAGS += -I./hwdep
CFLAGS += -I${SPXINC}/unix
CFLAGS += -I${SPXINC}/dbgout
CFLAGS += -I${SPXINC}/global
CFLAGS += -Wno-unused-but-set-variable
CFLAGS += -Wno-sign-compare
CFLAGS += -Wno-unused-variable
CFLAGS += -Wno-unused-parameter
CFLAGS += -Wno-error=missing-braces
#CFLAGS += -Wno-unused-function
#CFLAGS += -Wno-missing-braces
#CFLAGS += -Wno-missing-field-initializers
#CFLAGS += -Wall

include ${TOOLDIR}/rules/Rules.make.libs
