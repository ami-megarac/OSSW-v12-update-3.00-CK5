/****************************************************************************\
**
** fit_board_setup.c
**
** Contains function definitions for setting up board 
** Linux/raspi
**
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

void fit_board_setup(void) //lint !e765
{
}

void handle_uart_errors(void) /*lint !e765*/
{
/* This function is empty as it is not required for Linux */
}


