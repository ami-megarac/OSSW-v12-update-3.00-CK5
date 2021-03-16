/****************************************************************************\
**
** fit_uart.c
**
** Contains function definitions for uart related functions.
** 
** Copyright (C) 2016-2019, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/
#include "stdio.h"
//#include "conio.h"

/**
 *
 * uart_putc
 *
 * write byte to console
  *
 * @param   data --> byte to be transmitted
 *
 */
void fit_uart_putc(unsigned char data)
{
    (void)printf("%c", data);
}

/**
 *
 * uart_puts
 *
 * write string to console
 *
 * @param   s --> string to be transmitted
 *
 */
void fit_uart_puts(const char *s ) //lint !e765
{
    while (*s) 
    {
      fit_uart_putc(*s++); //lint !e732 
    }

}

/**
 *
 * fit_uart_getchar
 *
 * read a char from console
 *
 */
unsigned char fit_uart_getchar(void)
{
    unsigned char c;
    c = (unsigned char )getchar();
    (void)fflush(stdin);
    return c;
}

/**
 *
 * fit_uart_getc
 *
 * read a char from console
 *
 */
unsigned char fit_uart_getc(void) //lint !e765
{
    unsigned char c;
    c = (unsigned char )getchar();
    (void)fflush(stdin);
    return c;
}
