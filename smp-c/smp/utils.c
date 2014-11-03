//
//  utils.c
//  smp
//
//  Created by Chris Weaver on 9/26/14.
//  www.chrisweaver.com
//
//  This work is highly based off Shane Tully's Python SMP implementation found here:
//  https://shanetully.com/2013/08/mitm-protection-via-the-socialist-millionaire-protocol-otr-style/
//
//  Use feel free to use this code however you like, royalty free.
//  If you do use it, please consider letting me know with a tweet at at @jchrisweaver
//

#include <stdio.h>

#include "utils.h"

void dumpBuff( unsigned char* buffer, int len )
{
    for ( int t = 0; t < len ; t += 2 )
    {
        printf( "%02x %02x ", buffer[ t ], buffer[ t + 1] );
    }
    printf( "\nSize: %d\n", len );
}

unsigned int little2bigEndian( unsigned int num )
{
    uint32_t b0, b1, b2, b3;
    uint32_t res;
    b0 = (num & 0x000000ff) << 24u;
    b1 = (num & 0x0000ff00) << 8u;
    b2 = (num & 0x00ff0000) >> 8u;
    b3 = (num & 0xff000000) >> 24u;
    res = b0 | b1 | b2 | b3;
    return res;
}

unsigned int big2littleEndian( unsigned int num )
{
    uint32_t b0, b1, b2, b3;
    uint32_t res;
    b3 = (num & 0x000000ff) << 24u;
    b2 = (num & 0x0000ff00) << 8u;
    b1 = (num & 0x00ff0000) >> 8u;
    b0 = (num & 0xff000000) >> 24u;
    res = b0 | b1 | b2 | b3;
    return res;
}

char* readLine( char* input, int size )
{
    int count = 0;
    while ( 1 )
    {
        int c = getchar();
        if ( c == '\n' || c == EOF || count >= size )
            break;
        input[ count++ ] = (char)c;
    }
    input[ count++ ] = 0x00;
    return input;
}

