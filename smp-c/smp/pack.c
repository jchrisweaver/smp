//
//  pack.c
//  Smp
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

#include <stdarg.h>
#include <string.h>
#include "pack.h"
#include "utils.h"

// string of hex chars in, packed out
unsigned char* pack( unsigned char* buffer, char* val_in )
{
    unsigned long len = strlen( val_in );
    if ( len > 512 )
    {
        printf( "******************pack: length exceeeds buffer!!\n" );
        return NULL;
    }
    
    char temp_fix[ 512 ];
    memset( temp_fix, 0x00, 512 );
    if ( len % 2 )
    {
        memset( temp_fix, 0x30, 1 );    // "0"
        memcpy( temp_fix + 1, val_in, len );
    }
    else
        memcpy( temp_fix, val_in, len );
    
    unsigned char out[ 512 ];
    memset( out, 0x00, 512 );   // TODO: don't really need this after debugging
    str2bin( out, temp_fix );
    
    len = len / 2 + len % 2;    // round up to even number length
    
    int *t = ( int* )buffer;
    *t = (int ) len;
    *t = little2bigEndian( *t );
    memcpy( ( buffer + sizeof( int ) ), out, len );
    return ( buffer + sizeof( int ) + len );
}

unsigned char* unpack( unsigned char* buffer, char* val_out )
{
    int *size = ( int* )( buffer );
    *size = big2littleEndian( *size );
    
    buffer += 4;
    for ( int t = 0; t < *size; t++ )
    {
        buffer = bin2str( buffer, val_out );
        val_out++;
        val_out++;
    }
    return buffer;
}

// binary value in, printable string of hex values out
unsigned char* bin2str( unsigned char* buffer_in, char *out )
{
    char s = *buffer_in;
    char t1 = ( s & 0xF0 ) >> 4;
    char t2 = ( s & 0x0F );
    if ( t1 <= 9 )
        *out = '0' + t1;
    else if ( t1 > 9 )
        *out = 'A' + t1 - 10;
    out++;
    
    if ( t2 <= 9 )
        *out = '0' + t2;
    else if ( t2 > 9 )
        *out = 'A' + t2 - 10;
    
    return ++buffer_in;
}

// printable string of hex values in, binary value out
unsigned char* str2bin( unsigned char* buffer, const char *in )
{
    unsigned char value = 0;
    char ch = *in;
    
    while (ch == ' ' || ch == '\t')
        ch = *(++in);
    
    for (int count = 0; ; count++ )
    {
        if (ch >= '0' && ch <= '9')
            value = (value << 4) + (ch - '0');
        else if (ch >= 'A' && ch <= 'F')
            value = (value << 4) + (ch - 'A' + 10);
        else if (ch >= 'a' && ch <= 'f')
            value = (value << 4) + (ch - 'a' + 10);
        else
            return buffer;

        ch = *(++in);
        if ( ch == 0x00 || count % 2 == 1)
        {
            *buffer = value;
            ++buffer;
        }
    }
    return buffer;
}
