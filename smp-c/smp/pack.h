//
//  pack.h
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

#ifndef __Smp__pack__
#define __Smp__pack__

#include <stdio.h>

unsigned char* bin2str( unsigned char* buffer, char *ptr );
unsigned char* str2bin (unsigned char* buffer, const char *ptr);

unsigned char* pack( unsigned char* buffer, char* val_in );
unsigned char* unpack( unsigned char* buffer, char* val_out );

void testPack();

#endif /* defined(__Smp__pack__) */
