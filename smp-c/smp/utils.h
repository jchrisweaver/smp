//
//  utils.h
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

#ifndef __smp__utils__
#define __smp__utils__

unsigned int little2bigEndian( unsigned int num );
unsigned int big2littleEndian( unsigned int num );
void dumpBuff( unsigned char* buffer, int len );
char* readLine( char* input, int size );

#endif /* defined(__smp__utils__) */
