//
//  utils-openssl.h
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

#ifndef __smp__utils_openssl__
#define __smp__utils_openssl__

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <openssl/bn.h>

void printBN( char* name, BIGNUM* bn );
void printBNX( char* name, BIGNUM* bn );

BIGNUM* createRandomExponent( void );
void sha256( char *string, unsigned long len, char outputBuffer[ 65 ] );
BIGNUM* sha_with_version( const char* version, BIGNUM* a, BIGNUM* b );
BIGNUM* mulm( BIGNUM* x, BIGNUM* y, BIGNUM* mod_param );
BIGNUM* my_pow( BIGNUM* a, BIGNUM* p, BIGNUM* m );
BIGNUM* subm( BIGNUM* a, BIGNUM* b, BIGNUM* m );
BIGNUM* invm( BIGNUM* x, BIGNUM* m );
BIGNUM* binEncode( const char* input, unsigned long len );

unsigned char* simplePack( unsigned char* buffer_in, BIGNUM* bn );
unsigned char* simpleUnpack( unsigned char* buffer_in, BIGNUM* bn_new );
unsigned char* unpackAndCompare( unsigned char* buffer_in, BIGNUM *bn_old, BIGNUM *bn_new );

#endif /* defined(__smp__utils_openssl__) */
