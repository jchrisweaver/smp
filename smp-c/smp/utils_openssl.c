//
//  utils-openssl.c
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

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "utils_openssl.h"
#include "pack.h"

void printBN( char* name, BIGNUM* bn )
{
    printf( "%s = %s\n", name, BN_bn2dec( bn ) );
}

void printBNX( char* name, BIGNUM* bn )
{
    printf( "%s = %s\n", name, BN_bn2hex( bn ) );
}

BIGNUM* createRandomExponent( void )
{
    BIGNUM* buf;
    buf = BN_new();
    int ret = BN_rand( buf, 192 * 8, /*top*/ 0, /*bottom*/ 0 );
    if ( ret < 0 )
    {
        printf( "createRandomExponent: BN_rand failed: %d", ret );
    }
    
    return buf;
}

void sha256( char *string, unsigned long len, char outputBuffer[ 65 ] )
{
    unsigned char hash[ SHA256_DIGEST_LENGTH ];
    SHA256_CTX sha256;
    SHA256_Init( &sha256 );
    SHA256_Update( &sha256, string, len );
    SHA256_Final( hash, &sha256 );
    for( int i = 0; i < SHA256_DIGEST_LENGTH; i++ )
    {
        sprintf( outputBuffer + ( i * 2 ), "%02x", hash[ i ] );
    }
    outputBuffer[ 64 ] = 0;
}

BIGNUM* sha_with_version( const char* version, BIGNUM* a, BIGNUM* b )
{
    char buffer[ 1096 ];
    char* sA = BN_bn2dec( a );
    if ( b != NULL )
    {
        char* sB = BN_bn2dec( b );
        sprintf( buffer, "%s%s%s", version, sA, sB );
        OPENSSL_free( sB );
    }
    else
    {
        char* sA = BN_bn2dec( a );
        sprintf( buffer, "%s%s", version, sA );
    }
    OPENSSL_free( sA );
    
    char c_sha256[ 65 ];
    memset( c_sha256, 0x00, 65 );
    sha256( buffer, strlen( buffer ), c_sha256 );
    
    // c_sha256 contains TEXT STRING of the hex bytes, convert to binary
    unsigned char c_sha_bytes[ 32 ];
    memset( c_sha_bytes, 0x00, 32 );
    str2bin( c_sha_bytes, c_sha256 );
    
    BIGNUM* result = BN_bin2bn( c_sha_bytes, /*len*/32, NULL );
    if ( result == NULL )
    {
        printf( "sha_with_version: BN_bin2bn failed" );
    }
    return result;
}

BIGNUM* mulm( BIGNUM* x, BIGNUM* y, BIGNUM* mod_param )
{
    // return x * y % mod
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM* multMod = BN_new();
    int ret = BN_mod_mul( multMod, x, y, mod_param, ctx);   // r = |a * b mod m|
    if ( ret != 1 )
    {
        printf( "mulm: BN_mod_mul failed: %d", ret );
    }
    BN_CTX_free( ctx );
    
    return multMod;
}

BIGNUM* my_pow( BIGNUM* a, BIGNUM* p, BIGNUM* m )
{
    BN_CTX *ctx = BN_CTX_new();
    
    BIGNUM* result = BN_new();
    int ret = BN_mod_exp( result, a, p, m, ctx );    // | r = a^p % m |
    if ( ret != 1 )
    {
        printf( "pow: BN_mod_exp failed: %d", ret );
        result = NULL;
    }
    BN_CTX_free( ctx );
    
    return result;
}

BIGNUM* subm( BIGNUM* a, BIGNUM* b, BIGNUM* m )
{
    BN_CTX *ctx = BN_CTX_new();
    
    BIGNUM* result = BN_new();
    int ret = BN_mod_sub( result, a, b, m, ctx );  // r = | a - b mod m |
    if ( ret != 1 )
    {
        printf( "subm: BN_sub failed: %d", ret );
        result = NULL;
    }
    BN_CTX_free( ctx );
    return result;
}

// def invm(self, x):
BIGNUM* invm( BIGNUM* x, BIGNUM* m )
{
    // return pow(x, self.mod-2, self.mod)
    BIGNUM* bnTwo = BN_new();
    BN_set_word( bnTwo, 2 );
    
    BIGNUM* postSubtract = BN_new();
    int ret = BN_sub( postSubtract, m, bnTwo );  // r = a - b
    if ( ret != 1 )
    {
        printf( "invm: BN_sub failed: %d", ret );
    }
    
    BIGNUM* retN = my_pow( x, postSubtract, m );
    
    BN_free( bnTwo );
    BN_free( postSubtract );
    
    return retN;
}

BIGNUM* binEncode( const char* input, unsigned long len )
{
    BIGNUM* num = BN_new();
    BN_zero( num );
    
    BIGNUM* var = BN_new();
    for ( int t = 0; t < len; t++ )
    {
        BN_set_word( var, *( input + t ) );
        BN_lshift( num, num, 8 );
        BN_add( num, num, var );
    }
    BN_free( var );
    return num;
}

unsigned char* simplePack( unsigned char* buffer_in, BIGNUM* bn )
{
    char tempbuf[ 1024 ];
    char* s = BN_bn2hex( bn );
    sprintf( tempbuf, "%s", s );
    OPENSSL_free( s );
    unsigned char* next = pack( buffer_in, tempbuf );
    
    return next;
}

unsigned char* simpleUnpack( unsigned char* buffer_in, BIGNUM* bn_new )
{
    char out[ 1024 ];
    memset( out, 0x00, 1024 );
    unsigned char* ptr = unpack( buffer_in, out );
    unsigned char bytes_in[ 384 ];
    str2bin( bytes_in, out );
    BN_bin2bn( bytes_in, /*len*/ ( int )strlen( out ) / 2, bn_new );
    
    return ptr;
}

unsigned char* unpackAndCompare( unsigned char* buffer_in, BIGNUM *bn_old, BIGNUM *bn_new )
{
    unsigned char* ptr = simpleUnpack( buffer_in, bn_new );
    if ( BN_cmp( bn_old, bn_new ) != 0 )
    {
        printf ( "unpackAndCompare: Failed\n" );
        ptr = NULL;
    }
    return ptr;
}
