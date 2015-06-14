// socialist millionaire implementation
// C version

//  Created by Chris Weaver on 9/26/14.
//  www.chrisweaver.com
//
//  This work is highly based off Shane Tully's Python SMP implementation found here:
//  https://shanetully.com/2013/08/mitm-protection-via-the-socialist-millionaire-protocol-otr-style/
//
//  Use feel free to use this code however you like, royalty free.
//  If you do use it, please consider letting me know with a tweet at at @jchrisweaver
//


#ifdef OPENSSL_NO_DEPRECATED
#undef OPENSSL_NO_DEPRECATED
#endif

#include <string.h>
#include <openssl/crypto.h>

#include "smp.h"

#include "pack.h"
#include "socket_helpers.h"
#include "utils.h"
#include "utils_openssl.h"
#include "smp_support.h"

/* Defined in RFC 3526 with 1536-bit modulus (hex, big-endian):

    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
    670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF

As integer: 2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919
*/

unsigned char mod_buffer[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2, 0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1, 0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74, 0x02, 0x0b, 0xbe, 0xa6, 0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd, 0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d, 0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45, 0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6, 0xf4, 0x4c, 0x42, 0xe9, 0xa6, 0x37, 0xed, 0x6b, 0x0b, 0xff, 0x5c, 0xb6, 0xf4, 0x06, 0xb7, 0xed, 0xee, 0x38, 0x6b, 0xfb, 0x5a, 0x89, 0x9f, 0xa5, 0xae, 0x9f, 0x24, 0x11, 0x7c, 0x4b, 0x1f, 0xe6, 0x49, 0x28, 0x66, 0x51, 0xec, 0xe4, 0x5b, 0x3d, 0xc2, 0x00, 0x7c, 0xb8, 0xa1, 0x63, 0xbf, 0x05, 0x98, 0xda, 0x48, 0x36, 0x1c, 0x55, 0xd3, 0x9a, 0x69, 0x16, 0x3f, 0xa8, 0xfd, 0x24, 0xcf, 0x5f, 0x83, 0x65, 0x5d, 0x23, 0xdc, 0xa3, 0xad, 0x96, 0x1c, 0x62, 0xf3, 0x56, 0x20, 0x85, 0x52, 0xbb, 0x9e, 0xd5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6d, 0x67, 0x0c, 0x35, 0x4e, 0x4a, 0xbc, 0x98, 0x04, 0xf1, 0x74, 0x6c, 0x08, 0xca, 0x23, 0x73, 0x27, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

void setup()
{
    mod = BN_bin2bn( mod_buffer, /*len*/192, NULL );
    
    // modOrder = ( mod - 1 ) / 2
    BIGNUM* postSubtract = BN_new();
    BIGNUM* oneBN = BN_new();
    int ret = BN_one( oneBN );
    if ( ret != 1 )
    {
        printf( "setup: BN_one failed: %d", ret );
    }

    ret = BN_sub( postSubtract, mod, oneBN );  // r = a - b
    if ( ret != 1 )
    {
        printf( "setup: BN_sub failed: %d", ret );
    }
    BN_clear_free( oneBN );
    
    modOrder = BN_new();
    ret = BN_rshift1( modOrder, postSubtract ); // r = a Ö 2
    if ( ret != 1 )
    {
        printf( "setup: BN_rshift1 failed: %d", ret );
    }
    BN_clear_free( postSubtract );
    
    g2 = BN_new();
    g3 = BN_new();
    c1 = BN_new();
    c2 = BN_new();
    d1 = BN_new();
    d2 = BN_new();
    g3a = BN_new();
    
    // exponent used in step 1
    gen = BN_new();
    ret = BN_set_word( gen, 2 );
    
    match = 0;
}


unsigned int step1( unsigned char* buffer, int buflen )
{
    // self.x2 = createRandomExponent()
    // self.x3 = createRandomExponent()
    x2 = createRandomExponent();
    x3 = createRandomExponent();

    // g2 = pow( gen, x2, mod)  // genx^x2 % mod
    g2 = my_pow( gen, x2, mod );
    
    // g3 = pow( gen, x3, mod )
    g3 = my_pow( gen, x3, mod );
    
    // (c1, d1) = self.createLogProof(1, self.x2)
    createLogProof( "1", x2, c1, d1 );
    // (c2, d2) = self.createLogProof(2, self.x3)
    createLogProof( "2", x3, c2, d2 );

    /*
     # Send g2a, g3a, c1, d1, c2, d2
     return packList(self.g2, self.g3, c1, d1, c2, d2)
     */
    memset( buffer, 0x00, buflen );
    unsigned char* next = simplePack( buffer, g2 );
    next = simplePack( next, g3 );
    next = simplePack( next, c1 );
    next = simplePack( next, d1 );
    next = simplePack( next, c2 );
    next = simplePack( next, d2 );
    
    return ( unsigned int )( next - buffer );
}

unsigned int step2( unsigned char* buffer, int buflen )
{
    BIGNUM* g2a_new = BN_new();
    BIGNUM* c1_new = BN_new();
    BIGNUM* d1_new = BN_new();
    BIGNUM* c2_new = BN_new();
    BIGNUM* d2_new = BN_new();
    
    // (g2a, g3a, c1, d1, c2, d2) = unpackList(buffer)
    unsigned char* ptr = simpleUnpack( buffer, g2a_new);
    ptr = simpleUnpack( ptr, g3a);
    ptr = simpleUnpack( ptr, c1_new);
    ptr = simpleUnpack( ptr, d1_new);
    ptr = simpleUnpack( ptr, c2_new);
    ptr = simpleUnpack( ptr, d2_new);
    
    // if not self.checkLogProof('1', g2a, c1, d1):
    //    raise ValueError("Proof 1 check failed")
    if ( checkLogProof( "1", g2a_new, c1_new, d1_new ) != 1 )
        printf( "checkLogProof g2, c1, d1 failed!\n" );
    
    // if not self.checkLogProof('2', g3a, c2, d2):
    //    raise ValueError("Proof 2 check failed")
    if ( checkLogProof( "2", g3a, c2_new, d2_new ) != 1 )
        printf( "checkLogProof g3, c2, d2 failed!\n" );
    
    // self.x2 = createRandomExponent()
    // self.x3 = createRandomExponent()
    x2 = createRandomExponent();
    x3 = createRandomExponent();
    
    // self.g2 = pow(self.gen, self.x2, self.mod)
    g2 = my_pow( gen, x2, mod );

    // self.g3 = pow(self.gen, self.x3, self.mod)
    g3 = my_pow( gen, x3, mod );
    
    BIGNUM* c3_new = BN_new();
    BIGNUM* d3_new = BN_new();
    BIGNUM* c4_new = BN_new();
    BIGNUM* d4_new = BN_new();
    // (c3, d3) = self.createLogProof('3', self.x2)
    // (c4, d4) = self.createLogProof('4', self.x3)
    createLogProof( "3", x2, c3_new, d3_new );
    createLogProof( "4", x3, c4_new, d4_new );
    
    // self.gb2 = pow(self.g2a, self.x2, self.mod)
    gb2 = my_pow( g2a_new, x2, mod );
    
    // self.gb3 = pow(self.g3a, self.x3, self.mod)
    gb3 = my_pow( g3a, x3, mod );

    BIGNUM* r = createRandomExponent();
    
    // self.pb = pow(self.gb3, r, self.mod)
    pb = my_pow( gb3, r, mod );
    
    // self.qb = mulm(pow(self.gen, r, self.mod), pow(self.gb2, self.secret, self.mod), self.mod)
    // Step A: pow(self.gen, r, self.mod)
    BIGNUM* stepA = my_pow( gen, r, mod );
    
    // Step B: pow(self.gb2, self.secret, self.mod)
    BIGNUM* stepB = my_pow( gb2, secret, mod );
    
    // Step C: mulm( StepA, StepB, self.mod)
    qb = mulm( stepA, stepB, mod );

    // (c5, d5, d6) = self.createCoordsProof('5', self.gb2, self.gb3, r)
    BIGNUM* c5 = BN_new();
    BIGNUM* d5 = BN_new();
    BIGNUM* d6 = BN_new();
    createCoordsProof( "5", gb2, gb3, r, c5, d5, d6 );
    
    // # Sends g2b, g3b, pb, qb, all the c's and d's
    // return packList(self.g2, self.g3, self.pb, self.qb, c3, d3, c4, d4, c5, d5, d6)
    memset( buffer, 0x00, buflen );
    unsigned char* next = simplePack( buffer, g2 );
    next = simplePack( next, g3 );
    next = simplePack( next, pb );
    next = simplePack( next, qb );
    next = simplePack( next, c3_new );
    next = simplePack( next, d3_new );
    next = simplePack( next, c4_new );
    next = simplePack( next, d4_new );
    next = simplePack( next, c5 );
    next = simplePack( next, d5 );
    next = simplePack( next, d6 );
    
    // clean up
    BN_clear_free( g2a_new );
    BN_clear_free( c1_new );
    BN_clear_free( d1_new );
    BN_clear_free( c2_new );
    BN_clear_free( d2_new );
    BN_clear_free( c3_new );
    BN_clear_free( d3_new );
    BN_clear_free( c4_new );
    BN_clear_free( d4_new );
    BN_clear_free( r );
    BN_clear_free( stepA );
    BN_clear_free( stepB );
    BN_clear_free( c5 );
    BN_clear_free( d5 );
    BN_clear_free( d6 );
    
    return ( unsigned int )( next - buffer );
}

unsigned int step3( unsigned char* buffer, int buflen )
{
    BIGNUM* g2b_new = BN_new();
    BIGNUM* g3b_new = BN_new();
    BIGNUM* pb_new = BN_new();
    BIGNUM* qb_new = BN_new();
    BIGNUM* c3_new = BN_new();
    BIGNUM* d3_new = BN_new();
    BIGNUM* c4_new = BN_new();
    BIGNUM* d4_new = BN_new();
    BIGNUM* c5_new = BN_new();
    BIGNUM* d5_new = BN_new();
    BIGNUM* d6_new = BN_new();
    
    // (g2b, g3b, pb, qb, c3, d3, c4, d4, c5, d5, d6) = unpackList(buffer)
    unsigned char* ptr = simpleUnpack( buffer, g2b_new );
    ptr = simpleUnpack( ptr, g3b_new);
    ptr = simpleUnpack( ptr, pb_new);
    ptr = simpleUnpack( ptr, qb_new);
    ptr = simpleUnpack( ptr, c3_new);
    ptr = simpleUnpack( ptr, d3_new);
    ptr = simpleUnpack( ptr, c4_new);
    ptr = simpleUnpack( ptr, d4_new);
    ptr = simpleUnpack( ptr, c5_new);
    ptr = simpleUnpack( ptr, d5_new);
    ptr = simpleUnpack( ptr, d6_new);
    
    // if not self.checkLogProof('3', g2b, c3, d3):
    //    raise ValueError("Proof 3 check failed")
    if ( checkLogProof( "3", g2b_new, c3_new, d3_new ) != 1 )
        printf( "Proof 3 check failed!\n" );
    
    // if not self.checkLogProof('4', g3b, c4, d4):
    //    raise ValueError("Proof 4 check failed")
    if ( checkLogProof( "4", g3b_new, c4_new, d4_new ) != 1 )
        printf( "Proof 4 check failed!\n" );
    
    // self.g2b = g2b
    // self.g3b = g3b
    g3b = g3b_new;

    // self.ga2 = pow(self.g2b, self.x2, self.mod)
    BIGNUM* ga2 = my_pow( g2b_new, x2, mod );
    
    // self.ga3 = pow(self.g3b, self.x3, self.mod)
    BIGNUM* ga3 = my_pow( g3b_new, x3, mod );
    
    // if not self.checkCoordsProof('5', c5, d5, d6, self.ga2, self.ga3, pb, qb):
    //    raise ValueError("Proof 5 check failed")
    if ( checkCoordsProof( "5", c5_new, d5_new, d6_new, ga2, ga3, pb_new, qb_new ) != 1 )
        printf( "Proof 5 check failed!\n" );
    
    // s = createRandomExponent()
    BIGNUM* s = createRandomExponent();
                    
    qb = qb_new;
    pb = pb_new;
    
    // self.pa = pow(self.ga3, s, self.mod)
    pa = my_pow( ga3, s, mod );
    
    // self.qa = mulm(pow(self.gen, s, self.mod), pow(self.ga2, self.secret, self.mod), self.mod)
    // Step A = pow(self.gen, s, self.mod)
    // Step B = pow(self.ga2, self.secret, self.mod)
    // Step C = mulm( StepA, StepB, self.mod)
    BIGNUM* stepA = my_pow( gen, s, mod );
    BIGNUM* stepB = my_pow( ga2, secret, mod );
    qa = mulm( stepA, stepB, mod );
   
    // (c6, d7, d8) = self.createCoordsProof('6', self.ga2, self.ga3, s)
    BIGNUM* c6 = BN_new();
    BIGNUM* d7 = BN_new();
    BIGNUM* d8 = BN_new();
    createCoordsProof( "6", ga2, ga3, s, c6, d7, d8 );
    
    // inv = self.invm(qb)
    BIGNUM* inv = invm( qb_new, mod );
    
    // self.ra = pow(mulm(self.qa, inv, self.mod), self.x3, self.mod)
    // Step A = mulm(self.qa, inv, self.mod)
    stepA = mulm( qa, inv, mod );
    BIGNUM* ra = my_pow( stepA, x3, mod );
    
    // (c7, d9) = self.createEqualLogsProof('7', self.qa, inv, self.x3)
    BIGNUM* c7 = BN_new();
    BIGNUM* d9 = BN_new();
    createEqualLogsProof( "7", qa, inv, x3, c7, d9 );

    // # Sends pa, qa, ra, c6, d7, d8, c7, d9
    // return packList(self.pa, self.qa, self.ra, c6, d7, d8, c7, d9)
    memset( buffer, 0x00, buflen );
    unsigned char* next = simplePack( buffer, pa );
    next = simplePack( next, qa );
    next = simplePack( next, ra );
    next = simplePack( next, c6 );
    next = simplePack( next, d7 );
    next = simplePack( next, d8 );
    next = simplePack( next, c7 );
    next = simplePack( next, d9 );

    // clean up
    BN_clear_free( g2b_new );
    BN_clear_free( c3_new );
    BN_clear_free( d3_new );
    BN_clear_free( c4_new );
    BN_clear_free( d4_new );
    BN_clear_free( c5_new );
    BN_clear_free( d5_new );
    BN_clear_free( d6_new );
    BN_clear_free( ga2 );
    BN_clear_free( ga3 );
    BN_clear_free( s );
    BN_clear_free( stepA );
    BN_clear_free( stepB );
    BN_clear_free( c6 );
    BN_clear_free( d7 );
    BN_clear_free( d8 );
    BN_clear_free( inv );
    BN_clear_free( ra );
    BN_clear_free( c7 );
    BN_clear_free( d9 );

    return ( unsigned int )( next - buffer );
}

unsigned int step4( unsigned char* buffer, int buflen )
{
    BIGNUM* pa = BN_new();
    BIGNUM* qa = BN_new();
    BIGNUM* ra = BN_new();
    BIGNUM* c6 = BN_new();
    BIGNUM* d7 = BN_new();
    BIGNUM* d8 = BN_new();
    BIGNUM* c7 = BN_new();
    BIGNUM* d9 = BN_new();
    
    // (g2b, g3b, pb, qb, c3, d3, c4, d4, c5, d5, d6) = unpackList(buffer)
    unsigned char* ptr = simpleUnpack( buffer, pa );
    ptr = simpleUnpack( ptr, qa);
    ptr = simpleUnpack( ptr, ra);
    ptr = simpleUnpack( ptr, c6);
    ptr = simpleUnpack( ptr, d7);
    ptr = simpleUnpack( ptr, d8);
    ptr = simpleUnpack( ptr, c7);
    ptr = simpleUnpack( ptr, d9);

    // if not self.isValidArgument(pa) or not self.isValidArgument(qa) or not self.isValidArgument(ra):
    //    raise ValueError("Invalid pa/qa/ra values")
        
    // if not self.checkCoordsProof('6', c6, d7, d8, self.gb2, self.gb3, pa, qa):
    //    raise ValueError("Proof 6 check failed")
    
    if ( checkCoordsProof( "6", c6, d7, d8, gb2, gb3, pa, qa ) != 1 )
        printf( "Proof 6 check failed" );
    
    // if not self.checkEqualLogs('7', c7, d9, self.g3a, mulm(qa, self.invm(self.qb), self.mod), ra):
    //    raise ValueError("Proof 7 check failed")
    // Step A: self.invm(self.qb)
    // Step B: mulm(qa, StepA, self.mod )
    // Step C: checkEqualLogs( '7',c7, d9, self.g3a, StepB, ra):
    BIGNUM* stepA = invm( qb, mod );

    BIGNUM* stepB = mulm( qa, stepA, mod );
    if ( checkEqualLogs( "7", c7, d9, g3a, stepB, ra)  != 1 )
        printf( "Proof 7 check failed" );
    
    // inv = self.invm(self.qb)
    BIGNUM* inv = invm( qb, mod );
    // rb = pow(mulm(qa, inv, self.mod), self.x3, self.mod)
    // Step A = mulm(qa, inv, self.mod)
    stepA = mulm( qa, inv, mod );
    BIGNUM* rb = my_pow( stepA, x3, mod );
    BN_clear_free( stepA );
    
    // (c8, d10) = self.createEqualLogsProof('8', qa, inv, self.x3)
    BIGNUM* c8 = BN_new();
    BIGNUM* d10 = BN_new();
    createEqualLogsProof( "8", qa, inv, x3, c8, d10 );
    
    // rab = pow(ra, self.x3, self.mod)
    BIGNUM* rab = my_pow( ra, x3, mod );
                
    // inv = self.invm(self.pb)
    inv = invm( pb, mod );
    
    // if rab == mulm(pa, inv, self.mod):
    //    self.match = True
    stepA = mulm( pa, inv, mod );
    if ( BN_cmp( rab, stepA ) == 0 )
        match = 1;
                    
    // # Send rb, c8, d10
    // return packList(rb, c8, d10)
    memset( buffer, 0x00, buflen );
    unsigned char* next = simplePack( buffer, rb );
    next = simplePack( next, c8 );
    next = simplePack( next, d10 );
    
    // clean up
    BN_clear_free( stepB );
    BN_clear_free( inv );
    BN_clear_free( stepA );
    BN_clear_free( rb );
    BN_clear_free( c8 );
    BN_clear_free( d10 );
    BN_clear_free( rab );
    BN_clear_free( pa );
    BN_clear_free( qa );
    BN_clear_free( ra );
    BN_clear_free( c6 );
    BN_clear_free( d7 );
    BN_clear_free( d8 );
    BN_clear_free( c7 );
    BN_clear_free( d9 );
    
    return ( unsigned int )( next - buffer );
}

void step5( unsigned char* buffer, int buflen )
{
    BIGNUM* rb = BN_new();
    BIGNUM* c8 = BN_new();
    BIGNUM* d10 = BN_new();
    
    // (rb, c8, d10) = unpackList(buffer)
    unsigned char* ptr = simpleUnpack( buffer, rb );
    ptr = simpleUnpack( ptr, c8);
    ptr = simpleUnpack( ptr, d10);
    
    // if not self.isValidArgument(rb):
    //    raise ValueError("Invalid rb values")
        
    // if not self.checkEqualLogs('8', c8, d10, self.g3b, mulm(self.qa, self.invm(self.qb), self.mod), rb):
    //    raise ValueError("Proof 8 check failed")
    // Step A: self.invm(self.qb)
    // Step B: mulm(self.qa, Step A, self.mod)
    // Step C: checkEqualLogs('8', c8, d10, self.g3b, Step B, rb):
    BIGNUM* stepA = invm( qb, mod );
    BIGNUM* stepB = mulm( qa, stepA, mod );
    if ( checkEqualLogs( "8", c8, d10, g3b, stepB, rb ) != 1 )
        printf( "Proof 8 check failed\n" );
    BN_clear_free( stepA );
    
    // rab = pow(rb, self.x3, self.mod)
    BIGNUM* rab = my_pow( rb, x3, mod );
    
    // inv = self.invm(self.pb)
    BIGNUM* inv = invm( pb, mod );

    // if rab == mulm(self.pa, inv, self.mod):
    //    self.match = True
    stepA = mulm( pa, inv, mod );
    if ( BN_cmp( rab, stepA ) == 0 )
        match = 1;

    // clean up
    BN_clear_free( stepA );
    BN_clear_free( stepB );
    BN_clear_free( rab );
    BN_clear_free( inv );
    BN_clear_free( rb );
    BN_clear_free( c8 );
    BN_clear_free( d10 );
}

void cleanup()
{
    BN_clear_free( x2 );
    BN_clear_free( x3 );
    BN_clear_free( g2 );
    BN_clear_free( g3 );
    BN_clear_free( c1 );
    BN_clear_free( c2 );
    BN_clear_free( d1 );
    BN_clear_free( d2 );
    BN_clear_free( gb2 );
    BN_clear_free( gb3 );
    BN_clear_free( qa );
    BN_clear_free( qb );
    BN_clear_free( pb );
    BN_clear_free( g3a );
    BN_clear_free( g3b );
    BN_clear_free( pa );
    BN_clear_free( mod );
    BN_clear_free( gen );
    BN_clear_free( modOrder );
}

// usage: smp <IP address to connect to>
int main( int argc, char** argv )
{
    if ( argc != 2 ) /* argc should be 2 for correct execution */
    {
        printf( "usage:\n\tsmp <ipaddress>\n\tsmp server\n" );
        return EXIT_FAILURE;
    }
    
    int bServerMode = strstr( "server", argv[ 1 ] ) != 0;

    setup();
    
    unsigned char holder[ BUFFER_SIZE ];
    memset( holder, 0x00, BUFFER_SIZE );
    
    if ( !bServerMode )
    {
        // we are talking to the server at ip address argv[ 1 ]
        char input_string[ 256 ];
        //printf( "Enter a shared secret: " );
        //readLine( input_string, 256 );
        strcpy( input_string, "testme" );
        secret = binEncode( input_string, strlen( input_string ) );
        
        /*****************************************************/
        /*****************************************************/
        /*  Do Step 1 and send to other side */
        /*****************************************************/
        /*****************************************************/
        int len = step1( holder, BUFFER_SIZE );
        
        int serverfd = connect_to_server( argv[ 1 ] );
        if ( serverfd == 1 )
            return EXIT_FAILURE;
        
        write_to_server( serverfd, holder, len );
        // dumpBuff( holder, len );
        
        /*****************************************************/
        /*****************************************************/
        /*  Get results from other side. */
        /*  Other side performed Step 2. */
        /*****************************************************/
        /*****************************************************/
        memset( holder, 0x00, BUFFER_SIZE );
        len = revc_from_server( serverfd, holder, BUFFER_SIZE );
        // dumpBuff( holder, len );
        
        /*****************************************************/
        /*****************************************************/
        /*  Do Step 3 and send to the other side */
        /*****************************************************/
        /*****************************************************/
        step3( holder, BUFFER_SIZE );
        write_to_server( serverfd, holder, len );
        
        /*****************************************************/
        /*****************************************************/
        /*  Get bytes from other side and do Step 5 */
        /*****************************************************/
        /*****************************************************/
        memset( holder, 0x00, BUFFER_SIZE );
        len = revc_from_server( serverfd, holder, BUFFER_SIZE );
        // dumpBuff( holder, len );
        
        step5( holder, len );
        
        disconnect_from_server( serverfd );
    }
    else    // we are in server mode, other side will send us data first
    {
        int listenfd = listen_server();
        /*if ( listenfd == 1 )
            return EXIT_FAILURE;
        TODO: error checking
        */
        
        char input_string[ 256 ];
        //printf( "Enter a shared secret: " );
        //readLine( input_string, 256 );
        strcpy( input_string, "testme" );
        secret = binEncode( input_string, strlen( input_string ) );
        
        int len = revc_from_server( listenfd, holder, BUFFER_SIZE );
        // dumpBuff( holder, BUFFER_SIZE);
        
        /*****************************************************/
        /*****************************************************/
        /*  Do Step 2 and send to other side */
        /*****************************************************/
        /*****************************************************/
        len = step2( holder, BUFFER_SIZE  );
        write_to_server( listenfd, holder, len );

        len = revc_from_server( listenfd, holder, BUFFER_SIZE );
        // dumpBuff( holder, len );
        
        /*****************************************************/
        /*****************************************************/
        /*  Do Step 4 and send to other side */
        /*****************************************************/
        /*****************************************************/
        len = step4( holder, BUFFER_SIZE );
        write_to_server( listenfd, holder, len );
        
        disconnect_from_server( listenfd );
    }
    
    
    if ( match == 1 )
        printf( "Secrets match\n" );
    else
        printf( "Secrets do not match\n");
    
    cleanup();
    return EXIT_SUCCESS;
}
