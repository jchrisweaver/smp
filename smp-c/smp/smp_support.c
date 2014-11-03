//
//  smp_support.c
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

#include "smp_support.h"
#include "smp.h"
#include "utils_openssl.h"

//def createLogProof(self, version, x):
void createLogProof( char* version, BIGNUM* x, BIGNUM* c, BIGNUM* d )
{
    // randExponent = createRandomExponent()
    BIGNUM* randExponent = createRandomExponent();
    
    // c = sha256( version + str( pow( self.gen, randExponent, self.mod ) ) )
    BIGNUM* exponPower = my_pow( gen, randExponent, mod );
    
    BIGNUM* c_temp = sha_with_version( version, exponPower, NULL );
    BN_copy( c, c_temp );
    
    // d = ( randExponent - mulm( x, c, self.modOrder ) ) % self.modOrder
    BIGNUM* tmp = mulm( x, c, modOrder );
    BIGNUM* d_temp = subm( randExponent, tmp, modOrder );
    BN_copy( d, d_temp );
    
    // clean up
    BN_clear_free( randExponent );
    BN_clear_free( exponPower );
    BN_clear_free( c_temp );
    BN_clear_free( tmp );
    BN_clear_free( d_temp );
}

// def createCoordsProof(self, version, g2, g3, r):
void createCoordsProof( char* version, BIGNUM* g2, BIGNUM* g3, BIGNUM* r, BIGNUM* c, BIGNUM* d1, BIGNUM* d2 )
{
    // r1 = createRandomExponent()
    // r2 = createRandomExponent()
    BIGNUM* r1 = createRandomExponent();
    BIGNUM* r2 = createRandomExponent();
    
    // tmp1 = pow(g3, r1, self.mod)
    BIGNUM* tmp1 = my_pow( g3, r1, mod );
    
    // tmp2 = mulm( pow(self.gen, r1, self.mod), pow(g2, r2, self.mod), self.mod)
    // Step A = pow(self.gen, r1, self.mod)
    BIGNUM* stepA = my_pow( gen, r1, mod );
    
    // Step B = pow(g2, r2, self.mod)
    BIGNUM* stepB = my_pow( g2, r2, mod );
    
    // Step C = mulm( StepA, StepB, mod )
    BIGNUM* tmp2 = mulm( stepA, stepB, mod );
    
    // c = sha256(version + str(tmp1) + str(tmp2))
    BIGNUM* tmp3 = sha_with_version( version, tmp1, tmp2 );
    BN_copy( c, tmp3 );
    
    // d1 = (r1 - mulm(r, c, self.modOrder)) % self.modOrder
    BIGNUM* resultA = mulm( r, c, modOrder );
    BIGNUM* d1_temp = subm( r1, resultA, modOrder );
    BN_copy( d1, d1_temp );
    
    // d2 = (r2 - mulm(self.secret, c, self.modOrder)) % self.modOrder
    BIGNUM* resultB = mulm( secret, c, modOrder );
    BIGNUM* d2_temp = subm( r2, resultB, modOrder );
    BN_copy( d2, d2_temp );

    // clean up
    BN_clear_free( r1 );
    BN_clear_free( r2 );
    BN_clear_free( tmp1 );
    BN_clear_free( stepA );
    BN_clear_free( stepB );
    BN_clear_free( tmp2 );
    BN_clear_free( tmp3 );
    BN_clear_free( resultA );
    BN_clear_free( d1_temp );
    BN_clear_free( resultB );
    BN_clear_free( d2_temp );
    
    // return (c, d1, d2)
}

// def checkCoordsProof(self, version, c, d1, d2, g2, g3, p, q):
int checkCoordsProof( char* version, BIGNUM* c, BIGNUM* d1, BIGNUM* d2, BIGNUM* g2, BIGNUM* g3, BIGNUM* p, BIGNUM* q )
{
    // tmp1 = mulm(pow(g3, d1, self.mod), pow(p, c, self.mod), self.mod)
    // Step A = pow(g3, d1, self.mod)
    BIGNUM* stepA = my_pow( g3, d1, mod );
    
    // Step B = pow(p, c, self.mod)
    BIGNUM* stepB = my_pow( p, c, mod );
    
    // Step C = mulm( StepA, StepB, mod )
    BIGNUM* tmp1 = mulm( stepA, stepB, mod );
    
    // tmp2 = mulm(mulm(pow(self.gen, d1, self.mod), pow(g2, d2, self.mod), self.mod), pow(q, c, self.mod), self.mod)
    // Step A = pow(self.gen, d1, self.mod)
    stepA = my_pow( gen, d1, mod );
    
    // Step B = pow(g2, d2, self.mod)
    stepB = my_pow( g2, d2, mod );
    
    // Step C = pow(q, c, self.mod)
    BIGNUM* stepC = my_pow( q, c, mod );
    
    // Step D = mulm( StepA, StepB, self.mod )
    BIGNUM* stepD = mulm( stepA, stepB, mod );
    
    // Step E = mulm( StepD, StepC, mod )
    BIGNUM* tmp2 = mulm( stepD, stepC, mod );
    
    // cprime = sha256(version + str(tmp1) + str(tmp2))
    BIGNUM* cprime = sha_with_version( version, tmp1, tmp2 );
    int ret = BN_cmp( c, cprime );
    
    // clean up
    BN_clear_free( stepA );
    BN_clear_free( stepB );
    BN_clear_free( tmp1 );
    BN_clear_free( tmp2 );
    BN_clear_free( stepC );
    BN_clear_free( stepD );
    BN_clear_free( cprime );
    
    // return (c == cprime)
    return ( ret == 0 );
}

// def checkLogProof(self, version, g, c, d):
int checkLogProof( char* version, BIGNUM* g, BIGNUM* c, BIGNUM* d )
{
    // gd = pow( gen, d, mod )
    BIGNUM* gd = my_pow( gen, d, mod );
    
    // gc = pow( g, c, mod)
    BIGNUM* gc = my_pow( g, c, mod );
    
    // gdgc = gd * gc % self.mod
    BIGNUM* gdgc = mulm( gd, gc, mod );
    
    // return (sha256(version + str(gdgc)) == c)
    BIGNUM* bnShaBytes = sha_with_version( version, gdgc, NULL );
    int ret = BN_cmp( bnShaBytes, c );
    
    // clean up
    BN_clear_free( gd );
    BN_clear_free( gc );
    BN_clear_free( gdgc );
    BN_clear_free( bnShaBytes );
    
    return ( ret == 0 );
}

// def createEqualLogsProof(self, version, qa, qb, x):
void createEqualLogsProof( char* version, BIGNUM* qa, BIGNUM* qb, BIGNUM* x, /* out */BIGNUM* c, /* out */BIGNUM* d )
{
    // r = createRandomExponent()
    BIGNUM* r = createRandomExponent();
    
    // tmp1 = pow(self.gen, r, self.mod)
    BIGNUM* tmp1 = my_pow( gen, r, mod );
    
    // qab = mulm(qa, qb, self.mod)
    BIGNUM* qab = mulm( qa, qb, mod );
    
    // tmp2 = pow(qab, r, self.mod)
    BIGNUM* tmp2 = my_pow( qab, r, mod );
    
    // c = sha256(version + str(tmp1) + str(tmp2))
    BIGNUM* c_temp = sha_with_version( version, tmp1, tmp2 );
    BN_copy( c, c_temp );
    BN_clear_free( tmp1 );
    
    // tmp1 = mulm(x, c, self.modOrder)
    tmp1 = mulm( x, c, modOrder );
    
    // d = (r - tmp1) % self.modOrder
    BIGNUM* d_temp = subm( r, tmp1, modOrder );
    BN_copy( d, d_temp );
    
    // return (c, d)
    
    // clean up
    BN_clear_free( r );
    BN_clear_free( tmp1 );
    BN_clear_free( qab );
    BN_clear_free( tmp2 );
    BN_clear_free( c_temp );
    BN_clear_free( d_temp );
}

// def checkEqualLogs(self, version, c, d, g3, qab, r):
int checkEqualLogs( char* version, BIGNUM* c, BIGNUM* d, BIGNUM* g3, BIGNUM* qab, BIGNUM* r )
{
    // tmp1 = mulm(pow(self.gen, d, self.mod), pow(g3, c, self.mod), self.mod)
    // Step A = pow(self.gen, d, self.mod)
    BIGNUM* stepA = my_pow( gen, d, mod );
    
    // Step B = pow(g3, c, self.mod)
    BIGNUM* stepB = my_pow( g3, c, mod );
    
    // Step C = mulm( StepA, StepB, mod )
    BIGNUM* tmp1 = mulm( stepA, stepB, mod );
    BN_clear_free( stepA );
    BN_clear_free( stepB );
    
    // tmp2 = mulm(pow(qab, d, self.mod), pow(r, c, self.mod), self.mod)
    // Step A = pow(qab, d, self.mod)
    stepA = my_pow( qab, d, mod );
    
    // Step B = pow(r, c, self.mod)
    stepB = my_pow( r, c, mod );
    
    // Step C = mulm( StepA, StepB, mod )
    BIGNUM* tmp2 = mulm( stepA, stepB, mod );
    
    // cprime = sha256(version + str(tmp1) + str(tmp2))
    BIGNUM* cprime = sha_with_version( version, tmp1, tmp2 );
    int ret = ( BN_cmp( c, cprime ) == 0 );
    
    // clean up
    BN_clear_free( stepA );
    BN_clear_free( stepB );
    BN_clear_free( tmp1 );
    BN_clear_free( tmp2 );
    BN_clear_free( cprime );
    
    // return (c == cprime)
    return ret;
}

