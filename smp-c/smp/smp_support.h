//
//  smp_support.h
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

#ifndef __smp__smp_support__
#define __smp__smp_support__

#include <openssl/bn.h>

//def createLogProof(self, version, x):
void createLogProof( char* version, BIGNUM* x, BIGNUM* c, BIGNUM* d );

// def createCoordsProof(self, version, g2, g3, r):
void createCoordsProof( char* version, BIGNUM* g2, BIGNUM* g3, BIGNUM* r, BIGNUM* c, BIGNUM* d1, BIGNUM* d2 );

// def checkCoordsProof(self, version, c, d1, d2, g2, g3, p, q):
int checkCoordsProof( char* version, BIGNUM* c, BIGNUM* d1, BIGNUM* d2, BIGNUM* g2, BIGNUM* g3, BIGNUM* p, BIGNUM* q );

// def checkLogProof(self, version, g, c, d):
int checkLogProof( char* version, BIGNUM* g, BIGNUM* c, BIGNUM* d );

// def createEqualLogsProof(self, version, qa, qb, x):
void createEqualLogsProof( char* version, BIGNUM* qa, BIGNUM* qb, BIGNUM* x, /* out */BIGNUM* c, /* out */BIGNUM* d );

// def checkEqualLogs(self, version, c, d, g3, qab, r):
int checkEqualLogs( char* version, BIGNUM* c, BIGNUM* d, BIGNUM* g3, BIGNUM* qab, BIGNUM* r );

#endif /* defined(__smp__smp_support__) */
