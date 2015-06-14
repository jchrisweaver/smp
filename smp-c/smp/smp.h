//
//  smp.h
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

#ifndef __smp__smp__
#define __smp__smp__
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <openssl/bn.h>

BIGNUM* x2; // random exponent
BIGNUM* x3; // random exponent
BIGNUM* g2; // result of power and mod - step 1
BIGNUM* g3; // result of power and mod - step 1
BIGNUM* c1;
BIGNUM* c2;
BIGNUM* d1;
BIGNUM* d2;
BIGNUM* gb2;
BIGNUM* gb3;
BIGNUM* qa;
BIGNUM* qb;
BIGNUM* pb;

BIGNUM* g3a;
BIGNUM* g3b;
BIGNUM* pa;

BIGNUM* mod;
BIGNUM* gen;
BIGNUM* modOrder;

BIGNUM* secret;
int match;

#define BUFFER_SIZE 4096


#endif /* defined(__smp__smp__) */
