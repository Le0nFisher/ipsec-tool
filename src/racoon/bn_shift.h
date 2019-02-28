#ifndef BN_SHIFT_H
#define BN_SHIFT_H

#include "bn.h"
#include "bn_lib.h"
#include "ec_bn.h"

void BN_rshift1_sm2(BIGNUM_SM2 *r, int *r_top, BIGNUM_SM2 *a, int a_top);
int BN_lshift_sm2(BN_ULONG *r, int *rl, BN_ULONG *a, int al, int n);
int BN_rshift_sm2(BN_ULONG *r, int *rl, BN_ULONG *a, int al, int n);

int two_number_same(BN_ULONG *a, int len, BN_ULONG *b);

#endif

