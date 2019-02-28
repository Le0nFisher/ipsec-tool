#ifndef BN_MONT_H
#define BN_MONT_H

#include "bn.h"
#include "bn_gcd.h"
#include "bn_div.h"
#include "bn_lib.h"
#include "bn_add.h"
#include "ec_bn.h"





void BN_MONT_CTX_set_sm2(BN_ULONG *Mod, int ModLen, BN_ULONG *n0, BN_ULONG *RR);
void BN_mod_mul_montgomery_sm2(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, BN_ULONG *M, int M_Len, BN_ULONG n0);
void BN_mod_mul_montgomery_one_sm2(BN_ULONG *r, BN_ULONG *a, BN_ULONG *M, int M_Len, BN_ULONG n0);

#endif
