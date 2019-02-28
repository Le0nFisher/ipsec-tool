#ifndef BN_ASM_H
#define BN_ASM_H

#include "bn_lcl.h"
#include "bn_lib.h"

BN_ULONG bn_mul_add_words_sm2(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w);
BN_ULONG bn_mul_words_sm2(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w);
BN_ULONG bn_div_words_sm2(BN_ULONG h, BN_ULONG l, BN_ULONG d);
BN_ULONG bn_add_words_sm2(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b, int n);
BN_ULONG bn_sub_words_sm2(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b, int n);


#endif
