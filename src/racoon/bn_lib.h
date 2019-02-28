#ifndef BN_LIB_H
#define BN_LIB_H

#include "bn.h"

int BN_is_zero_sm2(BN_ULONG *a, BN_ULONG al);
int BN_is_one_sm2(BN_ULONG *a, BN_ULONG al);
void bn_fix_top_sm2(BN_ULONG *a, int *al);
int BN_num_bits_word_sm2(BN_ULONG l);
int BN_num_bits_sm2(BN_ULONG *a, int al);
int BN_ucmp_sm2(BN_ULONG *a, int al, BN_ULONG *b, int bl);

#endif

