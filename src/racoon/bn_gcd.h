#ifndef BN_GCD_H
#define BN_GCD_H

#include "bn.h"
#include "bn_add.h"
#include "bn_mul.h"
#include "bn_div.h"

void BN_mod_inverse_sm2(BN_ULONG *in, int *in_len, BN_ULONG *a, int a_len, BN_ULONG *n, int n_len);

#endif
