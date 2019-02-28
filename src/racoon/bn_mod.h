#ifndef BN_MOD_H
#define BN_MOD_H

#include "bn.h"
#include "bn_add.h"
#include "bn_lib.h"
#include "ec_bn.h"

void BN_mod_add_sm2(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, BN_ULONG *m, BN_ULONG mLen);
void BN_mod_sub_sm2(BN_ULONG *r, int *rl, BN_ULONG *a, BN_ULONG *b, BN_ULONG *m, BN_ULONG mLen);
void BN_mod_lshift1_sm2(BN_ULONG *r, BN_ULONG *a, BN_ULONG *m, BN_ULONG mLen);

#endif
