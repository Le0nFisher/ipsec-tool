#ifndef BN_ADD_H
#define BN_ADD_H

#include "bn_lcl.h"
#include "bn_asm.h"
#include "bn_lib.h"

int BN_uadd_sm2(BN_ULONG *r, int *rl, BN_ULONG *a, int al, BN_ULONG *b, int bl);
int BN_usub_sm2(BN_ULONG *r, int *rl, BN_ULONG *a, int al, BN_ULONG *b, int bl);

#endif
