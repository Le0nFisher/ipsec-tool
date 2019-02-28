#ifndef BN_MUL_H
#define BN_MUL_H

#include <stdlib.h>
#include <malloc.h>
#include "bn_lcl.h"
#include "bn_asm.h"
#include "bn_lib.h"
#include "bn_add.h"
#include "bn_shift.h"
#include "bn_lib.h"
#include "ecp_smpl.h"
#include "ec_mult.h"

void BN_mul_nomal_sm2(BN_ULONG *r, BN_ULONG *a, int na, BN_ULONG *b, int nb);
void BN_mul_sm2(BN_ULONG *r, int *rl, BN_ULONG *a, int al, BN_ULONG *b, int bl);

#endif

