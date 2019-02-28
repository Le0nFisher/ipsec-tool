#ifndef BN_DIV_H
#define BN_DIV_H
#include "bn.h"
#include "bn_lcl.h"
#include "bn_lib.h"
#include "bn_shift.h"
#include "bn_add.h"

void BN_div_sm2(BN_ULONG *dv, int *dv_len, BN_ULONG *rm, int *rm_len, BN_ULONG *num, int num_len, BN_ULONG *divisor, int divisor_len);

#endif

