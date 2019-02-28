#ifndef EC_MULT_H
#define EC_MULT_H

#include <stdlib.h>
#include <malloc.h>
#include "bn.h"
#include "bn_add.h"
#include "bn_shift.h"
#include "bn_lib.h"
#include "ec_bn.h"
#include "ec_lcl.h"
#include "ecp_smpl.h"

signed char *compute_wNAF(BIGNUM_SM2 *scalar, int w, int order_top, int *ret_len);
void EC_POINTs_mul_sm2(EC_GROUP *group, EC_POINT *R, EC_POINT *P, BIGNUM_SM2 *k, EC_POINT *Q, BIGNUM_SM2 *l); 

#endif
