#ifndef ECP_SMPL_H
#define ECP_SMPL_H

#include "bn.h"
#include "bn_mont.h"
#include "bn_mul.h"
#include "bn_div.h"
#include "bn_mod.h"
#include "bn_gcd.h"
#include "bn_add.h"
#include "bn_shift.h"
#include "bn_lib.h"
#include "ec_lcl.h"

void ec_GFp_simple_point_get_affine_coordinates_GFp(EC_GROUP *group, EC_POINT *point, BIGNUM_SM2 *x, BIGNUM_SM2 *y);
void ec_GFp_simple_add(EC_GROUP *group, EC_POINT *r, EC_POINT *a, EC_POINT *b);
void ec_GFp_simple_dbl(EC_GROUP *group, EC_POINT *r, EC_POINT *a);
int ec_GFp_simple_is_at_infinity(EC_GROUP *group, EC_POINT *point);

#endif

