#include "ecp_smpl.h"



void ec_GFp_simple_point_get_affine_coordinates_GFp(EC_GROUP *group, EC_POINT *point, BIGNUM_SM2 *x, BIGNUM_SM2 *y)
{
	BIGNUM_SM2 X, Y, Z, Z_1, Z_2, Z_3;
	int x_top, y_top;
	int Z_1_top, Z_2_top, Z_3_top;
	BN_ULONG temp[ECC_MAX_BLOCK_LEN_DWORD*2];
	int temp_top;

	/* transform  (X, Y, Z)  into  (x, y) := (X/Z^2, Y/Z^3) */
	
    BN_mod_mul_montgomery_one_sm2(X.d, point->X.d, group->field.d, group->field_top, group->n0);
	
    BN_mod_mul_montgomery_one_sm2(Y.d, point->Y.d, group->field.d, group->field_top, group->n0);

    BN_mod_mul_montgomery_one_sm2(Z.d, point->Z.d, group->field.d, group->field_top, group->n0);
	
	if(BN_is_one_sm2(Z.d, group->field_top))
	{
		memcpy(x, &X, BIGNUM_SIZE);
		memcpy(y, &Y, BIGNUM_SIZE);
	}
	else
	{
		BN_mod_inverse_sm2(Z_1.d, &Z_1_top, Z.d, group->field_top, group->field.d, group->field_top);	

		BN_mul_sm2(temp, &temp_top, Z_1.d, Z_1_top, Z_1.d, Z_1_top);
    
		BN_div_sm2(NULL, NULL, Z_2.d, &Z_2_top, temp, temp_top, group->field.d, group->field_top);

		BN_mul_sm2(temp, &temp_top, X.d, group->field_top, Z_2.d, Z_2_top);
    
		BN_div_sm2(NULL, NULL, x->d, &x_top, temp, temp_top, group->field.d, group->field_top);

		BN_mul_sm2(temp, &temp_top, Z_2.d, Z_2_top, Z_1.d, Z_1_top);
    
		BN_div_sm2(NULL, NULL, Z_3.d, &Z_3_top, temp, temp_top, group->field.d, group->field_top);

		BN_mul_sm2(temp, &temp_top, Z_3.d, Z_3_top, Y.d, group->field_top);
    
		BN_div_sm2(NULL, NULL,y->d, &y_top, temp, temp_top, group->field.d, group->field_top);
	}
}

void ec_GFp_simple_add(EC_GROUP *group, EC_POINT *r, EC_POINT *a, EC_POINT *b)
{
	int top1, top2;
	BIGNUM_SM2 n0, n1, n2, n3, n4, n5, n6;
	
	if(a == b)
	{
		ec_GFp_simple_dbl(group, r, a);
		return;
	}
	if(ec_GFp_simple_is_at_infinity(group, a))
	{
		memcpy(r, b, sizeof(EC_POINT));
		return;
	}
	if(ec_GFp_simple_is_at_infinity(group, b))
	{
		memcpy(r, a, sizeof(EC_POINT));
		return;
	}

	//if (a == b)
	//	return EC_POINT_dbl(group, r, a, ctx);
	//if (EC_POINT_is_at_infinity(group, a))
	//	return EC_POINT_copy(r, b);
	//if (EC_POINT_is_at_infinity(group, b))
	//	return EC_POINT_copy(r, a);

	/* n1, n2 */
	if (b->Z_is_one)
	{
		memcpy(&n1, &a->X, BIGNUM_SIZE);
		memcpy(&n2, &a->Y, BIGNUM_SIZE);
		/* n1 = X_a */
		/* n2 = Y_a */
	}
	else
	{

		BN_mod_mul_montgomery_sm2(n0.d, b->Z.d, b->Z.d, group->field.d, group->field_top, group->n0);
		BN_mod_mul_montgomery_sm2(n1.d, a->X.d, n0.d, group->field.d, group->field_top, group->n0);

		//field_sqr(group, n0, &b->Z, ctx)) goto end;
		//if (!field_mul(group, n1, &a->X, n0, ctx)) goto end;
		/* n1 = X_a * Z_b^2 */

		BN_mod_mul_montgomery_sm2(n0.d, n0.d, b->Z.d, group->field.d, group->field_top, group->n0);
		BN_mod_mul_montgomery_sm2(n2.d, a->Y.d, n0.d, group->field.d, group->field_top, group->n0);

		//if (!field_mul(group, n0, n0, &b->Z, ctx)) goto end;
		//if (!field_mul(group, n2, &a->Y, n0, ctx)) goto end;
		/* n2 = Y_a * Z_b^3 */
	}

	/* n3, n4 */
	if (a->Z_is_one)
	{
		memcpy(&n3, &b->X, BIGNUM_SIZE);
		memcpy(&n4, &b->Y, BIGNUM_SIZE);
		//if (!BN_copy(n3, &b->X)) goto end;
		//if (!BN_copy(n4, &b->Y)) goto end;
		/* n3 = X_b */
		/* n4 = Y_b */
	}
	else
	{

		BN_mod_mul_montgomery_sm2(n0.d, a->Z.d, a->Z.d, group->field.d, group->field_top, group->n0);
		BN_mod_mul_montgomery_sm2(n3.d, b->X.d, n0.d, group->field.d, group->field_top, group->n0);

		//if (!field_sqr(group, n0, &a->Z, ctx)) goto end;
		//if (!field_mul(group, n3, &b->X, n0, ctx)) goto end;
		/* n3 = X_b * Z_a^2 */

		BN_mod_mul_montgomery_sm2(n0.d, n0.d, a->Z.d, group->field.d, group->field_top, group->n0);
		BN_mod_mul_montgomery_sm2(n4.d, b->Y.d, n0.d, group->field.d, group->field_top, group->n0);

		//if (!field_mul(group, n0, n0, &a->Z, ctx)) goto end;
		//if (!field_mul(group, n4, &b->Y, n0, ctx)) goto end;
		/* n4 = Y_b * Z_a^3 */
	}

	/* n5, n6 */
    BN_mod_sub_sm2(n5.d, &top1, n1.d, n3.d, group->field.d, group->field_top);
    BN_mod_sub_sm2(n6.d, &top2, n2.d, n4.d, group->field.d, group->field_top);
	//if (!BN_mod_sub_quick(n5, n1, n3, p)) goto end;
	//if (!BN_mod_sub_quick(n6, n2, n4, p)) goto end;
	/* n5 = n1 - n3 */
	/* n6 = n2 - n4 */

	if(!top1)
	{
		if(!top2)
		{
			ec_GFp_simple_dbl(group, r, a);
			return;
		}
		else
		{
			memset(&r->Z, 0, BIGNUM_SIZE);
			r->Z_is_one = 0;
			return;
		}
	}

	/* 'n7', 'n8' */
    BN_mod_add_sm2(n1.d, n1.d, n3.d, group->field.d, group->field_top);
    BN_mod_add_sm2(n2.d, n2.d, n4.d, group->field.d, group->field_top);
	//if (!BN_mod_add_quick(n1, n1, n3, p)) goto end;
	//if (!BN_mod_add_quick(n2, n2, n4, p)) goto end;
	/* 'n7' = n1 + n3 */
	/* 'n8' = n2 + n4 */

	/* Z_r */
	if (a->Z_is_one && b->Z_is_one)
	{
			memcpy(&r->Z, &n5, BIGNUM_SIZE);
		  //if (!BN_copy(&r->Z, n5)) goto end;
	}
	else
	{
		if (a->Z_is_one)
		{ 
			memcpy(&n0, &b->Z, BIGNUM_SIZE);
			//{ if (!BN_copy(n0, &b->Z)) goto end; }
		}
		else if (b->Z_is_one)
		{ 
			memcpy(&n0, &a->Z, BIGNUM_SIZE);
			//{ if (!BN_copy(n0, &a->Z)) goto end; }
		}
		else
		{ 

			BN_mod_mul_montgomery_sm2(n0.d, a->Z.d, b->Z.d, group->field.d, group->field_top, group->n0);
			//if (!field_mul(group, n0, &a->Z, &b->Z, ctx)) goto end; 
		}

		BN_mod_mul_montgomery_sm2(r->Z.d, n0.d, n5.d, group->field.d, group->field_top, group->n0);

		//if (!field_mul(group, &r->Z, n0, n5, ctx)) goto end;
	}
	r->Z_is_one = 0;
	/* Z_r = Z_a * Z_b * n5 */

	/* X_r */
	BN_mod_mul_montgomery_sm2(n0.d, n6.d, n6.d, group->field.d, group->field_top, group->n0);
	BN_mod_mul_montgomery_sm2(n4.d, n5.d, n5.d, group->field.d, group->field_top, group->n0);
	BN_mod_mul_montgomery_sm2(n3.d, n1.d, n4.d, group->field.d, group->field_top, group->n0);
	BN_mod_sub_sm2(r->X.d, &top1, n0.d, n3.d, group->field.d, group->field_top);
	//if (!field_sqr(group, n0, n6, ctx)) goto end;
	//if (!field_sqr(group, n4, n5, ctx)) goto end;
	//if (!field_mul(group, n3, n1, n4, ctx)) goto end;
	//if (!BN_mod_sub_quick(&r->X, n0, n3, p)) goto end;
	/* X_r = n6^2 - n5^2 * 'n7' */
	
	/* 'n9' */

	BN_mod_lshift1_sm2(n0.d, r->X.d, group->field.d, group->field_top);
	BN_mod_sub_sm2(n0.d, &top1, n3.d, n0.d, group->field.d, group->field_top);
	//if (!BN_mod_lshift1_quick(n0, &r->X, p)) goto end;
	//if (!BN_mod_sub_quick(n0, n3, n0, p)) goto end;
	/* n9 = n5^2 * 'n7' - 2 * X_r */

	/* Y_r */
	BN_mod_mul_montgomery_sm2(n0.d, n0.d, n6.d, group->field.d, group->field_top, group->n0);
	BN_mod_mul_montgomery_sm2(n5.d, n4.d, n5.d, group->field.d, group->field_top, group->n0);
	BN_mod_mul_montgomery_sm2(n1.d, n2.d, n5.d, group->field.d, group->field_top, group->n0);
	BN_mod_sub_sm2(n0.d, &top1, n0.d, n1.d, group->field.d, group->field_top);
	if(n0.d[0] & 1)
	{
		BN_uadd_sm2(n0.d, &top1, n0.d, group->field_top, group->field.d, group->field_top);
		BN_rshift_sm2(r->Y.d, &top1, n0.d, top1, 1);
	}
	else
		BN_rshift_sm2(r->Y.d, &top1, n0.d, group->field_top, 1);

	//if (!field_mul(group, n0, n0, n6, ctx)) goto end;
  //if (!field_mul(group, n5, n4, n5, ctx)) goto end; /* now n5 is n5^3 */
  //if (!field_mul(group, n1, n2, n5, ctx)) goto end;
  //if (!BN_mod_sub_quick(n0, n0, n1, p)) goto end;
  //if (BN_is_odd(n0))
  //	if (!BN_add(n0, n0, p)) goto end;
	/* now  0 <= n0 < 2*p,  and n0 is even */
//	if (!BN_rshift1_sm2(&r->Y, n0)) goto end;
	/* Y_r = (n6 * 'n9' - 'n8' * 'n5^3') / 2 */
}

void ec_GFp_simple_dbl(EC_GROUP *group, EC_POINT *r, EC_POINT *a)
{
	int top;
	BIGNUM_SM2 n0, n1, n2, n3;
	
	if(ec_GFp_simple_is_at_infinity(group, a))
	{
		memset(&r->Z, 0, BIGNUM_SIZE);
		r->Z_is_one = 0;
		return;
	}

	//if (EC_POINT_is_at_infinity(group, a))
	//	{
	//	if (!BN_zero(&r->Z)) return 0;
	//	r->Z_is_one = 0;
	//	return 1;
	//	}
	
	/* n2 */
	BN_mod_mul_montgomery_sm2(n3.d, a->Y.d, a->Y.d, group->field.d, group->field_top, group->n0);
	BN_mod_mul_montgomery_sm2(n2.d, a->X.d, n3.d, group->field.d, group->field_top, group->n0);

	BN_mod_lshift1_sm2(n2.d, n2.d, group->field.d, group->field_top);
	BN_mod_lshift1_sm2(n2.d, n2.d, group->field.d, group->field_top);

	//if (!field_sqr(group, n3, &a->Y, ctx)) goto err;
	//if (!field_mul(group, n2, &a->X, n3, ctx)) goto err;
	//if (!BN_mod_lshift_quick(n2, n2, 2, p)) goto err;
	/* n2 = 4 * X_a * Y_a^2 */

	/* n3 */
	BN_mod_mul_montgomery_sm2(n0.d, n3.d, n3.d, group->field.d, group->field_top, group->n0);

	BN_mod_lshift1_sm2(n3.d, n0.d, group->field.d, group->field_top);
	BN_mod_lshift1_sm2(n3.d, n3.d, group->field.d, group->field_top);
	BN_mod_lshift1_sm2(n3.d, n3.d, group->field.d, group->field_top);
	//if (!field_sqr(group, n0, n3, ctx)) goto err;
	//if (!BN_mod_lshift_quick(n3, n0, 3, p)) goto err;
	/* n3 = 8 * Y_a^4 */


	/* n1 */
	if (a->Z_is_one)
	{
		BN_mod_mul_montgomery_sm2(n0.d, a->X.d, a->X.d, group->field.d, group->field_top, group->n0);

		BN_mod_lshift1_sm2(n1.d, n0.d, group->field.d, group->field_top);

		BN_mod_add_sm2(n0.d, n0.d, n1.d, group->field.d, group->field_top);
		BN_mod_add_sm2(n1.d, n0.d, group->a.d, group->field.d, group->field_top);

		//if (!field_sqr(group, n0, &a->X, ctx)) goto err;
		//if (!BN_mod_lshift1_quick(n1, n0, p)) goto err;
		//if (!BN_mod_add_quick(n0, n0, n1, p)) goto err;
		//if (!BN_mod_add_quick(n1, n0, &group->a, p)) goto err;
		/* n1 = 3 * X_a^2 + a_curve */
	}
	else
	{
		BN_mod_mul_montgomery_sm2(n0.d, a->X.d, a->X.d, group->field.d, group->field_top, group->n0);

		BN_mod_lshift1_sm2(n1.d, n0.d, group->field.d, group->field_top);

		BN_mod_add_sm2(n0.d, n0.d, n1.d, group->field.d, group->field_top);

		BN_mod_mul_montgomery_sm2(n1.d, a->Z.d, a->Z.d, group->field.d, group->field_top, group->n0);
		BN_mod_mul_montgomery_sm2(n1.d, n1.d, n1.d, group->field.d, group->field_top, group->n0);
		BN_mod_mul_montgomery_sm2(n1.d, n1.d, group->a.d, group->field.d, group->field_top, group->n0);
		BN_mod_add_sm2(n1.d, n1.d, n0.d, group->field.d, group->field_top);
		
		//if (!field_sqr(group, n0, &a->X, ctx)) goto err;
		//if (!BN_mod_lshift1_quick(n1, n0, p)) goto err;
		//if (!BN_mod_add_quick(n0, n0, n1, p)) goto err;
		//if (!field_sqr(group, n1, &a->Z, ctx)) goto err;
		//if (!field_sqr(group, n1, n1, ctx)) goto err;
		//if (!field_mul(group, n1, n1, &group->a, ctx)) goto err;
		//if (!BN_mod_add_quick(n1, n1, n0, p)) goto err;
		/* n1 = 3 * X_a^2 + a_curve * Z_a^4 */
	}

	/* Z_r */
	if (a->Z_is_one)
	{
		memcpy(&n0, &a->Y, BIGNUM_SIZE);	
		//if (!BN_copy(n0, &a->Y)) goto err;
	}
	else
	{
		BN_mod_mul_montgomery_sm2(n0.d, a->Y.d, a->Z.d, group->field.d, group->field_top, group->n0);
		//if (!field_mul(group, n0, &a->Y, &a->Z, ctx)) goto err;
	}

	BN_mod_lshift1_sm2(r->Z.d, n0.d, group->field.d, group->field_top);
	//if (!BN_mod_lshift1_quick(&r->Z, n0, p)) goto err;
	r->Z_is_one = 0;
	/* Z_r = 2 * Y_a * Z_a */

	

	/* X_r */
	BN_mod_lshift1_sm2(n0.d, n2.d, group->field.d, group->field_top);
	BN_mod_mul_montgomery_sm2(r->X.d, n1.d, n1.d, group->field.d, group->field_top, group->n0);
	BN_mod_sub_sm2(r->X.d, &top, r->X.d, n0.d, group->field.d, group->field_top);
	//if (!BN_mod_lshift1_quick(n0, n2, p)) goto err;
	//if (!field_sqr(group, &r->X, n1, ctx)) goto err;
	//if (!BN_mod_sub_quick(&r->X, &r->X, n0, p)) goto err;
	/* X_r = n1^2 - 2 * n2 */
	
	
	
	/* Y_r */
	BN_mod_sub_sm2(n0.d, &top, n2.d, r->X.d, group->field.d, group->field_top);
	BN_mod_mul_montgomery_sm2(n0.d, n1.d, n0.d, group->field.d, group->field_top, group->n0);
	BN_mod_sub_sm2(r->Y.d, &top, n0.d, n3.d, group->field.d, group->field_top);

	//if (!BN_mod_sub_quick(n0, n2, &r->X, p)) goto err;
	//if (!field_mul(group, n0, n1, n0, ctx)) goto err;
	//if (!BN_mod_sub_quick(&r->Y, n0, n3, p)) goto err;
	/* Y_r = n1 * (n2 - X_r) - n3 */
}

int ec_GFp_simple_is_at_infinity(EC_GROUP *group, EC_POINT *point)
{
	return BN_is_zero_sm2(point->Z.d, group->field_top);
}
