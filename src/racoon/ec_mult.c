#include "ec_mult.h"
#include <stdio.h>
#include <string.h>
/* Determine the width-(w+1) Non-Adjacent Form (wNAF) of 'scalar'.
 * This is an array  r[]  of values that are either zero or odd with an
 * absolute value less than  2^w  satisfying
 *     scalar = \sum_j r[j]*2^j
 * where at most one of any  w+1  consecutive digits is non-zero.
 */

#if 1


int BN_is_bit_set(BIGNUM_SM2 *a, int n)
{
	int i,j;
	int len;

	len=8;
	bn_fix_top_sm2(a->d, &len);
	if (n < 0) return 0;
	i=n/BN_BITS2;
	j=n%BN_BITS2;
	if (len <= i) return 0;

//	printf("%x ", a->d[i]);
	return (int)(((a->d[i])>>j)&((BN_ULONG)1));
}


/* Determine the modified width-(w+1) Non-Adjacent Form (wNAF) of 'scalar'.
 * This is an array  r[]  of values that are either zero or odd with an
 * absolute value less than  2^w  satisfying
 *     scalar = \sum_j r[j]*2^j
 * where at most one of any  w+1  consecutive digits is non-zero
 * with the exception that the most significant digit may be only
 * w-1 zeros away from that next non-zero digit.
 */
signed char *compute_wNAF_openssl(BIGNUM_SM2 *scalar, int w, int *ret_len)
{
	int window_val;
	int ok = 0;
	signed char *r = NULL;
	int sign = 1;
	int bit, next_bit, mask;
	int len = 0, j;
	BIGNUM_SM2 c;


	bit = 1 << w; /* at most 128 */
	next_bit = bit << 1; /* at most 256 */
	mask = next_bit - 1; /* at most 255 */
	memcpy(&c, scalar, BIGNUM_SIZE);
	
	len = BN_num_bits_sm2(c.d, 8);
	r = (signed char*)malloc(len + 1); /* modified wNAF may be one digit longer than binary representation
	                              * (*ret_len will be set to the actual length, i.e. at most
	                              * BN_num_bits_sm2(scalar) + 1) */
	
	window_val = scalar->d[0] & mask;
	j = 0;
	while ((window_val != 0) || (j + w + 1 < len)) /* if j+w+1 >= len, window_val will not increase */
		{
		int digit = 0;
		/* 0 <= window_val <= 2^(w+1) */

		if (window_val & 1)
			{
			/* 0 < window_val < 2^(w+1) */

			if (window_val & bit)
				{
				digit = window_val - next_bit; /* -2^w < digit < 0 */

#if 1 /* modified wNAF */
				if (j + w + 1 >= len)
					{
					/* special case for generating modified wNAFs:
					 * no new bits will be added into window_val,
					 * so using a positive digit here will decrease
					 * the total length of the representation */
					
					digit = window_val & (mask >> 1); /* 0 < digit < 2^w */
					}
#endif
				}
			else
				{
				digit = window_val; /* 0 < digit < 2^w */
				}
			
			if (digit <= -bit || digit >= bit || !(digit & 1))
				return NULL;

			window_val -= digit;

			/* now window_val is 0 or 2^(w+1) in standard wNAF generation;
			 * for modified window NAFs, it may also be 2^w
			 */
			if (window_val != 0 && window_val != next_bit && window_val != bit)
				return NULL;
			}

		r[j++] = sign * digit;
		window_val >>= 1;
		window_val += bit * BN_is_bit_set(scalar, j + w);
		
		if (window_val > next_bit)
			return NULL;
		}


	if (j > len + 1)
		return NULL;
	len = j;
	ok = 1;

 //err:
	if (!ok)
		{
		free(r);
		r = NULL;
		}
	if (ok)
		*ret_len = len;
	return r;
}

#endif

signed char *compute_wNAF(BIGNUM_SM2 *scalar, int w, int order_top, int *ret_len)
{
	int top;
	BIGNUM_SM2 c;
	signed char *r;
	int bit, next_bit, mask;
	BN_ULONG len = 0, j;
	
	bit = 1 << w; /* at most 128 */
	next_bit = bit << 1; /* at most 256 */
	mask = next_bit - 1; /* at most 255 */

	memcpy(&c, scalar, BIGNUM_SIZE);

	top = order_top;
	
	len = BN_num_bits_sm2(c.d, top) + 1; /* wNAF may be one digit longer than binary representation */
	r = (signed char *)malloc(len);

	j = 0;
	while (top)
	{
		int u = 0, u1;

		if (c.d[0] & 1) 
		{
			u = c.d[0] & mask;
			if (u & bit)
			{
				u -= next_bit;
				/* u < 0 */
				//c.d[0] -= u;
				u1 = -u;
                BN_uadd_sm2(c.d, &top, c.d, top, (BN_ULONG *)&u1, 1);
			}
			else
			{
				/* u > 0 */
				//c.d[0] -= u;
				u1 = u;
                BN_usub_sm2(c.d, &top, c.d, top, (BN_ULONG *)&u1, 1);
			}
		}

		r[j++] = u;
				
		BN_rshift1_sm2(&c, &top, &c, top);
	}

	*ret_len = j;

	return r;
}

#define EC_window_bits_for_scalar_size(b) \
		((b) >=  300 ? 4 : \
		 (b) >=   70 ? 3 : \
		 (b) >=   20 ? 2 : \
		  1)

/*	º∆À„ R = kP ªÚ R = kP + lQ	*/

void EC_POINTs_mul_sm2(EC_GROUP *group, EC_POINT *R, EC_POINT *P, BIGNUM_SM2 *k, EC_POINT *Q, BIGNUM_SM2 *l) 
{
	EC_POINT tmp;
	int num;
	int totalnum;
	int i, j;
	int kk;
	int r_is_inverted = 0;
	int r_is_at_infinity = 1;
	int top;
	int wsize[2]; /* individual window sizes */
	int wNAF_len[2];
	int max_len = 0;
	int num_val;
	signed char **wNAF; /* individual wNAFs */
	EC_POINT val_sub[2][16]; /* pointers to sub-arrays of 'val' */
	
	if(l == NULL)
	{
		totalnum = 1;
		num = 0;
	}
	else
	{
		totalnum = 2;
		num = 1;
	}
			
	wNAF = (signed char **)malloc((totalnum + 1) * sizeof wNAF[0]);

	/* num_val := total number of points to precompute */
	num_val = 0;
	for (i = 0; i < totalnum; i++)
	{
		int bits;

		bits = i < num ? BN_num_bits_sm2(l->d,group->order_top) : BN_num_bits_sm2(k->d,group->order_top);
		wsize[i] = EC_window_bits_for_scalar_size(bits);
		num_val += 1 << (wsize[i] - 1);
	}

	/* prepare precomputed values:
	 *    val_sub[i][0] :=     points[i]
	 *    val_sub[i][1] := 3 * points[i]
	 *    val_sub[i][2] := 5 * points[i]
	 *    ...
	 */
	for (i = 0; i < totalnum; i++)
	{
		if (i < num)
		{
			memcpy(&val_sub[i][0], Q, sizeof(EC_POINT));		
		}
		else
		{
			memcpy(&val_sub[i][0], P, sizeof(EC_POINT));		
		}

		if (wsize[i] > 1)
		{
		    ec_GFp_simple_dbl(group, &tmp, &val_sub[i][0]);

			for (j = 1; j < (int)(1u << (wsize[i] - 1)); j++)
			{
				ec_GFp_simple_add(group, &val_sub[i][j], &val_sub[i][j - 1], &tmp);
			}
		}
		wNAF[i + 1] = 0; 

		//by wuwentai modified bug
//		wNAF[i] = compute_wNAF((i < num ? l : k), wsize[i], group->order_top, &wNAF_len[i]);
		wNAF[i] = compute_wNAF_openssl((i < num ? l : k), wsize[i], &wNAF_len[i]);
		if (wNAF_len[i] > max_len)
			max_len = wNAF_len[i];
		}

	r_is_at_infinity = 1;

	for (kk = max_len - 1; kk >= 0; kk--)
	{
		if (!r_is_at_infinity)
		{
		  ec_GFp_simple_dbl(group, R, R);
		}
		
		for (i = 0; i < totalnum; i++)
		{
			if (wNAF_len[i] > kk)
			{
				int digit = wNAF[i][kk];
				int is_neg;

				if (digit) 
				{
					is_neg = digit < 0;

					if (is_neg)
						digit = -digit;

					if (is_neg != r_is_inverted)
					{
						if (!r_is_at_infinity)
						{
							if(ec_GFp_simple_is_at_infinity(group, R) || BN_is_zero_sm2(R->Y.d, group->field_top))
								goto next;

							BN_usub_sm2(R->Y.d, &top, group->field.d, group->field_top, R->Y.d, group->field_top);
						}
						next:
							r_is_inverted = !r_is_inverted;
					}

					/* digit > 0 */

					if (r_is_at_infinity)
					{
						memcpy(R, &val_sub[i][digit >> 1], sizeof(EC_POINT));
						r_is_at_infinity = 0;
					}
					else
					{
						ec_GFp_simple_add(group, R, R, &val_sub[i][digit >> 1]);
					}
				}
			}
		}
	}

	if (r_is_inverted)
        BN_usub_sm2(R->Y.d, &top, group->field.d, group->field_top, R->Y.d, group->field_top);

	if (wNAF != 0)
	{
		signed char **w;
		
		for (w = wNAF; *w != 0; w++)
			free(*w);
		
		free(wNAF);
	}
}

