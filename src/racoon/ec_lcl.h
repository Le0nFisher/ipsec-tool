#ifndef EC_LCL_H
#define EC_LCL_H

#include "ec_bn.h"

struct ec_point_st {
	BIGNUM_SM2 X;
	BIGNUM_SM2 Y;	
	BIGNUM_SM2 Z;	   /* Jacobian projective coordinates:
	* (X, Y, Z)  represents  (X/Z^2, Y/Z^3)  if  Z != 0 */
	int Z_is_one; /* enable optimized point arithmetics for special case */
    int pad;
} /* EC_POINT */;

typedef struct ec_point_st EC_POINT;

struct ec_group_st {
	
	BIGNUM_SM2 field; 
	/* Field specification.
	* For curves over GF(p), this is the modulus. */
	
	BIGNUM_SM2 a,b; 
	/* Curve coefficients.
	* (Here the assumption is that BIGNUMs can be used
	* or abused for all kinds of fields, not just GF(p).)
	* For characteristic  > 3,  the curve is defined
	* by a Weierstrass equation of the form
	*     y^2 = x^3 + a*x + b.
	*/

	BIGNUM_SM2 order;
	BIGNUM_SM2 RR;
	BIGNUM_SM2 Ni;     /* R*(1/R mod N) - N*Ni = 1
	                    * (Ni is only stored for bignum algorithm) */
	BIGNUM_SM2 field_data2;

	EC_POINT generator; /* Generator */

	unsigned int field_top;	/* Field length	*/ 
	unsigned int order_top;	/* Order length	*/ 
	unsigned int n0;   /* least significant word of Ni */
	unsigned int BitLen; 
} /* EC_GROUP */;

typedef struct ec_group_st EC_GROUP;

#endif

