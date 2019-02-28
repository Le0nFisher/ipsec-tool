#include "bn_mul.h"

void BN_mul_nomal_sm2(BN_ULONG *r, BN_ULONG *a, int na, BN_ULONG *b, int nb)
{
	BN_ULONG *rr;	
	if (na < nb)
	{
		int itmp;
		BN_ULONG *ltmp;
		
		itmp = na; na = nb; nb = itmp;
		ltmp = a; a = b; b = ltmp;
		
	}
	rr = &(r[na]);
	rr[0] = bn_mul_words_sm2(r, a, na, b[0]);

	
	for (;;)
	{
		if (--nb <= 0) return;
		rr[1] = bn_mul_add_words_sm2(&(r[1]), a, na, b[1]);
		if (--nb <= 0) return;
		rr[2] = bn_mul_add_words_sm2(&(r[2]), a, na, b[2]);
		if (--nb <= 0) return;
		rr[3] = bn_mul_add_words_sm2(&(r[3]), a, na, b[3]);
		if (--nb <= 0) return;
		rr[4] = bn_mul_add_words_sm2(&(r[4]), a, na, b[4]);
		rr += 4;
		r += 4;
		b += 4;
	}
}


void BN_mul_sm2(BN_ULONG *r, int *rl, BN_ULONG *a, int al, BN_ULONG *b, int bl)
{
	if ((al == 0) || (bl == 0))
	{
		*rl = 0;
		return;
	}
	*rl = al + bl;
    BN_mul_nomal_sm2(r, a, al, b, bl);
	bn_fix_top_sm2(r, rl);
	return;
}

