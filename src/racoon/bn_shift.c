#include "bn_shift.h"

void BN_rshift1_sm2(BIGNUM_SM2 *r, int *r_top, BIGNUM_SM2 *a, int a_top)
{
	BN_ULONG *ap, *rp, t, c;
	int i;	
	if(a_top == 0)
	{
		memset(r,0,BIGNUM_SIZE);
		*r_top = 0;
		return ;
	}
	
	ap = a->d;
	rp = r->d;
	c = 0;
	for(i = a_top-1; i >= 0; i--)
	{
		t = ap[i];
		rp[i] = (t >> 1) | c;
		c = (t & 1) ? BN_TBIT : 0;
	}
	
	if(r->d[a_top-1])
		*r_top = a_top;
	else
		*r_top = a_top-1;
}

int BN_lshift_sm2(BN_ULONG *r, int *rl, BN_ULONG *a, int al, int n)
{
	int i, nw, lb, rb;
	BN_ULONG l;
	
	nw = n/BN_BITS2;
	lb = n%BN_BITS2;
	rb = BN_BITS2 - lb;
	r[al+nw] = 0;
	if (lb == 0)
		for (i = al - 1; i >= 0; i--)
			r[nw+i] = a[i];
		else
			for (i = al - 1; i >= 0; i--)
			{
				l=a[i];
				r[nw+i+1] |= (l >> rb) & BN_MASK2;
				r[nw+i] = (l << lb) & BN_MASK2;
			}
			memset(r, 0, nw*sizeof(r[0]));
			/*	for (i=0; i<nw; i++)
			t[i]=0;*/
			*rl = al + nw + 1;
			bn_fix_top_sm2(r, rl);
			return(1);
}

int BN_rshift_sm2(BN_ULONG *r, int *rl, BN_ULONG *a, int al, int n)
{
	int i, j, nw, lb, rb;
	BN_ULONG *t, *f;
	BN_ULONG l, tmp;
	
	nw = n / BN_BITS2;
	rb = n % BN_BITS2;
	lb = BN_BITS2 - rb;
	if (nw > al || al == 0)
	{
		memset(r, 0, BIGNUM_SIZE);
		*rl = 0;
		return 0;
	}
	
	f = &a[nw];
	t = r;
	j = al - nw;
	*rl = j;
	
	if (rb == 0)
	{
		for (i = j + 1; i > 0; i--)
			*(t++) = *(f++);
	}
	else
	{
		l = *(f++);
		for (i = 1; i < j; i++)
		{
			tmp = (l >> rb) & BN_MASK2;
			l = *(f++);
			*(t++) = (tmp | (l << lb)) & BN_MASK2;
		}
		*(t++) = (l >> rb) & BN_MASK2;
	}
	*t = 0;
	bn_fix_top_sm2(r, rl);
	return(1);
}


//  判断2个大数是否相等,0 相等，1 不等

int two_number_same(BN_ULONG *a, int len, BN_ULONG *b)
{
int i;
int sum =0;
int hh;
for(i=0;i<len;i++)
{
if( a[i] == b[i]) hh=0;
 else hh =1;
 sum  = sum +hh;
}

if(sum ==0) return 0;
else return  1;
}
