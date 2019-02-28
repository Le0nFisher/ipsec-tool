#include "bn_add.h"
#include "bn_asm.h"


int BN_uadd_sm2(BN_ULONG *r, int *rl, BN_ULONG *a, int al, BN_ULONG *b, int bl)
{
	register int i;
	int max, min;
	BN_ULONG *ap, *bp, *rp, carry, t1;
	BN_ULONG *tmp;
	int tmp1;

	if (al < bl)
	{
		tmp = a; a = b; b = tmp;
		tmp1 = al; al = bl; bl = tmp1;
	}

	max = al;
	min = bl;

	*rl = max;

	ap = a;
	bp = b;
	rp = r;
	carry = 0;
	carry = bn_add_words_sm2(rp, ap, bp, min);
	rp += min;
	ap += min;
	bp += min;
	i = min;

	if (carry)
	{
		while (i < max)
		{
			i++;
			t1 = *(ap++);
			if ((*(rp++) = (t1+1) & BN_MASK2) >= t1)
			{
				carry=0;
				break;
			}
		}
		if ((i >= max) && carry)
		{
			*(rp++) = 1;
			(*rl)++;
		}
	}
	if (rp != ap)
	{
		for (; i < max; i++)
			*(rp++) = *(ap++);
	}
	return(1);
}



int BN_usub_sm2(BN_ULONG *r, int *rl, BN_ULONG *a, int al, BN_ULONG *b, int bl)
{
	int max, min;
	register BN_ULONG t1, t2, *ap, *bp, *rp;
	int i, carry;

	max = al;
	min = bl;

	ap = a;
	bp = b;
	rp = r;

	carry = 0;
	for (i = 0; i < min; i++)
	{
		t1= *(ap++);
		t2= *(bp++);
		if (carry)
		{
			carry = (t1 <= t2);
			t1 = (t1-t2-1) & BN_MASK2;
		}
		else
		{
			carry = (t1 < t2);
			t1 = (t1-t2) & BN_MASK2;
		}
		*(rp++) = t1 & BN_MASK2;
	}

	if (carry) /* subtracted */
	{
		while (i < max)
		{
			i++;
			t1 = *(ap++);
			t2 = (t1 - 1) & BN_MASK2;
			*(rp++) = t2;
			if (t1 > t2) break;
		}
	}

	if (rp != ap)
	{
		for (;;)
		{
			if (i++ >= max) break;
			rp[0]=ap[0];
			if (i++ >= max) break;
			rp[1]=ap[1];
			if (i++ >= max) break;
			rp[2]=ap[2];
			if (i++ >= max) break;
			rp[3]=ap[3];
			rp+=4;
			ap+=4;
		}
	}

	*rl=max;
	bn_fix_top_sm2(r, rl);
	return(1);
}

