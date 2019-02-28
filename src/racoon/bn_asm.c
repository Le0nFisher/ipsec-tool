#include "bn_asm.h"

BN_ULONG bn_mul_add_words_sm2(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w)
{
	BN_ULONG c = 0;
	BN_ULONG bl, bh;

	if (num <= 0) return((BN_ULONG)0);

	bl = LBITS(w);
	bh = HBITS(w);

	for (;;)
	{
		mul_add(rp[0], ap[0], bl, bh, c);
		if (--num == 0) break;
		mul_add(rp[1], ap[1], bl, bh, c);
		if (--num == 0) break;
		mul_add(rp[2], ap[2], bl, bh, c);
		if (--num == 0) break;
		mul_add(rp[3], ap[3], bl, bh, c);
		if (--num == 0) break;
		ap+=4;
		rp+=4;
	}
	return(c);
} 

BN_ULONG bn_mul_words_sm2(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w)
{
	BN_ULONG carry=0;
	BN_ULONG bl, bh;

	if (num <= 0) return((BN_ULONG)0);

	bl = LBITS(w);
	bh = HBITS(w);

	for (;;)
	{
		mul(rp[0], ap[0], bl, bh, carry);
		if (--num == 0) break;
		mul(rp[1], ap[1], bl, bh, carry);
		if (--num == 0) break;
		mul(rp[2], ap[2], bl, bh, carry);
		if (--num == 0) break;
		mul(rp[3], ap[3], bl, bh, carry);
		if (--num == 0) break;
		ap+=4;
		rp+=4;
	}

	return(carry);
} 


BN_ULONG bn_div_words_sm2(BN_ULONG h, BN_ULONG l, BN_ULONG d)
{
	BN_ULONG dh, dl, q, ret = 0, th, tl, t;
	int i, count = 2;

	if (d == 0) return(BN_MASK2);

	i = BN_num_bits_word_sm2(d);

	i = BN_BITS2 - i;
	if (h >= d) h -= d;

	if (i)
	{
		d <<= i;
		h = (h << i) | (l >> (BN_BITS2 - i));
		l <<= i;
	}
	dh = (d & BN_MASK2h) >> BN_BITS4;
	dl = (d & BN_MASK2l);
	for (;;)
	{
		if ((h >> BN_BITS4) == dh)
			q = BN_MASK2l;
		else
			q = h / dh;

		th = q * dh;
		tl = dl * q;
		for (;;)
		{
			t = h - th;
			if ((t & BN_MASK2h) ||
				((tl) <= (
					(t << BN_BITS4)|
					((l & BN_MASK2h) >> BN_BITS4))))
				break;
			q--;
			th -= dh;
			tl -= dl;
		}
		t = (tl >> BN_BITS4);
		tl = (tl << BN_BITS4) & BN_MASK2h;
		th += t;

		if (l < tl) th++;
		l -= tl;
		if (h < th)
		{
			h += d;
			q--;
		}
		h -= th;

		if (--count == 0) break;

		ret = q << BN_BITS4;
		h = ((h << BN_BITS4)|(l >> BN_BITS4)) & BN_MASK2;
		l = (l & BN_MASK2l) << BN_BITS4;
	}
	ret |= q;
	return(ret);
}

BN_ULONG bn_add_words_sm2(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b, int n)
{
	BN_ULONG c, l, t;

	if (n <= 0) return((BN_ULONG)0);

	c=0;
	for (;;)
	{
		t = a[0];
		t = (t + c) & BN_MASK2;
		c = (t < c);
		l = (t + b[0]) & BN_MASK2;
		c += (l < t);
		r[0] = l;
		if (--n <= 0) break;

		t = a[1];
		t = (t + c) & BN_MASK2;
		c =(t < c);
		l =(t + b[1]) & BN_MASK2;
		c += (l < t);
		r[1] = l;
		if (--n <= 0) break;

		t = a[2];
		t =(t + c) & BN_MASK2;
		c =(t < c);
		l =(t + b[2]) & BN_MASK2;
		c += (l < t);
		r[2] = l;
		if (--n <= 0) break;

		t = a[3];
		t =(t + c) & BN_MASK2;
		c =(t < c);
		l =(t + b[3]) & BN_MASK2;
		c += (l < t);
		r[3] = l;
		if (--n <= 0) break;

		a += 4;
		b += 4;
		r += 4;
	}

	return((BN_ULONG)c);
}

BN_ULONG bn_sub_words_sm2(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b, int n)
{
	BN_ULONG t1, t2;
	int c = 0;

	if (n <= 0) return((BN_ULONG)0);

	for (;;)
	{
		t1 = a[0]; t2 = b[0];
		r[0] = (t1 - t2 - c) & BN_MASK2;
		if (t1 != t2) c = (t1 < t2);
		if (--n <= 0) break;

		t1 = a[1]; t2 = b[1];
		r[1] = (t1 - t2 - c) & BN_MASK2;
		if (t1 != t2) c = (t1 < t2);
		if (--n <= 0) break;

		t1 = a[2]; t2 = b[2];
		r[2] = (t1 - t2 - c) & BN_MASK2;
		if (t1 != t2) c = (t1 < t2);
		if (--n <= 0) break;

		t1 = a[3]; t2 = b[3];
		r[3] = (t1 - t2 - c) & BN_MASK2;
		if (t1 != t2) c = (t1 < t2);
		if (--n <= 0) break;

		a += 4;
		b += 4;
		r += 4;
	}
	return(c);
}

