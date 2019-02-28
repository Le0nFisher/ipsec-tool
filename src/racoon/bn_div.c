#include "bn_div.h"

void BN_div_sm2(BN_ULONG *dv, int *dv_len, BN_ULONG *rm, int *rm_len, BN_ULONG *num, int num_len, BN_ULONG *divisor, int divisor_len)
{
	int norm_shift, i, j, loop;
	BN_ULONG snum[256], sdiv[256], tmp[256], dvv[256];
	int snum_len, sdiv_len, wnum_len, res_len, tmp_len;
	BN_ULONG *wnum;
	BN_ULONG *res;
	BN_ULONG *resp, *wnump;
	BN_ULONG d0, d1;
	int num_n, div_n;
	unsigned int x=0;
	

	if (BN_ucmp_sm2(num, num_len, divisor, divisor_len) < 0)
	{
		//������С�ڳ��������
		if (rm_len)
		{
			//����������������
			for(i = 0; i < num_len; i++)
				rm[i] = num[i];
			for(; i < divisor_len; i++)
				rm[i] = 0;
			//�����ĳ���Ϊ�������ĳ���
			*rm_len = num_len;
		}
		if (dv_len)
			*dv_len = 0;
		return;
	}

	if(dv != NULL)
		res = dv;
	else
		res = dvv;	

	/* First we normalise the numbers */
	norm_shift = BN_BITS2 - ((BN_num_bits_sm2(divisor,divisor_len))%BN_BITS2);
	//����sdiv�����һ���ֵ����,sdiv��β��Ҫ����һ����
	BN_lshift_sm2(sdiv, &sdiv_len, divisor, divisor_len, norm_shift);
	norm_shift += BN_BITS2;
	//����snum�����һ���ֵ����,snum��β��Ҫ����һ����
	BN_lshift_sm2(snum, &snum_len, num, num_len, norm_shift);
	div_n = sdiv_len;
	num_n = snum_len;
	//loopΪ�̵�����,��������num_n���Ϊ128+2=130,div_n��СΪ1,
	//����dvv����dvv[129]
	loop = num_n - div_n;

	/* Lets setup a 'window' into snum
	 * This is the part that corresponds to the current
	 * 'area' being divided */
	wnum = &snum[loop];
	wnum_len = div_n;

	/* Get the top 2 words of sdiv */
	d0 = sdiv[div_n-1];
	d1 = (div_n == 1)?0:sdiv[div_n-2];

	/* pointer to the 'top' of snum */
	wnump = &snum[num_n-1];

	/* Setup to 'res' */
	res_len = loop;
	resp = &res[loop-1];

	if (BN_ucmp_sm2(wnum, wnum_len, sdiv, sdiv_len) >= 0)
	{
		//����sdiv�����>B/2,������ֻ����Ϊ1
		BN_usub_sm2(wnum, &wnum_len, wnum, wnum_len, sdiv, sdiv_len);
		*resp = 1;
	}
	else
		res_len--;
	resp--;

	for (i = 0; i < loop - 1; i++)
	{
		x++;
		//if(x>=10)
		//	printf("div:x=%d\n",x);
		BN_ULONG q, l0;
		BN_ULONG n0, n1, rem=0;

		n0 = wnump[0];
		n1 = wnump[-1];
		if (n0 == d0)
			q = BN_MASK2;
		else 			/* n0 < d0 */
		{
			BN_ULONG t2l, t2h, ql, qh;

			q = bn_div_words_sm2(n0, n1, d0);
			rem = (n1 - q*d0) & BN_MASK2;

			t2l = LBITS(d1); t2h = HBITS(d1);
			ql = LBITS(q);  qh = HBITS(q);
			mul64(t2l, t2h, ql, qh); /* t2=(BN_ULLONG)d1*q; */

			//���̼���
			for (;;)
			{
				if ((t2h < rem) ||
					((t2h == rem) && (t2l <= wnump[-2])))
					break;
				q--;
				rem += d0;
				if (rem < d0) break; /* don't let rem overflow */
				if (t2l < d1) t2h--; t2l -= d1;
			}
		}

		//����һ�������̼���

		//��������ĳ˷�,tmp��sdiv��һ��
#ifdef ASM_OPTm
		l0 = Bn_mul_words_asm(tmp, sdiv, div_n, q);
#else
		l0 = bn_mul_words_sm2(tmp, sdiv, div_n, q);
#endif

		//��wnum��wnum_len�ĳ�ֵ
		wnum--; wnum_len++;

		tmp[div_n] = l0;
		for (j = div_n + 1; j > 0; j--)
			if (tmp[j-1]) break;
		tmp_len = j;

		j=wnum_len;

		if (BN_ucmp_sm2(wnum, wnum_len, tmp, tmp_len) >= 0)
		{
			BN_usub_sm2(wnum, &wnum_len, wnum, wnum_len, tmp, tmp_len);

			snum_len = snum_len + wnum_len - j;
		}
		else
		{
			BN_usub_sm2(wnum, &wnum_len, tmp, tmp_len, wnum, wnum_len);

			snum_len = snum_len + wnum_len - j;

			q--;
			j = wnum_len;
			BN_usub_sm2(wnum, &wnum_len, sdiv, sdiv_len, wnum, wnum_len);
			snum_len = snum_len + wnum_len - j;
		}
		
		*(resp--) = q;
		wnump--;
	}
	if (rm)
		//norm_shift�����һ�ֵ����,����rmҪ�ඨ��һ����
		BN_rshift_sm2(rm, rm_len, snum, snum_len, norm_shift);

	if(dv_len != NULL)
		*dv_len = res_len;
	
	return;
}
