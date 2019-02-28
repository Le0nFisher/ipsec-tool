#include "bn_mod.h"

unsigned x=0;

void BN_mod_add_sm2(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, BN_ULONG *m, BN_ULONG mLen)
{
   int rl;
   {
       BN_uadd_sm2(r, &rl, a, mLen, b, mLen);
       if(BN_ucmp_sm2(r, rl, m, mLen) >= 0) //r >= m
       {
           BN_usub_sm2(r, &rl, r, rl, m, mLen);
       }
   }
}

void BN_mod_sub_sm2(BN_ULONG *r, int *rl, BN_ULONG *a, BN_ULONG *b, BN_ULONG *m, BN_ULONG mLen)
{
	if(BN_ucmp_sm2(a, mLen, b, mLen) >= 0)  //a >= b
	{
		BN_usub_sm2(r, rl, a, mLen, b, mLen);
	}
	else
	{
		BN_ULONG t[ECC_MAX_BLOCK_LEN_DWORD+2];
		int tl;
		BN_usub_sm2(t, &tl, m, mLen, b, mLen);
		BN_uadd_sm2(r, rl, a, mLen, t, tl);
	}
}

void BN_mod_lshift1_sm2(BN_ULONG *r, BN_ULONG *a, BN_ULONG *m, BN_ULONG mLen)
{
    BN_ULONG t0, t1, t2;
    BN_ULONG c, carry;
    int i;

    if(a[mLen-1] & 0x80000000)  //大于模数
        goto BN_mod_lshift1a;

    for(i = mLen - 1; i > 0; i--)
    {
        t0 = (a[i] << 1) + (a[i-1] >> 31);
        if(t0 > m[i])   //大于模数
        {
BN_mod_lshift1a:
			c = 0;
			carry = 0;
			for(i = 0; i < (int)mLen; i++)
			{
				t0 = a[i];
				t1 = (t0 << 1) + c;
				t2 = m[i];
				r[i] = t1 - t2 - carry;
				if (t1 != t2) carry = (t1 < t2);
				c = t0 >> 31;
			}
			return;
        }
        if(t0 < m[i])   //小于模数
        {
			c = 0;
			for(i = 0;i < (int)mLen; i++)
			{
				t0 = a[i];
				t1 = (t0 << 1) + c;
				r[i] = t1;
				c = t0 >> 31;
			}
			return;
        }
    }

    t0 = (a[i]<<1);
    if(t0 > m[i])   //大于模数
    {
		c = 0;
		carry = 0;
		for(i = 0; i < (int)mLen; i++)
		{
			t0 = a[i];
			t1 = (t0 << 1) + c;
			t2 = m[i];
			r[i] = t1 - t2 - carry;
			if (t1 != t2) carry = (t1 < t2);
			c = t0 >> 31;
		}
		return;
    }
    if(t0 < m[i])   //小于模数
    {
		c = 0;
		for(i = 0; i < (int)mLen; i++)
		{
			t0 = a[i];
			t1 = (t0<<1) + c;
			r[i] = t1;
			c = t0 >> 31;
		}
		return;
    }

    memset(r, 0, mLen);
}

