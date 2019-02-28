#include "bn_mont.h"
#include <stdio.h>

#define UL unsigned int
#define ULL unsigned long long

extern void sw_memdump(unsigned char * buf, unsigned int len);

//////////////////////////////////////////////
//                                          //
//  函数功能:                               //
//      由模数计算出n0、RR                 //
//  函数参数:                               //
//      Mod:in,模数                           //
//      ModLen:in,模长                        //
//      n0:out                              //
//      RR:out                              //
//  函数返回:                               //
//      无                                   //
//                                          //
//////////////////////////////////////////////

unsigned int count1, count2;
volatile BN_ULONG g_n0=1;

void BN_MONT_CTX_set_sm2(BN_ULONG *Mod, int ModLen, BN_ULONG *n0, BN_ULONG *RR)
{
    BN_ULONG R[2];
    BN_ULONG tmod;
    BN_ULONG Ri[2];
    BN_ULONG tmp[ECC_MAX_BLOCK_LEN_DWORD*2+1];  
    int Ri_len;
    int RR_len;
    int i;

    count1 = 0;
    count2 = 0;
    
    R[0]=0;
    R[1]=1;
    tmod=Mod[0];
    
    BN_mod_inverse_sm2(&Ri[1], &Ri_len, R, 2, &tmod, 1);    


    Ri[0] = 0xffffffff;Ri[1] -= 1;

    if(Ri[1])
        BN_div_sm2(Ri, &Ri_len, NULL, NULL, Ri, 2, &tmod, 1);
    else
        BN_div_sm2(Ri, &Ri_len, NULL, NULL, Ri, 1, &tmod, 1);
        
    g_n0 = *n0 = Ri[0];
        
    for(i = 0; i < ModLen*2; i++)
        tmp[i] = 0;
    tmp[i] = 1;
    BN_div_sm2(NULL, NULL, RR, &RR_len, tmp, ModLen*2+1, Mod, ModLen);
}

#if 1
void BN_mod_mul_montgomery_sm2(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, BN_ULONG *M, int M_Len, BN_ULONG n0)
{
    int i, j, k;
    UL hht, llt, hht1, llt1, carry,carry1, bb, m, u;
    int rl;
    //BN_ULONG xxx;
    UL c[200*2+1], *cp;
    UL tt,ttc,ttc1,bl,bh,aaa;

    aaa=a[0];
    cp = c;

    memset(c, 0, sizeof(c));

    for(i = 0; i < M_Len; i++)
    {
        u = *cp;

        carry = 0;
        carry1 = 0;
        ttc1 =0;
        bb = b[i];

        llt = aaa * bb;
        tt = llt+u;
        m = tt * n0;

        for(j = 0; j < M_Len; j++)
        {
            //ai*bi
            hht = (a[j]>>16)&0xffff;
            llt = a[j]&0xffff;
            bl = bb&0xffff;
            bh = (bb>>16)&0xffff;
            mul64(llt,hht,bl,bh);

            //n0*M
            hht1 = (m>>16)&0xffff;
            llt1 = m&0xffff;
            bl = M[j]&0xffff;
            bh = (M[j]>>16)&0xffff;
            mul64(llt1,hht1,bl,bh);


            //ci=ci+ai*bi+n0*M+carry
            ttc = 0;
            tt = llt+llt1;
            ttc += ( tt < llt );
            tt += cp[j];
            ttc += ( tt < cp[j] );
            tt += carry;
            ttc += ( tt < carry );
            cp[j] = tt;

            ttc1 = 0;
            carry1 += hht;
            ttc1 += (carry1 < hht);
            carry1 += hht1;
            ttc1 += (carry1 < hht1);
            carry1 += ttc;
            ttc1 += (carry1 < ttc);
            carry = carry1;
            carry1 = ttc1;
        }
        cp[j] += carry;
        k = j+1;

        if(cp[j] < carry)
        {
            cp[k] += 1;
            cp[k] += carry1;
        }
        else
            cp[k] += carry1;

        cp++;
    }

    //判断乘积位数是否超过模数位数

    if(!carry1)
    {
        for(i = 0; i < M_Len; i++)
            r[i] = c[M_Len + i];

        if(BN_ucmp_sm2(r, M_Len, M, M_Len) >= 0)
        {
            BN_usub_sm2(r, &rl, r, M_Len, M, M_Len);
        }
    }
    else
        BN_usub_sm2(r, &rl, &c[M_Len], M_Len+1, M, M_Len);
}

//#pragma CODE_SECTION(BN_mod_mul_montgomery_one_sm2,".ext_text")
void BN_mod_mul_montgomery_one_sm2(BN_ULONG *r, BN_ULONG *a, BN_ULONG *M, int M_Len, BN_ULONG n0)
{
    int i, j, k;
    //UL ht1, lt1, carry, carry1, m, u;
    UL lt1, carry, carry1, m, u;
    int rl;
    UL c[ECC_MAX_BLOCK_LEN_DWORD*2+1], *cp;
    int first = 1;
    UL hht, llt, tt, ttc, ttc1, bl, bh;
    cp = c;

    memset(c, 0, sizeof(c));

    for(i = 0; i < M_Len; i++)
    {
        u = *cp;

        carry = 0;
        carry1 = 0;
        ttc1 = 0;

        if(first)
            m = (a[0] + u) * n0;
        else
            m = u * n0;

        for(j = 0; j < M_Len; j++)
        {

            //n0*M
            hht = (m>>16)&0xffff;
            llt = m&0xffff;
            bl = M[j]&0xffff;
            bh = (M[j]>>16)&0xffff;
            mul64(llt,hht,bl,bh);

            //ci=ci+ai*bi+n0*M+carry
            ttc = 0;
            if(first)
            {
                tt = a[j]+llt;
                ttc += ( tt < llt );
            }else
                tt = llt;

            tt += cp[j];
            ttc += ( tt < cp[j] );
            tt += carry;
            ttc += ( tt < carry );
            cp[j] = tt;

            carry1 += hht;
            ttc1 += (carry1 < hht);
            carry1 += ttc;
            ttc1 += (carry1 < ttc);
            carry = carry1;
            carry1 = ttc1;
        }
        cp[j] += carry;
        k = j+1;

        if(cp[j] < carry)
        {
            cp[k] += 1;
            cp[k] += carry1;
        }
        else
            cp[k] += carry1;

        cp++;

        if(first)
            first = 0;
    }

    //判断乘积位数是否超过模数位数

    if(!carry1)
    {
        for(i = 0; i < M_Len; i++)
            r[i] = c[M_Len + i];

        if(BN_ucmp_sm2(r, M_Len, M, M_Len) >= 0)
        {
            BN_usub_sm2(r, &rl, r, M_Len, M, M_Len);
        }
    }
    else
        BN_usub_sm2(r, &rl, &c[M_Len], M_Len+1, M, M_Len);
}



#else




void BN_mod_mul_montgomery_sm2(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, BN_ULONG *M, int M_Len, BN_ULONG n0)
{
    int i, j, k;
    UL ht, lt, ht1, lt1, carry, bb, m, u;
    int rl;
    ULL tmp, tmp1, carry1;
    ULL ab,nm;
    UL c[64*2+1], *cp;

    cp = c;

/*  if(BN_ucmp_sm2(a, M_Len, b, M_Len)==0)
        count1++;
    else
        count2++;
*/

    memset(c, 0, sizeof(c));

    for(i = 0; i < M_Len; i++)
    {
        u = *cp;

        carry = 0;
        carry1 = 0;
        bb = b[i];

        tmp = (ULL)a[0] * (ULL)bb;
        lt = (UL)tmp;
        m = (UL)((ULL)(lt+u) * (ULL)n0);

        for(j = 0; j < M_Len; j++)
        {
            ab = (ULL)a[j] * (ULL)bb;
            nm = (ULL)m * (ULL)M[j];

            tmp = ab + nm;
            carry = (tmp<ab);
            tmp += (ULL)cp[j];
            carry += (tmp<cp[j]);
            tmp += carry1;
            carry += (tmp<carry1);

            cp[j] = (UL)tmp;
            carry1 = (((ULL)carry)<<32) + (tmp>>32);


/*          //ai*bi

            tmp = (ULL)a[j] * (ULL)bb;
            ht = (UL)(tmp >> 32);
            lt = (UL)tmp;

            //n0*M

            tmp1 = (ULL)m * (ULL)M[j];
            ht1 = (UL)(tmp1 >> 32);
            lt1 = (UL)tmp1;

            //ci=ci+ai*bi+n0*M+carry

            tmp = (ULL)lt + (ULL)lt1;
            tmp += (ULL)cp[j];
            tmp += (ULL)carry;
            cp[j] = (UL)tmp;

            carry1 += (ULL)ht;
            carry1 += (ULL)ht1;
            tmp >>= 32;
            carry1 += tmp;
            carry = (UL)carry1;
            carry1 >>= 32;
*/
        }

        carry = (UL)carry1;
        carry1 >>= 32;

        cp[j] += carry;
        k = j+1;

        if(cp[j] < carry)
        {
            //cp[k] += 1;
            //cp[k] += (UL)carry1;
            cp[k] = 1 + (UL)carry1;
        }
        else
            //cp[k] += (UL)carry1;
            cp[k] = (UL)carry1;

        cp++;
    }

    //判断乘积位数是否超过模数位数
//printf("count1: %d, count2: %d",count1,count2 );

    if(!carry1)
    {
        for(i = 0; i < M_Len; i++)
            r[i] = c[M_Len + i];

        if(BN_ucmp_sm2(r, M_Len, M, M_Len) >= 0)
        {
            BN_usub_sm2(r, &rl, r, M_Len, M, M_Len);
        }
    }
    else
        BN_usub_sm2(r, &rl, &c[M_Len], M_Len+1, M, M_Len);
}

void BN_mod_mul_montgomery_one_sm2(BN_ULONG *r, BN_ULONG *a, BN_ULONG *M, int M_Len, BN_ULONG n0)
{
    int i, j, k;
    UL ht1, lt1, carry, m, u;
    int rl;
    ULL tmp, tmp1, carry1;
    UL c[ECC_MAX_BLOCK_LEN_DWORD*2+1], *cp;
    int first = 1;

    cp = c;

    memset(c, 0, sizeof(c));

    for(i = 0; i < M_Len; i++)
    {
        u = *cp;

        carry = 0;
        carry1 = 0;

        if(first)
            m = (UL)((ULL)(a[0]+u) * (ULL)n0);
        else
            m = (UL)(u * n0);

        for(j = 0; j < M_Len; j++)
        {

            //n0*M

            tmp1 = (ULL)m * (ULL)M[j];
            ht1 = (UL)(tmp1>>32);
            lt1 = (UL)tmp1;

            //ci=ci+ai*bi+n0*M+carry

            if(first)
                tmp = (ULL)a[j] + (ULL)lt1;
            else
                tmp = (ULL)lt1;
            tmp += (ULL)cp[j];
            tmp += (ULL)carry;
            cp[j] = (UL)tmp;

            carry1 += (ULL)ht1;
            tmp >>= 32;
            carry1 += tmp;
            carry = (UL)carry1;
            carry1 >>= 32;
        }
        cp[j] += carry;
        k = j+1;

        if(cp[j] < carry)
        {
            cp[k] += 1;
            cp[k] += (UL)carry1;
        }
        else
            cp[k] += (UL)carry1;

        cp++;

        if(first)
            first = 0;
    }

    //判断乘积位数是否超过模数位数

    if(!carry1)
    {
        for(i = 0; i < M_Len; i++)
            r[i] = c[M_Len + i];

        if(BN_ucmp_sm2(r, M_Len, M, M_Len) >= 0)
        {
            BN_usub_sm2(r, &rl, r, M_Len, M, M_Len);
        }
    }
    else
        BN_usub_sm2(r, &rl, &c[M_Len], M_Len+1, M, M_Len);
}
#endif
