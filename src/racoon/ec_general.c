#include "ec_general.h"
#include "ec_bn.h"



/////////////////////////////////////////////
//                                         //
//  º¯Êý¹¦ÄÜ:                              //
//      ³õÊ¼»¯ÇúÏß²ÎÊý(pÓò)                //
//  º¯Êý²ÎÊý:                              //
//      ECCPara:in,ÇúÏß²ÎÊý                //
//      group:out,´¦ÀíºóµÄÇúÏß²ÎÊý         //
//  º¯Êý·µ»Ø:                              //
//      ÎÞ                                  //
//                                         //
/////////////////////////////////////////////

extern void sw_memdump(unsigned char * buf, unsigned int len);


#define PPC_64

#if defined(PPC_64)
#define data_htonl(x)   ((((x) & 0xFF000000)>>24) | (((x) & 0x00FF0000)>>8) | \
                        (((x) & 0x0000FF00)<<8 ) | (((x) & 0x000000FF)<<24))
#else
#define data_htonl(x)   (x)
#endif

static void convert_data(char *psrc, uint32_t *pdst, int len)
{
    uint32_t u4_data;
    int      ii;

    for (ii=0; ii<(len/4); ii++)
    {
        GET_UINT32_BE(u4_data, psrc, ii*4);
        //PUT_UINT32_BE(u4_data, pdst, ii*4);
        *pdst++ = u4_data;
    }
}
/****add by leon for test***/

/**************************************************************************************
 *
 * ¿¿¿ void Exchange(unsigned char* arr,unsigned int len);
 * ¿¿¿ ¿¿¿¿¿¿¿¿¿¿
 * ¿¿¿ arr:    ¿¿
 *         len:    ¿¿¿¿¿¿
 *         ¿¿¿¿    void
 *
 *         ****************************************************************************************/
void Exchange(unsigned char* arr, unsigned int len)
{
    unsigned int i;
    unsigned char temp;
    for (i = 0; i < len / 2; i++) {
        temp = arr[i];
        arr[i] = arr[len - 1 - i];
        arr[len - 1 - i] = temp;
    }
}
/**************************************************************************************
 *
 * ¿¿¿ void Exchange_DWORD(unsigned char* arr,unsigned int len,int Flag);
 * ¿¿¿ ¿¿¿¿DWORD¿¿¿¿¿
 * ¿¿¿ arr:    ¿¿
 *         len:    ¿¿¿¿¿¿
 *                 Flag:
 *                 ¿¿¿¿    void
 *
 *                 ****************************************************************************************/
void Exchange_DWORD(unsigned char* arr, unsigned int len, int Flag)
{
    if (Flag == 0) { //¿¿¿
        Exchange(arr, len);
    }
    unsigned int DWORD_Num = len / 4;
    unsigned int i;
    unsigned char temp1;
    unsigned char temp2;
    unsigned char tmp_arr[4] = {0};
    if (len % 4 == 0) {
        for (i = 0; i < DWORD_Num; i++) {
            memcpy(tmp_arr, arr + i * 4, 4);
            temp1 = tmp_arr[0];
            temp2 = tmp_arr[1];
            tmp_arr[0] = tmp_arr[3];
            tmp_arr[1] = tmp_arr[2];
            tmp_arr[2] = temp2;
            tmp_arr[3] = temp1;
            memcpy(arr + i * 4, tmp_arr, 4);
            memset(tmp_arr, 0, 4);
        }
    } else { 
        for (i = 0; i < DWORD_Num; i++) {
            memcpy(tmp_arr, arr + i * 4, 4);
            temp1 = tmp_arr[0];
            temp2 = tmp_arr[1];
            tmp_arr[0] = tmp_arr[3];
            tmp_arr[1] = tmp_arr[2];
            tmp_arr[2] = temp2;
            tmp_arr[3] = temp1;
            memcpy(arr + i * 4, tmp_arr, 4);
            memset(tmp_arr, 0, 4);
        }

        unsigned int yu = len % 4;

        unsigned char *pbuf;

        pbuf = malloc(yu);

        if (!pbuf)
            return;

        memset(pbuf, 0, yu);
        memcpy(pbuf, arr + DWORD_Num * 4, yu);
        Exchange(pbuf, yu);
        unsigned int tt;
        memcpy(&tt, pbuf, yu);
        memcpy(arr + DWORD_Num * 4, pbuf, yu);
        free(pbuf);
        pbuf = NULL;
    }
}










void ECC_InitParameter(ECCParameter *pECCPara, EC_GROUP *group, unsigned int BitLen)
{
	int i;
	int dwords;
	unsigned int ByteLen, DWLen;
	unsigned char t[ECC_MAX_BLOCK_LEN];
	BN_ULONG tmp[ECC_MAX_BLOCK_LEN_DWORD];			
	memset(group,0,sizeof(EC_GROUP));
	
	printf("%s:%d ECCParameter\n", __FUNCTION__, __LINE__);
	sw_memdump((unsigned char *)pECCPara, sizeof(ECCParameter));
	
	ByteLen = (BitLen+7)>>3;
	DWLen = (BitLen+31)>>5;
			
	/** ¿¿¿p*/
	for(i = 0; i < ByteLen; i++)
		t[i] = pECCPara->p[ByteLen-1-i];
	Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
    memcpy(group->field.d, t, ByteLen);								
	printf("%s:%d group->field.d\n", __FUNCTION__, __LINE__);
	sw_memdump((unsigned char *)group->field.d, sizeof(group->field.d));
	
	/** ¿¿¿a*/
	for(i = 0; i < ByteLen; i++)
		t[i] = pECCPara->a[ByteLen-1-i];
	Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
    memcpy(group->a.d, t, ByteLen);								
	printf("%s:%d group->a.d\n", __FUNCTION__, __LINE__);
	sw_memdump((unsigned char *)group->a.d, sizeof(group->a.d));

	/** ¿¿¿b*/
	for(i = 0; i < ByteLen; i++)
		t[i] = pECCPara->b[ByteLen-1-i];
	Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
    memcpy(group->b.d, t, ByteLen);								
	printf("%s:%d group->b.d\n", __FUNCTION__, __LINE__);
	sw_memdump((unsigned char *)group->b.d, sizeof(group->b.d));

	/** ¿¿¿¿¿*/
	for(i = 0; i < ByteLen; i++)
		t[i] = pECCPara->Gx[ByteLen-1-i];
	Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
    memcpy(group->generator.X.d, t, ByteLen);
	printf("%s:%d group->generator.X.d\n", __FUNCTION__, __LINE__);
	sw_memdump((unsigned char *)group->generator.X.d, sizeof(group->generator.X.d));
	
	for(i = 0; i < ByteLen; i++)
		t[i] = pECCPara->Gy[ByteLen-1-i];
	Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
    memcpy(group->generator.Y.d, t, ByteLen);								
	printf("%s:%d group->generator.Y.d\n", __FUNCTION__, __LINE__);
	sw_memdump((unsigned char *)group->generator.Y.d, sizeof(group->generator.Y.d));

	/** ¿¿¿¿*/
    	dwords = DWLen;
    	bn_fix_top_sm2(group->field.d,&dwords);	
	group->field_top=dwords;
	printf("%s:%d group->field_top %d\n", __FUNCTION__, __LINE__, group->field_top);

	/** ¿¿¿¿ */
	for(i = 0; i < ByteLen; i++)
		t[i] = pECCPara->Gn[ByteLen-1-i];
	Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
    memcpy(group->order.d, t, ByteLen);
	printf("%s:%d group->order.d\n", __FUNCTION__, __LINE__);
	sw_memdump((unsigned char *)group->order.d, sizeof(group->order.d));
	
	/** ¿¿¿¿ */
	 dwords = DWLen;
	bn_fix_top_sm2(group->order.d, &dwords);	
	group->order_top = dwords;

	printf("%s:%d group->field.d\n", __FUNCTION__, __LINE__);
	sw_memdump((unsigned char *)group->field.d, sizeof(group->field.d));
	BN_MONT_CTX_set_sm2(group->field.d, group->field_top, &group->n0, group->RR.d);		
	memset(tmp,0,sizeof(tmp));
	tmp[0]=1;				
	printf("%s:%d group->RR.d group->n0 %u\n", __FUNCTION__, __LINE__, group->n0);
	sw_memdump((unsigned char *)group->RR.d, sizeof(group->RR.d));
	
	BN_mod_mul_montgomery_sm2(group->field_data2.d, tmp, group->RR.d, group->field.d, group->field_top, group->n0);
	printf("%s:%d group->field_data2.d\n", __FUNCTION__, __LINE__);	
	sw_memdump((unsigned char *)group->field_data2.d, sizeof(group->field_data2.d));

	BN_mod_mul_montgomery_sm2(group->a.d, group->a.d, group->RR.d, group->field.d, group->field_top, group->n0);
	BN_mod_mul_montgomery_sm2(group->b.d, group->b.d, group->RR.d, group->field.d, group->field_top, group->n0);
	BN_mod_mul_montgomery_sm2(group->generator.X.d, group->generator.X.d, group->RR.d, group->field.d, group->field_top, group->n0);
	printf("%s:%d group->generator.X.d\n", __FUNCTION__, __LINE__);
	sw_memdump((unsigned char *)group->generator.X.d, sizeof(group->generator.X.d));
	
	BN_mod_mul_montgomery_sm2(group->generator.Y.d, group->generator.Y.d, group->RR.d, group->field.d, group->field_top, group->n0);
	printf("%s:%d group->group->generator.Y.d\n", __FUNCTION__, __LINE__);
	sw_memdump((unsigned char *)group->generator.Y.d ,sizeof(group->generator.Y.d));	

	memcpy(group->generator.Z.d, group->field_data2.d, BIGNUM_SIZE);	
    group->generator.Z_is_one = 1;
    group->BitLen = BitLen;
	srand( (unsigned)time( NULL ) );
}

/////////////////////////////////////////////
//                                         //
//  º¯Êý¹¦ÄÜ:                              //
//      ²úÉúECCÃÜÔ¿¶Ô                       //
//      1<=k<=n-1                          //
//  º¯Êý²ÎÊý:                              //
//      group:in,ÇúÏßÈº½á¹¹             //
//      pECCPK:out,ECC¹«Ô¿                 //
//      pECCSK:out,ECCË½Ô¿                 //
//  º¯Êý·µ»Ø:                              //
//      ÎÞ                                 //
//                                         //
/////////////////////////////////////////////


void ECC_GenerateKeyPair(EC_GROUP *group, ECC_PUBLIC_KEY *pECCPK, ECC_PRIVATE_KEY *pECCSK)
{
    int i;
    BIGNUM_SM2 k;
    BIGNUM_SM2 x, y;
    EC_POINT R;
    unsigned int ByteLen, DWLen;
    unsigned char t[ECC_MAX_BLOCK_LEN];

    ByteLen = (group->BitLen+7)>>3;
    DWLen = (group->BitLen+31)>>5;

    memset(&k, 0, BIGNUM_SIZE);
    memset(&x, 0, BIGNUM_SIZE);
    memset(&y, 0, BIGNUM_SIZE);

again:
    //²úÉúË½Ô¿SK,1<=SK<=n-1
    for(i = 0; i < ByteLen; i++)
        t[i] = (unsigned char)rand();


    memset(&k, 0, BIGNUM_SIZE);
    memcpy(k.d, t, ByteLen);
    if(BN_is_zero_sm2(k.d, DWLen))
        goto again;

    //1 <= k <= n-1
    while(k.d[DWLen-1] >= group->order.d[DWLen-1])
        k.d[DWLen-1] >>= 1;

    //(x,y)=kG,¼ÆËã¹«Ô¿
    EC_POINTs_mul_sm2(group, &R, &group->generator, &k, NULL, NULL);
    ec_GFp_simple_point_get_affine_coordinates_GFp(group, &R, &x, &y);

    //½«Ð¡¶ËÄ£Ê½×ª»»µ½´ó¶ËÄ£Ê½£¬²¢Êä³ö¹«Ë½Ô¿
    memcpy(t, x.d, ByteLen);
    for(i = 0; i < ByteLen; i++)
        pECCPK->Qx[i] = t[ByteLen-1-i];

    memcpy(t, y.d, ByteLen);
    for(i = 0; i < ByteLen; i++)
        pECCPK->Qy[i] = t[ByteLen-1-i];

    memcpy(t, k.d, ByteLen);
    for(i = 0; i < ByteLen; i++)
        pECCSK->Ka[i] = t[ByteLen-1-i];
}

////////////////////////////////////////////////
//                                            //
//  º¯Êý¹¦ÄÜ:                                 //
//      1.ÑéÖ¤ÇúÏß²ÎÊý                        //
//      2.ÑéÖ¤µãÊÇ·ñÔÚÇúÏßÉÏ                  //
//  º¯Êý²ÎÊý:                                 //
//      pECCPara:in,ECCÇúÏß²ÎÊý               //
//      pECCPoint:in,´ýÑéÖ¤µÄµã               //
//  º¯Êý·µ»Ø:                                 //
//      1:µãÔÚÇúÏßÉÏ                          //
//      0:µã²»ÔÚÇúÏßÉÏ                        //
//                                            //
////////////////////////////////////////////////
int POINT_is_on_curve(EC_GROUP *group, ECCParameter *pECCPara, ECC_PUBLIC_KEY *pECCPoint)
{
    unsigned char t[ECC_MAX_BLOCK_LEN];
    BIGNUM_SM2 p, a, b;
    BIGNUM_SM2 X, Y;
    unsigned int ByteLen, DWLen;
    BN_ULONG temp1[ECC_MAX_BLOCK_LEN_DWORD*2+1];
    BN_ULONG temp2[ECC_MAX_BLOCK_LEN_DWORD*2+1];
    BIGNUM_SM2 tmp_data;

    int p_top, a_top, b_top;
    int X_top, Y_top;
    int temp1_top, temp2_top;
    int i;
    int ret;

#if 1
    memset((void *)&tmp_data, 0, sizeof(BIGNUM_SM2));

    printf("--------------------------------------------------------------\n");
    printf("----%s  group \n", __FUNCTION__);
    sw_memdump((unsigned char *)group, sizeof(EC_GROUP));

    printf("--------------------------------------------------------------\n");
    printf("---- ECC_PUBLIC_KEY (Qx)----\n");
    sw_memdump((unsigned char *)pECCPoint->Qx, ECC_MAX_BLOCK_LEN);
    printf("---- ECC_PUBLIC_KEY (Qy)----\n");
    sw_memdump((unsigned char *)pECCPoint->Qy, ECC_MAX_BLOCK_LEN);
#endif

    ByteLen = (group->BitLen+7)>>3;
    DWLen = (group->BitLen+31)>>5;

    //³õÊ¼»¯p
    for(i = 0; i < ByteLen; i++)
        t[i] = pECCPara->p[ByteLen-1-i];
    Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
    memcpy(p.d, t, ByteLen);

#if 1
    memcpy((char *)tmp_data.d, t, ByteLen);
//    convert_data((char *)t, (uint32_t *)tmp_data.d, ByteLen);

    printf("----%s  p.d \n", __FUNCTION__);
    sw_memdump((unsigned char *)tmp_data.d, ByteLen);
#endif

    p_top = DWLen;
    bn_fix_top_sm2(p.d, &p_top);

    //³õÊ¼»¯a
    for(i = 0; i < ByteLen; i++)
        t[i] = pECCPara->a[ByteLen-1-i];
    Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
    memcpy(a.d, t, ByteLen);
    a_top = DWLen;
    bn_fix_top_sm2(a.d, &a_top);

#if 1
    memcpy((char *)tmp_data.d, t, ByteLen);
//    convert_data((char *)t, (uint32_t *)tmp_data.d, ByteLen);

    printf("----%s  a.d \n", __FUNCTION__);
    sw_memdump((unsigned char *)tmp_data.d, ByteLen);
#endif

    //³õÊ¼»¯b
    for(i = 0; i < ByteLen; i++)
        t[i] = pECCPara->b[ByteLen-1-i];
    Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
    memcpy(b.d, t, ByteLen);
    b_top = DWLen;
    bn_fix_top_sm2(b.d, &b_top);

#if 1
    memcpy((char *)tmp_data.d, t, ByteLen);
//    convert_data((char *)t, (uint32_t *)tmp_data.d, ByteLen);

    printf("----%s  b.d \n", __FUNCTION__);
    sw_memdump((unsigned char *)tmp_data.d, ByteLen);
#endif

    //³õÊ¼»¯´ýÑéÖ¤µã
    for(i = 0; i < ByteLen; i++)
        t[i] = pECCPoint->Qx[ByteLen-1-i];
    Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
    memcpy(X.d, t, ByteLen);

#if 1
    memcpy((char *)tmp_data.d, t, ByteLen);
//    convert_data((char *)t, (uint32_t *)tmp_data.d, ByteLen);

    printf("----%s  X.d \n", __FUNCTION__);
    sw_memdump((unsigned char *)tmp_data.d, ByteLen);
#endif

    X_top = DWLen;
    bn_fix_top_sm2(X.d, &X_top);
    for(i = 0; i < ByteLen; i++)
        t[i] = pECCPoint->Qy[ByteLen-1-i];
    Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
    memcpy(Y.d, t, ByteLen);

    Y_top = DWLen;
    bn_fix_top_sm2(Y.d, &Y_top);

#if 1
    memcpy((char *)tmp_data.d, t, ByteLen);
//    convert_data((char *)t, (uint32_t *)tmp_data.d, ByteLen);

    printf("----%s  Y.d \n", __FUNCTION__);
    sw_memdump((unsigned char *)tmp_data.d, sizeof(BIGNUM_SM2));
#endif

    //x ^ 3 + a * x + b mod p
    BN_mul_sm2(temp1, &temp1_top, X.d, X_top, X.d, X_top);
    BN_div_sm2(NULL, NULL, temp1, &temp1_top, temp1, temp1_top, p.d, p_top);
    BN_mul_sm2(temp2, &temp2_top, temp1, temp1_top, X.d, X_top);
    BN_div_sm2(NULL, NULL, temp1, &temp1_top, temp2, temp2_top, p.d, p_top);
    BN_mul_sm2(temp2, &temp2_top, a.d, a_top, X.d, X_top);
    BN_div_sm2(NULL, NULL, temp2, &temp2_top, temp2, temp2_top, p.d, p_top);
    BN_uadd_sm2(temp1, &temp1_top, temp1, temp1_top, temp2, temp2_top);
    BN_div_sm2(NULL, NULL, temp1, &temp1_top, temp1, temp1_top, p.d, p_top);
    BN_uadd_sm2(temp1, &temp1_top, temp1, temp1_top, b.d, b_top);
    BN_div_sm2(NULL, NULL, temp1, &temp1_top, temp1, temp1_top, p.d, p_top);

    //y ^ 2
    BN_mul_sm2(temp2, &temp2_top, Y.d, Y_top, Y.d, Y_top);
    BN_div_sm2(NULL, NULL, temp2, &temp2_top, temp2, temp2_top, p.d, p_top);
    ret = BN_ucmp_sm2(temp1, temp1_top, temp2, temp2_top);
    if( ret )
    {
        printf("--------[POINT_is_on_curve] return fail!!!!\n");
        return 0;
    }
    printf("--------[POINT_is_on_curve] return OK.\n");
    return 1;
}

