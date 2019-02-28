#include <stdio.h>
#include "SM2_DSA.h"

extern void sw_memdump(unsigned char * buf, unsigned int len);
																																
/////////////////////////////////////////////
//										   //
//	函数功能:							   //
//      ECDSA签名运算(p域)                 //
//	函数参数:							   //
//      group:in,曲线参数                  //
//		e:in,HASH值						   //
//		pECCSK:in,ECC私钥		    	   //							
//		pECCSign:out,签名值				   //
//	函数返回:							   //
//      无                                 //
//										   //
/////////////////////////////////////////////

void Exchange_DWORD(unsigned char* arr,unsigned int len,int Flag);


//  具体算法前要添加A1,A2两个步骤
void ECDSA_Sig(EC_GROUP *group, unsigned char *e, unsigned int e_len, unsigned char *pRand, ECC_PRIVATE_KEY *pECCSK, ECC_SIGNATURE *pECCSign)
{
	int i, top,top1;
	EC_POINT R;
	BIGNUM_SM2 k;
	BIGNUM_SM2 x, y;
    BIGNUM_SM2  zwk_temp,r_add_k,number_1,number_1_add_da,k_sub_rda;
	unsigned char t[ECC_MAX_BLOCK_LEN];
	BIGNUM_SM2 tmp1, tmp2;
	BN_ULONG tmp3[ECC_MAX_BLOCK_LEN_DWORD*2+1],tmp4[ECC_MAX_BLOCK_LEN_DWORD*2+1];
	BIGNUM_SM2 Plain;
	BIGNUM_SM2 SK;
	BIGNUM_SM2 r, s;
	unsigned char tmp_e[ECC_MAX_BLOCK_LEN];  

	//init plain text
	if(e_len < ECC_MAX_BLOCK_LEN) {
		memset(tmp_e, 0, ECC_MAX_BLOCK_LEN);
		memcpy(tmp_e, e, e_len);
	} else {
		memcpy(tmp_e, e, ECC_MAX_BLOCK_LEN);
	}
	memset(&Plain, 0, BIGNUM_SIZE);
	for(i = 0; i < ECC_MAX_BLOCK_LEN; i++)
		t[i] = tmp_e[ECC_MAX_BLOCK_LEN-1-i];
    Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
    memcpy(Plain.d, t, ECC_MAX_BLOCK_LEN);

	//初始化私钥
	memset(&SK, 0, BIGNUM_SIZE);
	for(i = 0; i < ECC_MAX_BLOCK_LEN; i++)
		t[i] = pECCSK->Ka[ECC_MAX_BLOCK_LEN-1-i];
    Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
    memcpy(SK.d, t, ECC_MAX_BLOCK_LEN);				
	memset(&k, 0, BIGNUM_SIZE);
	
	if(pRand == NULL)
	{
		for(i=0;i<ECC_MAX_BLOCK_LEN;i++)
			t[i]=0xff;//(unsigned char)rand();
		pRand = t;	
	}		
	memcpy(k.d, pRand, ECC_MAX_BLOCK_LEN);

	
	while(k.d[ECC_MAX_BLOCK_LEN_DWORD-1] >= group->order.d[ECC_MAX_BLOCK_LEN_DWORD-1])
		k.d[ECC_MAX_BLOCK_LEN_DWORD-1] >>= 1;	
 	
 	//(x1, y1) = kG
 	EC_POINTs_mul_sm2(group, &R, &group->generator, &k, NULL, NULL); 
    ec_GFp_simple_point_get_affine_coordinates_GFp(group, &R, &x, &y);  
	
	//r =( e+x) mod n
	BN_mod_add_sm2(zwk_temp.d, Plain.d, x.d, group->order.d, group->order_top);	
    BN_div_sm2(NULL, NULL, r.d, &top, zwk_temp.d, group->order_top, group->order.d, group->order_top);		

	//r+k=n
	BN_mod_add_sm2(r_add_k.d, r.d, k.d, group->order.d, group->order_top);	
		
	//1+da
	memset(number_1.d, 0x00, sizeof(BIGNUM_SM2));
	number_1.d[0]=0x1;
    BN_mod_add_sm2(number_1_add_da.d, number_1.d, SK.d, group->order.d, group->order_top);

    //1+da 的逆
	BN_mod_inverse_sm2(tmp2.d, &top, number_1_add_da.d, group->order_top, group->order.d, group->order_top);

	// r.da
	BN_mul_sm2(tmp3, &top, SK.d, group->order_top, r.d, group->order_top);
	BN_div_sm2(NULL, NULL, tmp1.d, &top, tmp3, top, group->order.d, group->order_top);

	//k-r.da
    BN_mod_sub_sm2(k_sub_rda.d, &top1, k.d, tmp1.d, group->order.d, group->field_top);

	//INVERSE((1+da))(k-rda)
  	BN_mul_sm2(tmp4, &top, k_sub_rda.d, group->order_top, tmp2.d, group->order_top);
	BN_div_sm2(NULL, NULL, s.d, &top, tmp4, top, group->order.d, group->order_top);		

	//将小端模式转换到大端模式，并输出
    memcpy(t, r.d, ECC_MAX_BLOCK_LEN);								
    Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
	for(i = 0; i < ECC_MAX_BLOCK_LEN; i++)
		pECCSign->r[i] = t[ECC_MAX_BLOCK_LEN-1-i];
    memcpy(t, s.d, ECC_MAX_BLOCK_LEN);								
    Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
	for(i = 0; i < ECC_MAX_BLOCK_LEN; i++)
		pECCSign->s[i] = t[ECC_MAX_BLOCK_LEN-1-i];
}

void sw_memdump(unsigned char * buf, unsigned int len)
{
#define LINE_LEN 4096
    unsigned int i, off = 0;
    const unsigned char *data = buf;
    char line[LINE_LEN];

    line[0] = '\0';
    for (i = 0; i < len; i++) {
		if(i > 0 && (i % 8 == 0)) {
			off += snprintf(line + off,  LINE_LEN - off, "\n"); 
		}
		off += snprintf(line + off,  LINE_LEN - off, "%02X ", buf[i]); 
    }

	printf("%s\n", line);
}												
/////////////////////////////////////////////
//										   //
//	函数功能:							   //
//      ECDSA验证签名运算(p域)             //
//	函数参数:							   //
//      group:in,曲线参数                  //
//		e:in,HASH值						   //
//		pECCPK:in,ECC公钥                  //							
//		pECCSign:in,签名值				   //
//	函数返回:							   //
//		1:验证成功						   //
//		0:验证失败						   //
//										   //
/////////////////////////////////////////////

int ECDSA_Verify(EC_GROUP *group, unsigned char *e, unsigned int e_len, ECC_PUBLIC_KEY *pECCPK, ECC_SIGNATURE *pECCSign)
{
	int i;
	int ret;
	EC_POINT R, Q;
	BIGNUM_SM2 r, s;
	BIGNUM_SM2 x, y;
	unsigned char t[ECC_MAX_BLOCK_LEN];
	unsigned char e_tmp[ECC_MAX_BLOCK_LEN];
	BIGNUM_SM2 Plain;
	BIGNUM_SM2  zwkr_add_s,R_out;	

	//初始化明文
	if(e_len > ECC_MAX_BLOCK_LEN) {
		memcpy(e_tmp, e, ECC_MAX_BLOCK_LEN);
	} else {
		memset(e_tmp, 0, ECC_MAX_BLOCK_LEN);
		memcpy(e_tmp, e, e_len);
	}
	memset(&Plain, 0, BIGNUM_SIZE);
	for(i = 0; i < ECC_MAX_BLOCK_LEN ; i++)
		t[i] = e_tmp[ECC_MAX_BLOCK_LEN-1-i];  
    Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
    memcpy(Plain.d, t, ECC_MAX_BLOCK_LEN);								

	//初始化公钥
	memset(&Q, 0, sizeof(EC_POINT));
	for(i = 0; i < ECC_MAX_BLOCK_LEN; i++)
		t[i] = pECCPK->Qx[ECC_MAX_BLOCK_LEN-1-i];
    Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
    memcpy(Q.X.d, t, ECC_MAX_BLOCK_LEN);							
	for(i = 0; i < ECC_MAX_BLOCK_LEN; i++)
		t[i] = pECCPK->Qy[ECC_MAX_BLOCK_LEN-1-i];
    Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
    memcpy(Q.Y.d, t, ECC_MAX_BLOCK_LEN);								

	//初始化r
	memset(&r, 0, BIGNUM_SIZE);
	for(i = 0; i < ECC_MAX_BLOCK_LEN; i++)
		t[i] = pECCSign->r[ECC_MAX_BLOCK_LEN-1-i];
    Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
    memcpy(r.d, t, ECC_MAX_BLOCK_LEN);	
	
	//r>=n,报错	
	ret = BN_ucmp_sm2(r.d, ECC_MAX_BLOCK_LEN_DWORD, group->order.d, ECC_MAX_BLOCK_LEN_DWORD);				
	if(ret >= 0)
		return 0;			//验证未通过

	//初始化s
	memset(&s, 0, BIGNUM_SIZE);
	for(i = 0; i < ECC_MAX_BLOCK_LEN; i++)
		t[i] = pECCSign->s[ECC_MAX_BLOCK_LEN-1-i];
    Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
    memcpy(s.d, t, ECC_MAX_BLOCK_LEN);								

	//s>=n,报错	
	ret = BN_ucmp_sm2(s.d, ECC_MAX_BLOCK_LEN_DWORD, group->order.d, ECC_MAX_BLOCK_LEN_DWORD);				
	if(ret >= 0)
		return 0;			//验证未通过

	BN_mod_mul_montgomery_sm2(Q.X.d, Q.X.d, group->RR.d, group->field.d, group->field_top, group->n0);
	BN_mod_mul_montgomery_sm2(Q.Y.d, Q.Y.d, group->RR.d, group->field.d, group->field_top, group->n0);
	memcpy(Q.Z.d, group->field_data2.d, group->field_top*BN_BYTES);
    Q.Z_is_one = 1;

	//r+s mod n
	BN_mod_add_sm2(zwkr_add_s.d, r.d, s.d, group->order.d, group->order_top);

	//X = sG + tPa
 	EC_POINTs_mul_sm2(group, &R, &group->generator, &s, &Q, &zwkr_add_s);   
    ec_GFp_simple_point_get_affine_coordinates_GFp(group, &R, &x, &y);

	//(e+x1) mod n
	BN_mod_add_sm2(R_out.d, Plain.d, x.d, group->order.d, group->order_top);	
	if(BN_ucmp_sm2(r.d, group->order_top, R_out.d, group->order_top))		
		return 0;			//验证未通过
		
	return 1;				//验证通过
}

