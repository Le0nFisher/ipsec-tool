
#include "SM2_ES.h"

extern void sw_memdump(unsigned char * buf, unsigned int len);

/////////////////////////////////////////////
//									       //
//	º¯Êý¹¦ÄÜ:  ÓàÒò×ÓhÎª 1						       //
//      ECES¼ÓÃÜÔËËã(pÓò)                  //
//	º¯Êý²ÎÊý:						       //
//      group:in,ÇúÏß²ÎÊý                  //
//		e:in,Ã÷ÎÄ					       //
//		pECCPK:in,ECC¹«Ô¿
//   int e_len  Ã÷ÎÄ³¤¶È	               //							
//		¼ÓÃÜ½á¹û
//  ECC_ENCRYPTION *pEncryption   ¼ÓÃÜÖµ
//    unsigned char *c1, ³¤¶ÈÊÇ32+32
//     unsigned char *c2, ºÍÃ÷ÎÄµÈ³¤
//      unsigned char *c3  ºÍÔÓ´ÕËã·¨Êä³öµÈ³¤£¬´Ë´¦Ñ¡ÓÃ32

	           //
//	º¯Êý·µ»Ø:							   //
//		ÎÞ        						   //
//										   //
/////////////////////////////////////////////

unsigned char tt[ECC_MAX_BLOCK_LEN];
void Exchange_DWORD(unsigned char* arr,unsigned int len,int Flag);

int ECES_Encryption(EC_GROUP *group, unsigned char *e, int e_len, unsigned char *pRand, ECC_PUBLIC_KEY *pECCPK,unsigned char *pbyCodeOut)
{
	unsigned int i;
	unsigned int j = 0;
	EC_POINT R, Q;
	BIGNUM_SM2 k;
	BIGNUM_SM2 x1, y1;
	BIGNUM_SM2 x2, y2;

	BIGNUM_SM2 Data;
	
	unsigned char x1in[ECC_MAX_BLOCK_LEN],y1in[ECC_MAX_BLOCK_LEN];
	unsigned char x2in[ECC_MAX_BLOCK_LEN],y2in[ECC_MAX_BLOCK_LEN];
	unsigned char data[ECC_MAX_BLOCK_LEN+1024+ECC_MAX_BLOCK_LEN];
    unsigned int ct = 0x00000001;
    unsigned char t[1024];    

	unsigned char c1[64];
	unsigned char c3[32];
	unsigned char tmp_e[ECC_MAX_BLOCK_LEN];  

	//init plain text
	if(e_len < ECC_MAX_BLOCK_LEN) {
		memset(tmp_e, 0, ECC_MAX_BLOCK_LEN);
		memcpy(tmp_e, e, e_len);
	} else {
		memcpy(tmp_e, e, ECC_MAX_BLOCK_LEN);
	}

	memset(&Data, 0, BIGNUM_SIZE);	
	for(i = 0; i < ECC_MAX_BLOCK_LEN; i++)
		t[i] = tmp_e[ECC_MAX_BLOCK_LEN-1-i];  
    Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
    memcpy(Data.d, t, ECC_MAX_BLOCK_LEN);

	printf("\nECES_Encryption Data.d \n");
	sw_memdump((unsigned char *)Data.d, ECC_MAX_BLOCK_LEN);
	
	//³õÊ¼»¯¹«Ô¿	
	memset(&Q, 0, sizeof(EC_POINT));
	for(i = 0; i < ECC_MAX_BLOCK_LEN; i++)
		t[i] = pECCPK->Qx[ECC_MAX_BLOCK_LEN-1-i];  
    Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
    memcpy(Q.X.d, t, ECC_MAX_BLOCK_LEN);

	printf("\nECES_Encryption Data.d \n");
	sw_memdump((unsigned char *)Q.X.d, ECC_MAX_BLOCK_LEN);
	
	for(i = 0; i < ECC_MAX_BLOCK_LEN; i++)
		t[i] = pECCPK->Qy[ECC_MAX_BLOCK_LEN-1-i]; 
    Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
    memcpy(Q.Y.d, t, ECC_MAX_BLOCK_LEN);

	printf("\nECES_Encryption Q.Y.d\n");
	sw_memdump((unsigned char *)Q.Y.d, ECC_MAX_BLOCK_LEN);
	
	BN_mod_mul_montgomery_sm2(Q.X.d, Q.X.d, group->RR.d, group->field.d, group->field_top, group->n0);
	BN_mod_mul_montgomery_sm2(Q.Y.d, Q.Y.d, group->RR.d, group->field.d, group->field_top, group->n0);
	memcpy(Q.Z.d, group->field_data2.d, group->field_top*BN_BYTES);
    Q.Z_is_one = 1;

  
	memset(&k, 0, BIGNUM_SIZE);
	if(pRand == NULL)
	{
		for(i=0;i<ECC_MAX_BLOCK_LEN;i++)
			tt[i]=0x5;//tt[i]=(unsigned char)rand();
		pRand = tt;	
	}
	memcpy(k.d, pRand, ECC_MAX_BLOCK_LEN);

	while(k.d[ECC_MAX_BLOCK_LEN_DWORD-1] >= group->order.d[ECC_MAX_BLOCK_LEN_DWORD-1])
		k.d[ECC_MAX_BLOCK_LEN_DWORD-1] >>= 1;

 	//(x1,y1)=kG
 	EC_POINTs_mul_sm2(group, &R, &group->generator, &k, NULL, NULL);   
	
    ec_GFp_simple_point_get_affine_coordinates_GFp(group, &R, &x1, &y1);

 	//(x2,y2)=kQ
	//  A3:  S= [k.h][h]Pb Ä¬ÈÏÓàÒò×ÓH=1
 	EC_POINTs_mul_sm2(group, &R, &Q, &k, NULL, NULL);  
    ec_GFp_simple_point_get_affine_coordinates_GFp(group, &R, &x2, &y2);

	//ÅÐ¶Ïx2ÊÇ·ñÎª0
	memcpy(t, x1.d, ECC_MAX_BLOCK_LEN);
    Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
	for(i = 0; i < ECC_MAX_BLOCK_LEN; i++)
		x1in[i] = t[ECC_MAX_BLOCK_LEN-1-i];
	memcpy(t, y1.d, ECC_MAX_BLOCK_LEN);									
    Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
	for(i = 0; i < ECC_MAX_BLOCK_LEN; i++)
		y1in[i] = t[ECC_MAX_BLOCK_LEN-1-i];

	for(i=0;i<32;i++)
		c1[i] =x1in[i];
	for(i=32;i<64;i++)
		c1[i] =y1in[i-32];

	for(i = 0; i < (int)group->field_top; i++)
	{
		if(x2.d[i])
			break;
	}
	if(i==(int)group->field_top)
		return -1;

	// ±¾´¦×öÊý¾ÝµÄµßµ¹
	memcpy(t, x2.d, ECC_MAX_BLOCK_LEN);
    Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
	for(i = 0; i < ECC_MAX_BLOCK_LEN; i++)
		x2in[i] = t[ECC_MAX_BLOCK_LEN-1-i];
	memcpy(t, y2.d, ECC_MAX_BLOCK_LEN);	
    Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
	for(i = 0; i < ECC_MAX_BLOCK_LEN; i++)
		y2in[i] = t[ECC_MAX_BLOCK_LEN-1-i];
	
	for(i=0;i<32;i++)
    	data[i] = x2in[i];	
	for(i=0;i<32;i++)
    	data[32+i] = y2in[i];

	for(i = 0; i < e_len/ECC_MAX_BLOCK_LEN; i++)
	{
		data[ECC_MAX_BLOCK_LEN*2] = (unsigned char)(ct >> 24);
		data[ECC_MAX_BLOCK_LEN*2+1] = (unsigned char)(ct >> 16);
		data[ECC_MAX_BLOCK_LEN*2+2] = (unsigned char)(ct >> 8);
		data[ECC_MAX_BLOCK_LEN*2+3] = (unsigned char)ct;

		SCH(data, ECC_MAX_BLOCK_LEN*2+4, 2, t);
		for(j = 0; j < ECC_MAX_BLOCK_LEN; j++)
			pbyCodeOut[2*ECC_MAX_BLOCK_LEN+ECC_MAX_BLOCK_LEN*i+j] = e[ECC_MAX_BLOCK_LEN*i+j] ^ t[j];
		
		ct += 1;
	}

	if(e_len%ECC_MAX_BLOCK_LEN)
	{
		data[ECC_MAX_BLOCK_LEN*2] = (unsigned char)(ct >> 24);
		data[ECC_MAX_BLOCK_LEN*2+1] = (unsigned char)(ct >> 16);
		data[ECC_MAX_BLOCK_LEN*2+2] = (unsigned char)(ct >> 8);
		data[ECC_MAX_BLOCK_LEN*2+3] = (unsigned char)ct;

		SCH(data, ECC_MAX_BLOCK_LEN*2+4, 2, t);
		for(j = 0; j < e_len%ECC_MAX_BLOCK_LEN; j++)
			pbyCodeOut[2*ECC_MAX_BLOCK_LEN+ECC_MAX_BLOCK_LEN*i+j] = e[ECC_MAX_BLOCK_LEN*i+j] ^ t[j];
	}

	memcpy(data, x2in, ECC_MAX_BLOCK_LEN);	
	memcpy(&data[ECC_MAX_BLOCK_LEN], e, e_len);
	memcpy(&data[ECC_MAX_BLOCK_LEN+e_len], y2in, ECC_MAX_BLOCK_LEN);	
	SCH(data,32+32+e_len,2,c3);

	for(i = 0; i < 2*ECC_MAX_BLOCK_LEN; i++)
		pbyCodeOut[i] = c1[i];					
	for(i = 0; i < ECC_MAX_BLOCK_LEN; i++)
		pbyCodeOut[2*ECC_MAX_BLOCK_LEN+e_len+i] = c3[i];

	printf("\nECES_Encryption pbyCodeOut\n");
	sw_memdump((unsigned char *)pbyCodeOut, sizeof(ECC_ENCRYPTION));

	
	return 1;

}

/////////////////////////////////////////////
//				                           //
//	º¯Êý¹¦ÄÜ:							   //
//      ECES½âÃÜÔËËã(pÓò)                  //
//	º¯Êý²ÎÊý:							   //
//      group:in,ÇúÏß²ÎÊý                  //
//		unsigned char *c1, unsigned char *c2,unsigned char *c3,¼ÓÃÜÖµ	           //

 //         ECCParameter   eccpa ÇúÏß²ÎÊý£¬ÓÃÓÚÅÐ¶ÏC1ÊÇ·ñÔÚÇúÏßÉÏ¡£

//  ECC_ENCRYPTION *pEncryption,
//    unsigned char *c1, ³¤¶ÈÊÇ32+32 £¬
//     unsigned char *c2, ºÍÃ÷ÎÄµÈ³¤
//      c2_len C2µÄ³¤¶È
//      unsigned char *c3  ºÍÔÓ´ÕËã·¨Êä³öµÈ³¤£¬´Ë´¦Ñ¡ÓÃ32

//		pECCSK:in,ECCË½Ô¿                  //							
//		e:out,Ã÷ÎÄ				           //
//	º¯Êý·µ»Ø:							   //
//		0 ²»³É¹¦£»
//      1  ³É¹¦     						   //
//										   //
/////////////////////////////////////////////

int ECES_Decryption(EC_GROUP *group, unsigned char *pCodeIn, int c2_len , ECC_PRIVATE_KEY *pECCSK, unsigned char *e)
{
	unsigned int i = 0;
	unsigned int j = 0;
	
	EC_POINT R,Q;
	
	BIGNUM_SM2 x,  y;
	BIGNUM_SM2 SK;
	unsigned char x2in[ECC_MAX_BLOCK_LEN],y2in[ECC_MAX_BLOCK_LEN];
	unsigned int ct = 0x00000001;
	unsigned char t[1024];
	unsigned char data[ECC_MAX_BLOCK_LEN+1024+ECC_MAX_BLOCK_LEN];
	
	//init encode 
	unsigned char c1[64];
	unsigned char c3[32];

	printf("\nDecryption pCodeIn\n");
	sw_memdump((unsigned char *)pCodeIn, sizeof(ECC_ENCRYPTION));

	
	memset(&Q, 0, sizeof(EC_POINT));
	for(i = 0; i < 2*ECC_MAX_BLOCK_LEN; i++)	
		c1[i] = pCodeIn[i];
	for(i = 0; i < ECC_MAX_BLOCK_LEN; i++)	
		c3[i] =  pCodeIn[2*ECC_MAX_BLOCK_LEN+c2_len+i];
	for(i = 0; i < ECC_MAX_BLOCK_LEN; i++)	
		t[i] = c1[31-i];

    Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
	
	memcpy(Q.X.d, t, ECC_MAX_BLOCK_LEN);		
	for(i = 0; i < ECC_MAX_BLOCK_LEN; i++)
		t[i] = c1[63-i];
    Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
	memcpy(Q.Y.d, t, ECC_MAX_BLOCK_LEN);

	//3?��??��????		
	memset(&SK, 0, BIGNUM_SIZE);
	for(i = 0; i < ECC_MAX_BLOCK_LEN; i++)
		t[i] = pECCSK->Ka[ECC_MAX_BLOCK_LEN-1-i];  
    Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
	memcpy(SK.d, t, ECC_MAX_BLOCK_LEN); 

	printf("\nDecryption SK.d\n");
	sw_memdump((unsigned char *)SK.d, ECC_MAX_BLOCK_LEN);
	
	BN_mod_mul_montgomery_sm2(Q.X.d, Q.X.d, group->RR.d, group->field.d, group->field_top, group->n0);
	BN_mod_mul_montgomery_sm2(Q.Y.d, Q.Y.d, group->RR.d, group->field.d, group->field_top, group->n0);
	memcpy(Q.Z.d, group->field_data2.d, group->field_top*BN_BYTES); 
	Q.Z_is_one=1;								
	
	//(x1,y1)=dQ
	EC_POINTs_mul_sm2(group, &R, &Q, &SK, NULL,NULL); 
	ec_GFp_simple_point_get_affine_coordinates_GFp(group, &R, &x, &y);
	if(BN_is_zero_sm2(x.d, ECC_MAX_BLOCK_LEN_DWORD)||BN_is_zero_sm2(y.d, ECC_MAX_BLOCK_LEN_DWORD))
		return 0; // ?T????��?
	
	
	// B2
	// ��?��|��?��y?Y��?��?��1
	memcpy(t, x.d, ECC_MAX_BLOCK_LEN);
    Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
	for(i = 0; i < ECC_MAX_BLOCK_LEN; i++)
		x2in[i] = t[ECC_MAX_BLOCK_LEN-1-i];
	memcpy(t, y.d, ECC_MAX_BLOCK_LEN);	
    Exchange_DWORD(t, sizeof(t) / sizeof(t[0]), 1);
	for(i = 0; i < ECC_MAX_BLOCK_LEN; i++)
		y2in[i] = t[ECC_MAX_BLOCK_LEN-1-i]; 
	for(i=0;i<32;i++)
		data[i] = x2in[i];	
	for(i=0;i<32;i++)
		data[32+i] = y2in[i];
	
	for(i = 0; i < c2_len/ECC_MAX_BLOCK_LEN; i++)
	{
		data[ECC_MAX_BLOCK_LEN*2] = (unsigned char)(ct >> 24);
		data[ECC_MAX_BLOCK_LEN*2+1] = (unsigned char)(ct >> 16);
		data[ECC_MAX_BLOCK_LEN*2+2] = (unsigned char)(ct >> 8);
		data[ECC_MAX_BLOCK_LEN*2+3] = (unsigned char)ct;
		
		SCH(data, ECC_MAX_BLOCK_LEN*2+4, 2, t);
		for(j = 0; j < ECC_MAX_BLOCK_LEN; j++)
			e[ECC_MAX_BLOCK_LEN*i+j] = pCodeIn[2*ECC_MAX_BLOCK_LEN+ECC_MAX_BLOCK_LEN*i+j] ^ t[j];
		
		ct += 1;
	}
	
	if(c2_len%ECC_MAX_BLOCK_LEN)
	{
		data[ECC_MAX_BLOCK_LEN*2] = (unsigned char)(ct >> 24);
		data[ECC_MAX_BLOCK_LEN*2+1] = (unsigned char)(ct >> 16);
		data[ECC_MAX_BLOCK_LEN*2+2] = (unsigned char)(ct >> 8);
		data[ECC_MAX_BLOCK_LEN*2+3] = (unsigned char)ct;
		
		SCH(data, ECC_MAX_BLOCK_LEN*2+4, 2, t);
		for(j = 0; j < c2_len%ECC_MAX_BLOCK_LEN; j++)
			e[ECC_MAX_BLOCK_LEN*i+j] = pCodeIn[2*ECC_MAX_BLOCK_LEN+ECC_MAX_BLOCK_LEN*i+j] ^ t[j];
	}
	
	memcpy(data, x2in, ECC_MAX_BLOCK_LEN);	
	memcpy(&data[ECC_MAX_BLOCK_LEN], e, c2_len);	
	memcpy(&data[ECC_MAX_BLOCK_LEN+c2_len], y2in, ECC_MAX_BLOCK_LEN);									
	SCH(data, ECC_MAX_BLOCK_LEN+c2_len+ECC_MAX_BLOCK_LEN, 2, t);
	
	if(memcmp(t, c3, 32))
		return 0;
	else	
		return 1;
}



