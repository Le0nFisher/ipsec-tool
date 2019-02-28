/*
 * sm4.c
 *
 *  Created on: 2015-9-16
 *      Author: lyyu (Liyang Yu)
 *	   Version: 1.0
 * Description:	xfrm(IPsec) sm4 algorithm source file for ike
 */
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
	 
#include <sys/param.h>
#include <stdarg.h>
	 
#include <openssl/ec.h>
#include <openssl/x509.h>
#include "config.h"
	 
#include "var.h"
#include "misc.h"
#include "vmbuf.h"
#include "plog.h"
#include "sockmisc.h"
#include "debug.h"
#include "sm2.h"
#include "sm4.h"
#include "ec_bn.h"

//SM4--begin
unsigned char  sm4_key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 }; //  ��Կ
unsigned char sm4_iv[16] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}; // CBCģʽ�µ�IV��16���ֽڡ�

//ѭ������nλ
#define  shift(x,n) (((x)<<(n))|((x)>>(32-(n))))
#define  L_CHANGE(x)  (x)^ shift((x), 2) ^ shift((x), 10)^shift((x), 18)^ shift((x), 24)
#define L_KEY(x)  (x)^shift((x), 13)^shift((x), 23)


static u_int32_t FK[4] = {  0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC };
static u_int32_t CK[32] = {  0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
							 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
							 0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
							 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
							 0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
							 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
							 0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
							 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
						  };

static unsigned char SBOX[256] = {
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};
#define  T_CHANGE(x) (SBOX[((x)>>24)&0xff]<<24) |(SBOX[((x)>>16)&0xff]<<16)|(SBOX[((x)>>8)&0xff]<<8)|SBOX[(x)&0xff]

static inline void KEY_EXPAND(u_int32_t KEY[4], u_int32_t RK[32])
{
	int i;
	u_int32_t MK[36];
	MK[0] = KEY[0] ^ FK[0];
	MK[1] = KEY[1] ^ FK[1];
	MK[2] = KEY[2] ^ FK[2];
	MK[3] = KEY[3] ^ FK[3];

	for (i = 0; i < 32; i++) {
		RK[i] =  MK[i] ^ L_KEY((u_int32_t)(T_CHANGE(MK[i + 1] ^ MK[i + 2] ^ MK[i + 3] ^ CK[i])));
		MK[i + 4] = RK[i];
	}
}

static inline void  ECB_EN_MOD(u_int32_t  text_in[4], u_int32_t rk[32], u_int32_t text_out[4])
{
	int i;

	u_int32_t  x0, x1, x2, x3;

	u_int32_t 	mid;

	x0 = text_in[0];
	x1 = text_in[1];
	x2 = text_in[2];
	x3 = text_in[3];

	for (i = 0; i < 8; i++) {
		mid = x1 ^ x2 ^ x3 ^ rk[4 * i];
		mid =  T_CHANGE(mid);
		x0 = x0 ^ L_CHANGE(mid);

		mid = x2 ^ x3 ^ x0 ^ rk[4 * i + 1];
		mid =  T_CHANGE(mid);

		x1 = x1 ^ L_CHANGE(mid);

		mid = x3 ^ x0 ^ x1 ^ rk[4 * i + 2];
		mid =  T_CHANGE(mid);
		x2 = x2 ^ L_CHANGE(mid);

		mid = x0 ^ x1 ^ x2 ^ rk[4 * i + 3];
		mid =  T_CHANGE(mid);
		x3 = x3 ^ L_CHANGE(mid);
	}

	text_out[0] = x3;
	text_out[1] = x2;
	text_out[2] = x1;
	text_out[3] = x0;
}

static inline void ECB_DE_MOD(u_int32_t  text_in[4], u_int32_t rk[32], u_int32_t text_out[4])
{
	int i;

	u_int32_t  x0, x1, x2, x3, mid;

	x0 = text_in[0];
	x1 = text_in[1];
	x2 = text_in[2];
	x3 = text_in[3];


	for (i = 0; i < 8; i++) {
		mid = x1 ^ x2 ^ x3 ^ rk[31 - 4 * i];
		mid =  T_CHANGE(mid);
		x0 = x0 ^ L_CHANGE(mid);



		mid = x2 ^ x3 ^ x0 ^ rk[30 - 4 * i];
		mid =  T_CHANGE(mid);

		x1 = x1 ^ L_CHANGE(mid);


		mid = x3 ^ x0 ^ x1 ^ rk[29 - 4 * i];
		mid =  T_CHANGE(mid);
		x2 = x2 ^ L_CHANGE(mid);


		mid = x0 ^ x1 ^ x2 ^ rk[28 - 4 * i];
		mid =  T_CHANGE(mid);
		x3 = x3 ^ L_CHANGE(mid);
	}

	text_out[0] = x3;
	text_out[1] = x2;
	text_out[2] = x1;
	text_out[3] = x0;
}

// CBC  ����ģʽ
// ���ⲿ�����
//  ain  ����
// ain_len ���ĳ���
//  key   ��չ���32����Կ
//  IV ��ʼIV
//  aout �������
void   CBC_EN_MOD(u_int32_t *ain, int ain_len, u_int32_t key[32], u_int32_t IV[4], u_int32_t  *aout)
{
	int i, j;
	u_int32_t aintemp[4];
//	u_int32_t IVtemp[4];
	u_int32_t *IVtemp;
	u_int32_t text_out[4];
	printf("CBC_EN_MOD key text:\n");
	sw_memdump((u_int8_t *)key, 128);

#if 0
	IVtemp[0] = IV[0];
	IVtemp[1] = IV[1];
	IVtemp[2] = IV[2];
	IVtemp[3] = IV[3];
#endif
	IVtemp = IV;

	for (i = 0; i < (ain_len / 4); i++) {
		for (j = 0; j < 4; j++)
			aintemp[j] = ain[4 * i + j] ^ IVtemp[j];
		ECB_EN_MOD(aintemp, key,  text_out);

		for (j = 0; j < 4; j++) {
			aout[4 * i + j] = text_out[j];
			IVtemp[j] = text_out[j];
		}
	}
}

// CBC ����ģʽ
// ���ⲿ�����
//  ain  ����
// ain_len ���ĳ���
//  key   ��չ���32����Կ
//  IV ��ʼIV
//  aout �������
static inline void CBC_DE_MOD(u_int32_t *ain, int ain_len, u_int32_t key[32], u_int32_t IV[4], u_int32_t  *aout)
{

	int i, j;
	u_int32_t aintemp[4];
//	u_int32_t IVtemp[4];
	u_int32_t *IVtemp;

	u_int32_t text_out[4];
	printf("CBC_DE_MOD key text:\n");
	sw_memdump((u_int8_t *)key, 128);

#if 0
	IVtemp[0] = IV[0];
	IVtemp[1] = IV[1];
	IVtemp[2] = IV[2];
	IVtemp[3] = IV[3];
#endif
	IVtemp = IV;
	for (i = 0; i < (ain_len / 4); i++) {
		for (j = 0; j < 4; j++)
			aintemp[j] = ain[4 * i + j];
		ECB_DE_MOD(aintemp, key, text_out);
		for (j = 0; j < 4; j++) {
			aout[4 * i + j] = text_out[j] ^ IVtemp[j];
			IVtemp[j] = aintemp[j];
		}
	}
}

vchar_t *sm4_cbc_crypt(u_int8_t *data, size_t data_len, u_int8_t *key, size_t key_len, u_int8_t *iv, int enc)
{
	u_int8_t RK[128];
	vchar_t *ret = NULL;
	u_int32_t key_tmp[4];

	if (data_len <= 0) {
		/*Todo: debug or log*/
		return NULL;
	}
	printf("sm4_cbc_crypt opt type %s\n", enc ? "encrypt": "decrypt");
	printf("plain text:\n");
	sw_memdump(data, data_len);


	printf("IV text:\n");
	sw_memdump(iv, 16);

	/*malloc buffer for result*/
	ret = vmalloc(data_len);
	if (ret == NULL) {
		return NULL;
	}
	printf("input key text:\n");
	sw_memdump(key, key_len);

    GET_UINT32_BE( key_tmp[0], key, 0 );
    GET_UINT32_BE( key_tmp[1], key, 4 );
    GET_UINT32_BE( key_tmp[2], key, 8 );
    GET_UINT32_BE( key_tmp[3], key, 12 );

	KEY_EXPAND((u_int32_t *)key_tmp, (u_int32_t *)RK);
	printf("expand key text:\n");
	sw_memdump(RK, 128);

	if (enc)  {
		u_int8_t dec[1024];
		/* encrypt */
		CBC_EN_MOD((u_int32_t *)data, data_len / 4, (u_int32_t *)RK, (u_int32_t *)iv, (u_int32_t *)ret->v);

		printf("---------------Add for compare-------------------\n");
		CBC_DE_MOD((u_int32_t *)ret->v, ret->l / 4, (u_int32_t *)RK, (u_int32_t *)iv, (u_int32_t *)dec);
		printf("test plain:\n");
		sw_memdump(dec, data_len);
	} else {
		/* decrypt */
		CBC_DE_MOD((u_int32_t *)data, data_len / 4, (u_int32_t *)RK, (u_int32_t *)iv, (u_int32_t *)ret->v);
	}
	printf("expand key text:\n");
	sw_memdump((u_int8_t *)ret->v, ret->l);

	return ret;

}

int sm4_weakkey(vchar_t *key)
{
	return 0;
}

int sm4_keylen(int len)
{
	if (len == 0) {
		return 128;
	}

	if (len != 128) {
		plog(LLV_ERROR, LOCATION, NULL, "%s: SM4 key size is not correct. %d\r\n", __FUNCTION__, len);
		return -1;   /**output log outside*/
	}

	return len;
}


vchar_t *sm4_cbc_encrypt(vchar_t *data, vchar_t *key, vchar_t *iv)
{
	return	sm4_cbc_crypt((u_int8_t *)data->v, data->l, (u_int8_t *)key->v, key->l, (u_int8_t *)iv->v, 1);
}

vchar_t *sm4_cbc_decrypt(vchar_t *cipher, vchar_t *key, vchar_t *iv)
{
	return sm4_cbc_crypt((u_int8_t *)cipher->v, cipher->l, (u_int8_t *)key->v, key->l, (u_int8_t *)iv->v, 0);
}

//SM4--end
