/*
 * sm3.c
 *
 *  Created on: 2015-9-19
 *      Author: lyyu (Liyang Yu)
 *	   Version: 1.0
 * Description:	xfrm(IPsec) sm3 algorithm source file for ike
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
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
#include "sm3.h"

//循环左移n位
#define t_shift(x,n) (((x) << (n))|((x)>>(32-(n))))
#define P0(x) t_shift((x),9)^t_shift((x),17)^(x)
#define P1(x)  t_shift((x),15)^ t_shift((x),23)^(x)
#define FF(x, y, z, j)  ( (j) < 16 ? ((x)^(y)^(z)) : (((x) & (y)) | ((x) & (z)) | ((y) & (z))) )
#define GG(x, y, z, j)  ( (j) < 16 ? ((x)^(y)^(z)) : (((x) & (y)) | ((~x) &(z))) )


#define CHAR_TO_UINT32(n, b, i)            \
	{                                         \
		(n) = ( (unsigned int) (b)[(i)    ] << 24 )   \
			  | ( (unsigned int) (b)[(i) + 1] << 16 )   \
			  | ( (unsigned int) (b)[(i) + 2] <<  8 )   \
			  | ( (unsigned int) (b)[(i) + 3]       );  \
	}


#define UINT32_TO_CHAR(n, b, i)          \
	{                                       \
		(b)[(i)    ] =  ( (n) >> 24 )&0xff;  \
		(b)[(i) + 1] =  ( (n) >> 16 )&0xff;  \
		(b)[(i) + 2] =  ( (n) >>  8 )&0xff;  \
		(b)[(i) + 3] =  ( (n)       )&0xff;  \
	}



#define ARRAY(aa,ain,i)\
	{ CHAR_TO_UINT32((aa)[ 0], (ain),  (i)*64);\
		CHAR_TO_UINT32((aa)[ 1], (ain),  (i)*64+4);\
		CHAR_TO_UINT32((aa)[ 2], (ain),  (i)*64+8);\
		CHAR_TO_UINT32((aa)[ 3], (ain),  (i)*64+12);\
		CHAR_TO_UINT32((aa)[ 4], (ain),  (i)*64+16);\
		CHAR_TO_UINT32((aa)[ 5], (ain), (i)*64+20);\
		CHAR_TO_UINT32((aa)[ 6], (ain), (i)*64+24);\
		CHAR_TO_UINT32((aa)[ 7], (ain), (i)*64+28);\
		CHAR_TO_UINT32((aa)[ 8], (ain), (i)*64+32);\
		CHAR_TO_UINT32((aa)[ 9], (ain), (i)*64+36);\
		CHAR_TO_UINT32((aa)[10], (ain), (i)*64+40);\
		CHAR_TO_UINT32((aa)[11], (ain), (i)*64+44);\
		CHAR_TO_UINT32((aa)[12], (ain), (i)*64+48);\
		CHAR_TO_UINT32((aa)[13], (ain), (i)*64+52);\
		CHAR_TO_UINT32((aa)[14], (ain), (i)*64+56);\
		CHAR_TO_UINT32((aa)[15], (ain), (i)*64+60);\
	}


#define LUN_FUN(a,b,c,d,e,f,g,h,a1,a2,i,ctx_t){\
		unsigned int ss1,ss2,tt1,tt2;\
		ss1 =t_shift(((t_shift((a),12)+(e)) +t_shift((ctx_t),(i))) ,7);\
		ss2 = ss1 ^t_shift((a),12);  \
		tt1 = FF( (a),(b), (c),(i))+(d)+ss2+(a2)[(i)];\
		tt2 = GG( (e),(f), (g),(i))+(h)+ss1+(a1)[(i)];\
		(d) = (c);\
		(c) = t_shift((b),9);\
		(b) =(a);\
		(a)= tt1;\
		(h) = (g);\
		(g) = t_shift((f),19);\
		(f) = (e);\
		(e) = P0(tt2);\
	}


#define message_expand(ain, a1out,a2out)\
	{\
		(a1out)[0] = (ain)[0];(a1out)[1] = (ain)[1];(a1out)[2] = (ain)[2];(a1out)[3] = (ain)[3];\
		(a1out)[4] = (ain)[4];(a1out)[5] = (ain)[5];(a1out)[6] = (ain)[6];(a1out)[7] = (ain)[7];\
		(a1out)[8] = (ain)[8];(a1out)[9] = (ain)[9];(a1out)[10] = (ain)[10];(a1out)[11] = (ain)[11];\
		(a1out)[12] = (ain)[12];(a1out)[13] = (ain)[13];(a1out)[14] = (ain)[14];(a1out)[15] = (ain)[15];\
		\
		(a1out)[16] =P1((a1out)[0]^(a1out)[7]^t_shift((a1out)[13],15)) ^ t_shift((a1out)[3],7) ^ (a1out)[10];\
		(a1out)[17] =P1((a1out)[1]^(a1out)[8]^t_shift((a1out)[14],15)) ^ t_shift((a1out)[4],7) ^ (a1out)[11];\
		(a1out)[18] =P1((a1out)[2]^(a1out)[9]^t_shift((a1out)[15],15)) ^ t_shift((a1out)[5],7) ^ (a1out)[12];\
		(a1out)[19] =P1((a1out)[3]^(a1out)[10]^t_shift((a1out)[16],15)) ^ t_shift((a1out)[6],7) ^ (a1out)[13];\
		(a1out)[20] =P1((a1out)[4]^(a1out)[11]^t_shift((a1out)[17],15)) ^ t_shift((a1out)[7],7) ^ (a1out)[14];\
		(a1out)[21] =P1((a1out)[5]^(a1out)[12]^t_shift((a1out)[18],15)) ^ t_shift((a1out)[8],7) ^ (a1out)[15];\
		(a1out)[22] =P1((a1out)[6]^(a1out)[13]^t_shift((a1out)[19],15)) ^ t_shift((a1out)[9],7) ^ (a1out)[16];\
		(a1out)[23] =P1((a1out)[7]^(a1out)[14]^t_shift((a1out)[20],15)) ^ t_shift((a1out)[10],7) ^ (a1out)[17];\
		(a1out)[24] =P1((a1out)[8]^(a1out)[15]^t_shift((a1out)[21],15)) ^ t_shift((a1out)[11],7) ^ (a1out)[18];\
		(a1out)[25] =P1((a1out)[9]^(a1out)[16]^t_shift((a1out)[22],15)) ^ t_shift((a1out)[12],7) ^ (a1out)[19];\
		(a1out)[26] =P1((a1out)[10]^(a1out)[17]^t_shift((a1out)[23],15)) ^ t_shift((a1out)[13],7) ^ (a1out)[20];\
		\
		(a1out)[27] =P1((a1out)[11]^(a1out)[18]^t_shift((a1out)[24],15)) ^ t_shift((a1out)[14],7) ^ (a1out)[21];\
		(a1out)[28] =P1((a1out)[12]^(a1out)[19]^t_shift((a1out)[25],15)) ^ t_shift((a1out)[15],7) ^ (a1out)[22];\
		(a1out)[29] =P1((a1out)[13]^(a1out)[20]^t_shift((a1out)[26],15)) ^ t_shift((a1out)[16],7) ^ (a1out)[23];\
		(a1out)[30] =P1((a1out)[14]^(a1out)[21]^t_shift((a1out)[27],15)) ^ t_shift((a1out)[17],7) ^ (a1out)[24];\
		(a1out)[31] =P1((a1out)[15]^(a1out)[22]^t_shift((a1out)[28],15)) ^ t_shift((a1out)[18],7) ^ (a1out)[25];\
		(a1out)[32] =P1((a1out)[16]^(a1out)[23]^t_shift((a1out)[29],15)) ^ t_shift((a1out)[19],7) ^ (a1out)[26];\
		(a1out)[33] =P1((a1out)[17]^(a1out)[24]^t_shift((a1out)[30],15)) ^ t_shift((a1out)[20],7) ^ (a1out)[27];\
		(a1out)[34] =P1((a1out)[18]^(a1out)[25]^t_shift((a1out)[31],15)) ^ t_shift((a1out)[21],7) ^ (a1out)[28];\
		(a1out)[35] =P1((a1out)[19]^(a1out)[26]^t_shift((a1out)[32],15)) ^ t_shift((a1out)[22],7) ^ (a1out)[29];\
		(a1out)[36] =P1((a1out)[20]^(a1out)[27]^t_shift((a1out)[33],15)) ^ t_shift((a1out)[23],7) ^ (a1out)[30];\
		\
		(a1out)[37] =P1((a1out)[21]^(a1out)[28]^t_shift((a1out)[34],15)) ^ t_shift((a1out)[24],7) ^ (a1out)[31];\
		(a1out)[38] =P1((a1out)[22]^(a1out)[29]^t_shift((a1out)[35],15)) ^ t_shift((a1out)[25],7) ^ (a1out)[32];\
		(a1out)[39] =P1((a1out)[23]^(a1out)[30]^t_shift((a1out)[36],15)) ^ t_shift((a1out)[26],7) ^ (a1out)[33];\
		(a1out)[40] =P1((a1out)[24]^(a1out)[31]^t_shift((a1out)[37],15)) ^ t_shift((a1out)[27],7) ^ (a1out)[34];\
		(a1out)[41] =P1((a1out)[25]^(a1out)[32]^t_shift((a1out)[38],15)) ^ t_shift((a1out)[28],7) ^ (a1out)[35];\
		(a1out)[42] =P1((a1out)[26]^(a1out)[33]^t_shift((a1out)[39],15)) ^ t_shift((a1out)[29],7) ^ (a1out)[36];\
		(a1out)[43] =P1((a1out)[27]^(a1out)[34]^t_shift((a1out)[40],15)) ^ t_shift((a1out)[30],7) ^ (a1out)[37];\
		(a1out)[44] =P1((a1out)[28]^(a1out)[35]^t_shift((a1out)[41],15)) ^ t_shift((a1out)[31],7) ^ (a1out)[38];\
		(a1out)[45] =P1((a1out)[29]^(a1out)[36]^t_shift((a1out)[42],15)) ^ t_shift((a1out)[32],7) ^ (a1out)[39];\
		(a1out)[46] =P1((a1out)[30]^(a1out)[37]^t_shift((a1out)[43],15)) ^ t_shift((a1out)[33],7) ^ (a1out)[40];\
		(a1out)[47] =P1((a1out)[31]^(a1out)[38]^t_shift((a1out)[44],15)) ^ t_shift((a1out)[34],7) ^ (a1out)[41];\
		(a1out)[48] =P1((a1out)[32]^(a1out)[39]^t_shift((a1out)[45],15)) ^ t_shift((a1out)[35],7) ^ (a1out)[42];\
		(a1out)[49] =P1((a1out)[33]^(a1out)[40]^t_shift((a1out)[46],15)) ^ t_shift((a1out)[36],7) ^ (a1out)[43];\
		(a1out)[50] =P1((a1out)[34]^(a1out)[41]^t_shift((a1out)[47],15)) ^ t_shift((a1out)[37],7) ^ (a1out)[44];\
		(a1out)[51] =P1((a1out)[35]^(a1out)[42]^t_shift((a1out)[48],15)) ^ t_shift((a1out)[38],7) ^ (a1out)[45];\
		(a1out)[52] =P1((a1out)[36]^(a1out)[43]^t_shift((a1out)[49],15)) ^ t_shift((a1out)[39],7) ^ (a1out)[46];\
		(a1out)[53] =P1((a1out)[37]^(a1out)[44]^t_shift((a1out)[50],15)) ^ t_shift((a1out)[40],7) ^ (a1out)[47];\
		\
		(a1out)[54] =P1((a1out)[38]^(a1out)[45]^t_shift((a1out)[51],15)) ^ t_shift((a1out)[41],7) ^ (a1out)[48];\
		(a1out)[55] =P1((a1out)[39]^(a1out)[46]^t_shift((a1out)[52],15)) ^ t_shift((a1out)[42],7) ^ (a1out)[49];\
		(a1out)[56] =P1((a1out)[40]^(a1out)[47]^t_shift((a1out)[53],15)) ^ t_shift((a1out)[43],7) ^ (a1out)[50];\
		(a1out)[57] =P1((a1out)[41]^(a1out)[48]^t_shift((a1out)[54],15)) ^ t_shift((a1out)[44],7) ^ (a1out)[51];\
		(a1out)[58] =P1((a1out)[42]^(a1out)[49]^t_shift((a1out)[55],15)) ^ t_shift((a1out)[45],7) ^ (a1out)[52];\
		(a1out)[59] =P1((a1out)[43]^(a1out)[50]^t_shift((a1out)[56],15)) ^ t_shift((a1out)[46],7) ^ (a1out)[53];\
		\
		(a1out)[60] =P1((a1out)[44]^(a1out)[51]^t_shift((a1out)[57],15)) ^ t_shift((a1out)[47],7) ^ (a1out)[54];\
		(a1out)[61] =P1((a1out)[45]^(a1out)[52]^t_shift((a1out)[58],15)) ^ t_shift((a1out)[48],7) ^ (a1out)[55];\
		(a1out)[62] =P1((a1out)[46]^(a1out)[53]^t_shift((a1out)[59],15)) ^ t_shift((a1out)[49],7) ^ (a1out)[56];\
		(a1out)[63] =P1((a1out)[47]^(a1out)[54]^t_shift((a1out)[60],15)) ^ t_shift((a1out)[50],7) ^ (a1out)[57];\
		(a1out)[64] =P1((a1out)[48]^(a1out)[55]^t_shift((a1out)[61],15)) ^ t_shift((a1out)[51],7) ^ (a1out)[58];\
		(a1out)[65] =P1((a1out)[49]^(a1out)[56]^t_shift((a1out)[62],15)) ^ t_shift((a1out)[52],7) ^ (a1out)[59];\
		(a1out)[66] =P1((a1out)[50]^(a1out)[57]^t_shift((a1out)[63],15)) ^ t_shift((a1out)[53],7) ^ (a1out)[60];\
		(a1out)[67] =P1((a1out)[51]^(a1out)[58]^t_shift((a1out)[64],15)) ^ t_shift((a1out)[54],7) ^ (a1out)[61];\
		\
		(a2out)[0] = (a1out)[0] ^(a1out)[4];(a2out)[1] = (a1out)[1] ^(a1out)[5];(a2out)[2] = (a1out)[2] ^(a1out)[6];(a2out)[3] = (a1out)[3] ^(a1out)[7];\
		(a2out)[4] = (a1out)[4] ^(a1out)[8];(a2out)[5] = (a1out)[5] ^(a1out)[9];(a2out)[6] = (a1out)[6] ^(a1out)[10];(a2out)[7] = (a1out)[7] ^(a1out)[11];\
		(a2out)[8] = (a1out)[8] ^(a1out)[12];(a2out)[9] = (a1out)[9] ^(a1out)[13];(a2out)[10] = (a1out)[10] ^(a1out)[14];(a2out)[11] = (a1out)[11] ^(a1out)[15];\
		(a2out)[12] = (a1out)[12] ^(a1out)[16];(a2out)[13] = (a1out)[13] ^(a1out)[17];(a2out)[14] = (a1out)[14] ^(a1out)[18];(a2out)[15] = (a1out)[15] ^(a1out)[19];\
		(a2out)[16] = (a1out)[16] ^(a1out)[20];(a2out)[17] = (a1out)[17] ^(a1out)[21];(a2out)[18] = (a1out)[18] ^(a1out)[22];(a2out)[19] = (a1out)[19] ^(a1out)[23];\
		(a2out)[20] = (a1out)[20] ^(a1out)[24];(a2out)[21] = (a1out)[21] ^(a1out)[25];(a2out)[22] = (a1out)[22] ^(a1out)[26];(a2out)[23] = (a1out)[23] ^(a1out)[27];\
		(a2out)[24] = (a1out)[24] ^(a1out)[28];(a2out)[25] = (a1out)[25] ^(a1out)[29];(a2out)[26] = (a1out)[26] ^(a1out)[30];(a2out)[27] = (a1out)[27] ^(a1out)[31];\
		(a2out)[28] = (a1out)[28] ^(a1out)[32];(a2out)[29] = (a1out)[29] ^(a1out)[33];(a2out)[30] = (a1out)[30] ^(a1out)[34];(a2out)[31] = (a1out)[31] ^(a1out)[35];\
		(a2out)[32] = (a1out)[32] ^(a1out)[36];(a2out)[33] = (a1out)[33] ^(a1out)[37];(a2out)[34] = (a1out)[34] ^(a1out)[38];(a2out)[35] = (a1out)[35] ^(a1out)[39];\
		(a2out)[36] = (a1out)[36] ^(a1out)[40];(a2out)[37] = (a1out)[37] ^(a1out)[41];(a2out)[38] = (a1out)[38] ^(a1out)[42];(a2out)[39] = (a1out)[39] ^(a1out)[43];\
		(a2out)[40] = (a1out)[40] ^(a1out)[44];(a2out)[41] = (a1out)[41] ^(a1out)[45];(a2out)[42] = (a1out)[42] ^(a1out)[46];(a2out)[43] = (a1out)[43] ^(a1out)[47];\
		(a2out)[44] = (a1out)[44] ^(a1out)[48];(a2out)[45] = (a1out)[45] ^(a1out)[49];(a2out)[46] = (a1out)[46] ^(a1out)[50];(a2out)[47] = (a1out)[47] ^(a1out)[51];\
		(a2out)[48] = (a1out)[48] ^(a1out)[52];(a2out)[49] = (a1out)[49] ^(a1out)[53];(a2out)[50] = (a1out)[50] ^(a1out)[54];(a2out)[51] = (a1out)[51] ^(a1out)[55];\
		(a2out)[52] = (a1out)[52] ^(a1out)[56];(a2out)[53] = (a1out)[53] ^(a1out)[57];(a2out)[54] = (a1out)[54] ^(a1out)[58];(a2out)[55] = (a1out)[55] ^(a1out)[59];\
		(a2out)[56] = (a1out)[56] ^(a1out)[60];(a2out)[57] = (a1out)[57] ^(a1out)[61];(a2out)[58] = (a1out)[58] ^(a1out)[62];(a2out)[59] = (a1out)[59] ^(a1out)[63];\
		(a2out)[60] = (a1out)[60] ^(a1out)[64];(a2out)[61] = (a1out)[61] ^(a1out)[65];(a2out)[62] = (a1out)[62] ^(a1out)[66];(a2out)[63] = (a1out)[63] ^(a1out)[67];\
	}

#define ARRAY_ARRAY(a,b)\
	{\
		(a)[0] =(b)[0];\
		(a)[1] =(b)[1];\
		(a)[2] =(b)[2];\
		(a)[3] =(b)[3];\
		(a)[4] =(b)[4];\
		(a)[5] =(b)[5];\
		(a)[6] =(b)[6];\
		(a)[7] =(b)[7]; \
	}

int sm3_hash_len()
{
	/**bit unit length*/
	return SM3_DIGEST_SIZE << 3;
}


vchar_t *sm3_digest_one(vchar_t *data)
{
	vchar_t *ret;

	if ((ret = vmalloc(SM3_DIGEST_SIZE * sizeof(char))) == 0) {
		return NULL;
	}
	sm3_hash((unsigned char *)data->v, data->l, (unsigned char *)ret->v);
	return ret;
}

char *sm3_init()
{
	int i;
	SM3_CTX *ctx = NULL;

	ctx = (SM3_CTX *)malloc(sizeof(SM3_CTX));;
	if (NULL == ctx) {
		return NULL;
	}

	ctx->LENGHT = 0;
	ctx->MIDLE_STATE[0] = 0x7380166f;
	ctx->MIDLE_STATE[1] = 0x4914b2b9;
	ctx->MIDLE_STATE[2] = 0x172442d7;
	ctx->MIDLE_STATE[3] = 0xda8a0600;
	ctx->MIDLE_STATE[4] = 0xa96f30bc;
	ctx->MIDLE_STATE[5] = 0x163138aa;
	ctx->MIDLE_STATE[6] = 0xe38dee4d;
	ctx->MIDLE_STATE[7] = 0xb0fb0e4e;
	for (i = 0 ; i < 64; i++) {
		if (i < 16) {
			ctx->CONSTANT_T[i] = 0x79cc4519;
		} else {
			ctx->CONSTANT_T[i] = 0x7a879d8a;
		}

		ctx->MEM[i] = 0x0;
	}

	return ((char *)ctx);
}


void CF_FUNCTION(SM3_CTX *ctx , unsigned int ain[16], unsigned int vin[8], unsigned int a1[68], unsigned int a2[64],  unsigned int aout[8])
{
	unsigned int a, b, c, d, e, f, g, h;
	unsigned int ctx_t;
	int i;
	a = vin[0];
	b = vin[1];
	c = vin[2];
	d = vin[3];
	e = vin[4];
	f = vin[5];
	g = vin[6];
	h = vin[7];
	for (i = 0; i < 64; i++) {
		ctx_t = ctx->CONSTANT_T[i];
		LUN_FUN(a, b, c, d, e, f, g, h, a1, a2, i, ctx_t);
	}
	aout[0] = a ^ vin[0];
	aout[1] = b ^ vin[1];
	aout[2] = c ^ vin[2];
	aout[3] = d ^ vin[3];
	aout[4] = e ^ vin[4];
	aout[5] = f ^ vin[5];
	aout[6] = g ^ vin[6];
	aout[7] = h ^ vin[7];
}

void sm3_operaat(SM3_CTX *ctx , unsigned int  aa[16])
{
	unsigned int a1out[68];
	unsigned int a2out[64];
	unsigned int vin[8];
	unsigned int acfout[8];

	ARRAY_ARRAY(vin, ctx->MIDLE_STATE);

	message_expand(aa, a1out, a2out);
	CF_FUNCTION(ctx, aa, vin, a1out, a2out, acfout);

	ctx->MIDLE_STATE[0] = acfout[0];
	ctx->MIDLE_STATE[1] = acfout[1];
	ctx->MIDLE_STATE[2] = acfout[2];
	ctx->MIDLE_STATE[3] = acfout[3];
	ctx->MIDLE_STATE[4] = acfout[4];
	ctx->MIDLE_STATE[5] = acfout[5];
	ctx->MIDLE_STATE[6] = acfout[6];
	ctx->MIDLE_STATE[7] = acfout[7];
}

void sm3_update(char *c, vchar_t *data)
{
	sm3_update_ex((SM3_CTX *)c,  (unsigned char *)data->v, data->l);
	return;
}

//modified by Tim
void sm3_update_ex(SM3_CTX *ctx , unsigned char * ain, int ain_len)
{
	int i;
	unsigned int  aa[16];
	int len_m = ctx->LENGHT % 64;
	int sum = (len_m + ain_len) / 64;

	ctx->LENGHT += ain_len;

	if (sum <= 0) {
		for (i = len_m; i < len_m + ain_len; i++)
			ctx->MEM[i] = ain[i - len_m];
	} else {
		if (len_m > 0) {
			for (i = len_m; i < 64; i++)
				ctx->MEM[i] = ain[i - len_m];
			ARRAY(aa, ctx->MEM, 0);
			sm3_operaat(ctx , aa);

			for (i = 0; i < sum - 1; i++) {
				ARRAY(aa, ain + 64 - len_m, i);
				sm3_operaat(ctx , aa);
			}

			memset(ctx->MEM, 0, 64);
		} else {
			for (i = 0; i < sum; i++) {
				ARRAY(aa, ain, i);
				sm3_operaat(ctx , aa);
			}
		}

		for (i = 0; i < ((len_m + ain_len) % 64); i++)
			ctx->MEM[i] = ain[ain_len - ((len_m + ain_len) % 64) + i];
	}
}

vchar_t * sm3_final(char *ctx)
{
	vchar_t *ret = NULL;

	ret = vmalloc(SM3_DIGEST_SIZE);
	if (NULL == ret) {
		return ret;
	}

	sm3_final_ex((SM3_CTX *)ctx,  (unsigned char *)ret->v);
	free((SM3_CTX *)ctx);

	return ret;
}

void sm3_final_ex(SM3_CTX *ctx, unsigned char aout[32])
{
	unsigned char atemp[64];
	unsigned char btemp[64];

	memset(btemp, 0, 64);
	memcpy(atemp, ctx->MEM, 64);

	unsigned int  aa[16];
	atemp[ctx->LENGHT % 64] = 0x80;
	if (((ctx->LENGHT % 64) < 56)) {
		ARRAY(aa, atemp, 0);
		aa[15] = (ctx->LENGHT) * 8;
		sm3_operaat(ctx , aa);

		UINT32_TO_CHAR(ctx->MIDLE_STATE[0], aout,  0);
		UINT32_TO_CHAR(ctx->MIDLE_STATE[1], aout,  4);
		UINT32_TO_CHAR(ctx->MIDLE_STATE[2], aout,  8);
		UINT32_TO_CHAR(ctx->MIDLE_STATE[3], aout, 12);
		UINT32_TO_CHAR(ctx->MIDLE_STATE[4], aout, 16);
		UINT32_TO_CHAR(ctx->MIDLE_STATE[5], aout, 20);
		UINT32_TO_CHAR(ctx->MIDLE_STATE[6], aout, 24);
		UINT32_TO_CHAR(ctx->MIDLE_STATE[7], aout, 28);
	} else {

		ARRAY(aa, atemp, 0);
		sm3_operaat(ctx , aa);
		ARRAY(aa, btemp, 0);
		aa[15] = (ctx->LENGHT) * 8;
		sm3_operaat(ctx , aa);
		UINT32_TO_CHAR(ctx->MIDLE_STATE[0], aout,  0);
		UINT32_TO_CHAR(ctx->MIDLE_STATE[1], aout,  4);
		UINT32_TO_CHAR(ctx->MIDLE_STATE[2], aout,  8);
		UINT32_TO_CHAR(ctx->MIDLE_STATE[3], aout, 12);
		UINT32_TO_CHAR(ctx->MIDLE_STATE[4], aout, 16);
		UINT32_TO_CHAR(ctx->MIDLE_STATE[5], aout, 20);
		UINT32_TO_CHAR(ctx->MIDLE_STATE[6], aout, 24);
		UINT32_TO_CHAR(ctx->MIDLE_STATE[7], aout, 28);
	}
}

void sm3_hash(unsigned char *ain, int len, unsigned char aout[32])
{
	SM3_CTX *ctx = NULL;

	ctx = (SM3_CTX *)sm3_init();
	if (NULL == ctx) {
		return;
	}

	sm3_update_ex(ctx , ain, len);
	sm3_final_ex(ctx, aout);

	free(ctx);
}


/*
 * SM3 HMAC context setup
 */
char *sm3_hmac_init_ex(unsigned char *key, int keylen)
{
	int i;
	unsigned char sum[32];
	SM3_CTX *ctx = NULL;

	ctx = (SM3_CTX *)sm3_init();
	if (NULL == ctx) {
		return NULL;
	}
	memset(ctx->IPAD, 0, HMAC_BUFER_SIZE);

	if (keylen > HMAC_BUFER_SIZE) {
		sm3_hash(key, keylen, sum);
		keylen = 32;
	} else {
		memcpy(ctx->IPAD, key, keylen);
	}
	memcpy(ctx->OPAD, ctx->IPAD, HMAC_BUFER_SIZE);
	for (i = 0; i < HMAC_BUFER_SIZE; i++) {
		ctx->IPAD[i] ^= HMAC_IPAD;
		ctx->OPAD[i] ^= HMAC_OPAD;
	}

	sm3_update_ex(ctx, ctx->IPAD, HMAC_BUFER_SIZE);

	return ((char *)ctx);
}


/*
 * SM3 HMAC process buffer
 */
void sm3_hmac_update_ex(SM3_CTX *ctx, unsigned char *input, int ilen)
{
	sm3_update_ex(ctx, input, ilen);
}

/*
 * SM3 HMAC final digest
 */
void sm3_hmac_final_ex(SM3_CTX *ctx, unsigned char output[32])
{
	int hlen;
	SM3_CTX *c = NULL;
	unsigned char tmpbuf[32];

	hlen =  32;

	sm3_final_ex(ctx, tmpbuf);
	c = (SM3_CTX *)sm3_init();
	if (NULL == c) {
		return;
	}

	sm3_update_ex(c, ctx->OPAD, 64);
	sm3_update_ex(c, tmpbuf, hlen);
	sm3_final_ex(c, output);
	free(ctx);
	free(c);
}


/*************************************************
  Function		: sm3_hmac
  Description	: SM3算法计算HMAC接口
  Input			: key 密钥值
  				  keylen 密钥长度
  				  input 计算HMAC数据流
  				  ilen
  Output		: N/A
  Return		: NULL 加密操作失败
  				  非空返回加密后数据指针
  Author		: Liyang Yu
  Others		: output = HMAC-SM3#( hmac key, input buffer )
  Date			: 2015/10/18
*************************************************/
void sm3_hmac(unsigned char *key, int keylen,
			  unsigned char *input, int ilen,
			  unsigned char output[32])
{
	SM3_CTX *ctx = NULL;

	ctx = (SM3_CTX *)sm3_hmac_init_ex(key, keylen);
	sm3_hmac_update_ex(ctx, input, ilen);
	sm3_hmac_final_ex(ctx, output);
}

char *sm3_hmac_init(vchar_t *key)
{
	return sm3_hmac_init_ex((unsigned char *)key->v, key->l);
}

void sm3_hmac_update(char *c, vchar_t *data)
{
	sm3_hmac_update_ex((SM3_CTX *)c, (unsigned char *)data->v, data->l);
}

vchar_t *sm3_hmac_final(char *c)
{
	vchar_t *ret = NULL;

	if ((ret = vmalloc(SM3_DIGEST_SIZE)) == 0) {
		return ret;
	}

	sm3_hmac_final_ex((SM3_CTX *)c, (unsigned char *)ret->v);

	return ret;
}


vchar_t *sm3_hmac_one(vchar_t *key, vchar_t *data)
{
	vchar_t *ret = NULL;

	ret = vmalloc(SM3_DIGEST_SIZE);
	if (NULL == ret) {
		return ret;
	}

	sm3_hmac((unsigned char *)key->v, key->l, (unsigned char *)data->v, data->l, (unsigned char *)ret->v);

	return ret;
}


