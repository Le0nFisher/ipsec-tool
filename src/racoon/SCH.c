#include "stdio.h"
#include <string.h>
#include "SCH.h"
#include "mytimer.h"
#include "parse.h"


void HOST_c2l(const unsigned char *c, unsigned int *l)
{
	*l  = (((unsigned int)(*((c)++))) << 24);		
	*l |= (((unsigned int)(*((c)++))) << 16);		
	*l |= (((unsigned int)(*((c)++))) << 8 );		
	*l |= (((unsigned int)(*((c)++)))      );
}

void HOST_p_c2l(const unsigned char *c, unsigned int *l, int n)
{					
	switch (n) 
	{					
		case 0: *l  = ((unsigned int)(*((c)++))) << 24;	
		case 1: *l |= ((unsigned int)(*((c)++))) << 16;	
		case 2: *l |= ((unsigned int)(*((c)++))) << 8;	
		case 3: *l |= ((unsigned int)(*((c)++)));		
	} 
}

void HOST_c2l_p(const unsigned char *c, unsigned int *l, int n)
{					
	*l = 0; 
	c += n;					
	switch (n) 
	{					\
		case 3: *l  = ((unsigned int)(*(--(c)))) << 8;	
		case 2: *l |= ((unsigned int)(*(--(c)))) << 16;	
		case 1: *l |= ((unsigned int)(*(--(c)))) << 24;	
	} 
}

void HOST_l2c(const unsigned int l, unsigned char *c)	
{
	*((c)++) = (unsigned char)(((l) >> 24)&0xff);	
    *((c)++) = (unsigned char)(((l) >> 16)&0xff);
    *((c)++) = (unsigned char)(((l) >>  8)&0xff);
    *((c)++) = (unsigned char)(((l)      )&0xff);
}

unsigned int FF(unsigned int A, unsigned int B, unsigned int C, int j)
{
	if(j < 16)
		return (A ^ B ^ C);
	else
		return ((A & B) | (A & C) | (B & C));
}

unsigned int GG(unsigned int E, unsigned int F, unsigned int G, int j)
{
	if(j < 16)
		return (E ^ F ^ G);
	else
		return ((E & F) | (~E & G));
}

unsigned int P0(unsigned int X)
{
	return (X ^ ((X << 9) | (X >> 23)) ^ ((X << 17) | (X >> 15)));
}

unsigned int P1_(unsigned int X)
{
	return (X ^ ((X << 15) | (X >> 17)) ^ ((X << 23) | (X >> 9)));
}

void SCH_BLOCK_HOST_ORDER(SCH_CTX *c, const void *d, int num)
{
	const unsigned int *W = d;
	unsigned int Wj[68], Wj_[64];
	unsigned int A, B, C, D, E, F, G, H;
	unsigned int Tj;
	unsigned int SS1, SS2, TT1, TT2;
	unsigned int T;
	int j;

	A = c->IV0;
	B = c->IV1;
	C = c->IV2;
	D = c->IV3;
	E = c->IV4;
	F = c->IV5;
	G = c->IV6;
	H = c->IV7;

	for (;;)
	{
		//消息扩展

		for(j = 0; j < 16; j++)
			Wj[j] = W[j];

		for(j = 16; j < 68; j++)
			Wj[j] = P1_(Wj[j - 16] ^ Wj[j - 9] ^ ((Wj[j - 3] << 15) | (Wj[j - 3] >> 17))) ^ ((Wj[j - 13] << 7) | (Wj[j - 13] >> 25)) ^ Wj[j - 6];

		for(j = 0; j < 64; j++)
			Wj_[j] = Wj[j] ^ Wj[j+4];
	
		//压缩主函数

		for(j = 0; j < 64; j++)
		{
			Tj = (j < 16) ? INIT_DATA_T0 : INIT_DATA_T1; 
			
			T = ((A << 12) | (A >> 20)) + E + ((Tj << (j & 0x1f)) | (Tj >> (32 - (j & 0x1f))));  
			SS1 = (T << 7) | (T >> 25);
			SS2 = SS1 ^ ((A << 12) | (A >> 20));
			TT1 = FF(A, B, C, j) + D + SS2 + Wj_[j];
			TT2 = GG(E, F, G, j) + H + SS1 + Wj[j];
			D = C;
			C = (B << 9) | (B >> 23);
			B = A;
			A = TT1;
			H = G;
			G = (F << 19) | (F >> 13);
			F = E;
			E = P0(TT2);
		}

		c->IV0 ^= A; 
		c->IV1 ^= B;
		c->IV2 ^= C;
		c->IV3 ^= D;
		c->IV4 ^= E;
		c->IV5 ^= F;
		c->IV6 ^= G;
		c->IV7 ^= H;

		if (--num <= 0) break;

		A = c->IV0;
		B = c->IV1;
		C = c->IV2;
		D = c->IV3;
		E = c->IV4;
		F = c->IV5;
		G = c->IV6;
		H = c->IV7;

		W += SCH_LBLOCK;
	}
}

void SCH_BLOCK_DATA_ORDER(SCH_CTX *c, const void *p, int num)
{
	const unsigned char *data = p;
	unsigned int l;
	unsigned int Wj[68], Wj_[64];
	unsigned int A, B, C, D, E, F, G, H;
	unsigned int Tj;
	unsigned int SS1, SS2, TT1, TT2;
	unsigned int T;
	int j;

	A = c->IV0;
	B = c->IV1;
	C = c->IV2;
	D = c->IV3;
	E = c->IV4;
	F = c->IV5;
	G = c->IV6;
	H = c->IV7;

	for (;;)
	{
		//消息扩展

		for(j = 0; j < 16; j++)
		{
			HOST_c2l(data, &l); data +=4;
			Wj[j] = l;
		}

		for(j = 16; j < 68; j++)
			Wj[j] = P1_(Wj[j - 16] ^ Wj[j - 9] ^ ((Wj[j - 3] << 15) | (Wj[j - 3] >> 17))) ^ ((Wj[j - 13] << 7) | (Wj[j - 13] >> 25)) ^ Wj[j - 6];

		for(j = 0; j < 64; j++)
			Wj_[j] = Wj[j] ^ Wj[j+4];
	
		//压缩主函数

		for(j = 0; j < 64; j++)
		{
			Tj = (j < 16) ? INIT_DATA_T0 : INIT_DATA_T1; 
			
			T = ((A << 12) | (A >> 20)) + E + ((Tj << (j & 0x1f)) | (Tj >> (32 - (j & 0x1f))));  
			SS1 = (T << 7) | (T >> 25);
			SS2 = SS1 ^ ((A << 12) | (A >> 20));
			TT1 = FF(A, B, C, j) + D + SS2 + Wj_[j];
			TT2 = GG(E, F, G, j) + H + SS1 + Wj[j];
			D = C;
			C = (B << 9) | (B >> 23);
			B = A;
			A = TT1;
			H = G;
			G = (F << 19) | (F >> 13);
			F = E;
			E = P0(TT2);
		}

		c->IV0 ^= A; 
		c->IV1 ^= B;
		c->IV2 ^= C;
		c->IV3 ^= D;
		c->IV4 ^= E;
		c->IV5 ^= F;
		c->IV6 ^= G;
		c->IV7 ^= H;

		if (--num <= 0) break;

		A = c->IV0;
		B = c->IV1;
		C = c->IV2;
		D = c->IV3;
		E = c->IV4;
		F = c->IV5;
		G = c->IV6;
		H = c->IV7;
	}
}

void SCH_Init(SCH_CTX *c)
{
	c->IV0 = INIT_DATA_IV0;
	c->IV1 = INIT_DATA_IV1;
	c->IV2 = INIT_DATA_IV2;
	c->IV3 = INIT_DATA_IV3;
	c->IV4 = INIT_DATA_IV4;
	c->IV5 = INIT_DATA_IV5;
	c->IV6 = INIT_DATA_IV6;
	c->IV7 = INIT_DATA_IV7;
	c->Nl = 0;
	c->Nh = 0;
	c->num = 0;
}

/*
void SCH_Update(SCH_CTX *c, const void *data_, int len)
{
	const unsigned char *data = data_;
	SCH_LONG *p;
	unsigned int l;
	int sw, / *sc,* / ew, ec;

	if (len == 0) return;

	l = (len << 3 ) & 0xffffffffL;
	c->Nh += (len >> 29);
	c->Nl = l;

	sw = len / SCH_CBLOCK;
	if (sw > 0)
	{
		SCH_BLOCK_DATA_ORDER(c, data, sw);
		sw *= SCH_CBLOCK;
		data += sw;
		len -= sw;
	}

	if (len != 0) 
	{
		p = c->data;
		c->num = len;
		ew = len >> 2;	/ * words to copy * /
		ec = len & 0x03;
		for (; ew; ew--,p++)
		{
			HOST_c2l(data, &l); data +=4; *p = l;
		}
		HOST_c2l_p(data, &l, ec);
		*p = l;
	}
	
	return;
}*/
void SCH_Update(SCH_CTX *c, const void *data_, int len)
{
	const unsigned char *data = (const unsigned char *)data_;
	SCH_LONG *p;
	unsigned int l;
	int sw, ew, ec;
	
	if (len == 0) return;
	
	l = (c->Nl + (len << 3)) & 0xffffffffL;
	if (l < c->Nl) 
		c->Nh++;
	c->Nh += (len >> 29);
	c->Nl = l;
	
	sw = len / SCH_CBLOCK;
	if (sw > 0)
	{
		SCH_BLOCK_DATA_ORDER(c, data, sw);
		sw *= SCH_CBLOCK;
		data += sw;
		len -= sw;
	}
	
	if (len != 0) 
	{
		p = c->data;
		c->num = len;
		ew = len >> 2;	/* words to copy */
		ec = len & 0x03;
		for (; ew; ew--,p++)
		{
			HOST_c2l(data, &l); data +=4; *p = l;
		}
		HOST_c2l_p(data, &l, ec);
		*p = l;
	}
	
	return;
}


void SCH_Final(unsigned char *md, SCH_CTX *c, int out_len)
{
	SCH_LONG *p;
	unsigned int l;
	int i, j;
	static const unsigned char end[4] = {0x80,0x00,0x00,0x00};
	const unsigned char *cp = end;
	unsigned int A, B, C, D, E, F, G, H;

	p = c->data;
	i = c->num >> 2;
	j = c->num & 0x03;

	l = (j==0) ? 0 : p[i];

	HOST_p_c2l(cp, &l, j); p[i++] = l; 

	if (i > (SCH_LBLOCK-2)) /* save room for Nl and Nh */
	{
		if (i < SCH_LBLOCK) p[i] = 0;
		SCH_BLOCK_HOST_ORDER(c, p, 1);
		i = 0;
	}

	for (; i< (SCH_LBLOCK - 2); i++)
		p[i] = 0;

	p[SCH_LBLOCK-2] = c->Nh;
	p[SCH_LBLOCK-1] = c->Nl;

	SCH_BLOCK_HOST_ORDER(c,p,1);

	A = c->IV0;
	B = c->IV1;
	C = c->IV2;
	D = c->IV3;
	E = c->IV4;
	F = c->IV5;
	G = c->IV6;
	H = c->IV7;

	if(out_len == SCH_256_FLAG)
	{
		HOST_l2c(A, md);
		HOST_l2c(B, md + 4);
		HOST_l2c(C, md + 8);
		HOST_l2c(D, md + 12);
		HOST_l2c(E, md + 16);
		HOST_l2c(F, md + 20);
		HOST_l2c(G, md + 24);
		HOST_l2c(H, md + 28);
	}
	else if(out_len == SCH_192_FLAG)
	{
		unsigned int y0, y1, y2, y3, y4, y5;
		
		y0 = A ^ B ^ E;
		y1 = B ^ F;
		y2 = C ^ G;
		y3 = D ^ H;
		y4 = F ^ C;
		y5 = D ^ G;
		HOST_l2c(y0, md);
		HOST_l2c(y1, md + 4);
		HOST_l2c(y2, md + 8);
		HOST_l2c(y3, md + 12);
		HOST_l2c(y4, md + 16);
		HOST_l2c(y5, md + 20);
	}
	else	//SCH_160_FLAG
	{
		unsigned int y0, y1, y2, y3, y4;
		
		y0 = A ^ B ^ E;
		y1 = B ^ F ^ C;
		y2 = C ^ G;
		y3 = D ^ H;
		y4 = D ^ G;
		HOST_l2c(y0, md);
		HOST_l2c(y1, md + 4);
		HOST_l2c(y2, md + 8);
		HOST_l2c(y3, md + 12);
		HOST_l2c(y4, md + 16);
	}
	
	c->num = 0;

	return;
}

void SCH_Final1(unsigned char *md, SCH_CTX *c, int out_len)
{
	unsigned int A, B, C, D, E, F, G, H;

	A = c->IV0;
	B = c->IV1;
	C = c->IV2;
	D = c->IV3;
	E = c->IV4;
	F = c->IV5;
	G = c->IV6;
	H = c->IV7;

	if(out_len == SCH_256_FLAG)
	{
		HOST_l2c(A, md);
		HOST_l2c(B, md + 4);
		HOST_l2c(C, md + 8);
		HOST_l2c(D, md + 12);
		HOST_l2c(E, md + 16);
		HOST_l2c(F, md + 20);
		HOST_l2c(G, md + 24);
		HOST_l2c(H, md + 28);
	}
	else if(out_len == SCH_192_FLAG)
	{
		unsigned int y0, y1, y2, y3, y4, y5;
		
		y0 = A ^ B ^ E;
		y1 = B ^ F;
		y2 = C ^ G;
		y3 = D ^ H;
		y4 = F ^ C;
		y5 = D ^ G;
		HOST_l2c(y0, md);
		HOST_l2c(y1, md + 4);
		HOST_l2c(y2, md + 8);
		HOST_l2c(y3, md + 12);
		HOST_l2c(y4, md + 16);
		HOST_l2c(y5, md + 20);
	}
	else	//SCH_160_FLAG 
	{
		unsigned int y0, y1, y2, y3, y4;
		
		y0 = A ^ B ^ E;
		y1 = B ^ F ^ C;
		y2 = C ^ G;
		y3 = D ^ H;
		y4 = D ^ G;
		HOST_l2c(y0, md);
		HOST_l2c(y1, md + 4);
		HOST_l2c(y2, md + 8);
		HOST_l2c(y3, md + 12);
		HOST_l2c(y4, md + 16);
	}
	
	c->num = 0;

	return;
}

void SCH(const unsigned char *d, int n, int out_len, unsigned char *md)
{
	SCH_CTX c;

	SCH_Init(&c);
	SCH_Update(&c, d, n);
	SCH_Final(md, &c, out_len);
}



void SM3_Test(param_t *param)
{
	unsigned char datain[256];
	unsigned char dataout[32];
	unsigned int TestSizeMbit = 1000;
	unsigned int j;
	struct timeval DiffTime,Start, Stop;
	
	printf("SM3 test success!\n");


	if(param->isSpeedTest == 1)
	{

		GetTimeTick(&Start);
		for(j=0;j<TestSizeMbit*512;j++)
		{
			SCH(datain,256,2,dataout);
		}
		GetTimeTick(&Stop);
		GetTimeDiff(&DiffTime, &Start, &Stop);

		//printf("%d MB sm3 encode take %ds %dus\n", (int)TestSizeMbit, DiffTime.tv_sec, DiffTime.tv_usec);
		//printf("SM3 speed: %f Mbit/s \n\n", (float)(TestSizeMbit/(float)((DiffTime.tv_sec*1000000 + DiffTime.tv_usec)/1000000)));

	}
}





// #pragma CODE_SECTION(ECC_UserID_HASH,".ext_text")
void ECC_UserID_HASH(unsigned short wEccBits,
					 unsigned char *pECCPara,
					 unsigned char *pECCPublicKey,
					 unsigned char *pUserID,
					 unsigned short wUserIDLen,
					 unsigned char *pbyHashData,
					 unsigned short *pwHashOutIDLen)
{
		unsigned short wbit_len;
		unsigned char byOutput[32];
		unsigned char buf[2 + 256 + 32 * 6];
		
		wbit_len = wUserIDLen * 8;
		buf[0] = wbit_len >> 8;
		buf[1] = (unsigned char)wbit_len;
		memcpy(&buf[2], pUserID, wUserIDLen);
		memcpy(&buf[2+wUserIDLen], pECCPara+wEccBits/8, wEccBits/8*4);
		memcpy(&buf[2+wUserIDLen+wEccBits/8*4], pECCPublicKey, wEccBits/8*2);
		SCH(buf, 2+wUserIDLen+wEccBits/8*6, SCH_256_FLAG, byOutput);
		memcpy(pbyHashData,byOutput,256/8);	
		*pwHashOutIDLen = 256/8;
}

