#ifndef EC_BN_H
#define EC_BN_H

////////////////////////////////////////////////////////////////////////////////
#ifndef BN_ULONG
#define BN_ULONG	unsigned int
#endif

#define BIGNUM_SIZE	sizeof(BIGNUM_SM2)

#define ECC_MAX_BITS			256


#define ECC_MAX_BLOCK_LEN			((ECC_MAX_BITS+7)/8)	//ECC���鳤���ֽ��� 
#define ECC_MAX_BLOCK_LEN_DWORD		((ECC_MAX_BITS+31)/32)  //ECC���鳤��˫���� 

#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                     \
{                                                \
    (n) = ((uint32_t) (b)[(i)    ] << 24)        \
        | ((uint32_t) (b)[(i) + 1] << 16)        \
        | ((uint32_t) (b)[(i) + 2] <<  8)        \
        | ((uint32_t) (b)[(i) + 3]      );       \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                    \
{                                               \
    (b)[(i)    ] = (uint8_t) ((n) >> 24);       \
    (b)[(i) + 1] = (uint8_t) ((n) >> 16);       \
    (b)[(i) + 2] = (uint8_t) ((n) >>  8);       \
    (b)[(i) + 3] = (uint8_t) ((n)      );       \
}
#endif

typedef struct bignum_st_sm2
{
	BN_ULONG d[ECC_MAX_BLOCK_LEN_DWORD+2];	/* ��ĳЩ��������ʱ�����(BN_uadd_sm2,BN_rshift_sm2) */
} BIGNUM_SM2;

//ECCоƬ�����ṹ
typedef struct ECCParameter_st
{
    unsigned char p[ECC_MAX_BLOCK_LEN];		//ģ��p
	unsigned char a[ECC_MAX_BLOCK_LEN];		//����a
	unsigned char b[ECC_MAX_BLOCK_LEN];		//����b
	unsigned char Gx[ECC_MAX_BLOCK_LEN];	//G���x����
	unsigned char Gy[ECC_MAX_BLOCK_LEN];	//G���y����
	unsigned char Gn[ECC_MAX_BLOCK_LEN];	//G��Ľ�
} ECCParameter;

//ECC��Կ�ṹ
typedef struct 
{
	unsigned char Qx[ECC_MAX_BLOCK_LEN];		//Q���x����
	unsigned char Qy[ECC_MAX_BLOCK_LEN];		//Q���y����
} ECC_PUBLIC_KEY;

//ECC˽Կ�ṹ
typedef struct 
{
	unsigned char Ka[ECC_MAX_BLOCK_LEN];		//˽ԿKa
} ECC_PRIVATE_KEY;

//ECCǩ��ֵ�ṹ
typedef struct 
{
	unsigned char r[ECC_MAX_BLOCK_LEN];	
	unsigned char s[ECC_MAX_BLOCK_LEN];	
} ECC_SIGNATURE;

//ECC����ֵ�ṹ
typedef struct 
{
	unsigned char C1[2*ECC_MAX_BLOCK_LEN];	
	unsigned char C2[ECC_MAX_BLOCK_LEN];  //�����ĵȳ��������	ECC_MAX_BLOCK_LEN
	unsigned char C3[ECC_MAX_BLOCK_LEN];	

} ECC_ENCRYPTION;


#endif
