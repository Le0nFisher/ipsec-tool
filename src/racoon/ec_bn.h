#ifndef EC_BN_H
#define EC_BN_H

////////////////////////////////////////////////////////////////////////////////
#ifndef BN_ULONG
#define BN_ULONG	unsigned int
#endif

#define BIGNUM_SIZE	sizeof(BIGNUM_SM2)

#define ECC_MAX_BITS			256


#define ECC_MAX_BLOCK_LEN			((ECC_MAX_BITS+7)/8)	//ECC分组长度字节数 
#define ECC_MAX_BLOCK_LEN_DWORD		((ECC_MAX_BITS+31)/32)  //ECC分组长度双字数 

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
	BN_ULONG d[ECC_MAX_BLOCK_LEN_DWORD+2];	/* 在某些函数调用时有溢出(BN_uadd_sm2,BN_rshift_sm2) */
} BIGNUM_SM2;

//ECC芯片参数结构
typedef struct ECCParameter_st
{
    unsigned char p[ECC_MAX_BLOCK_LEN];		//模数p
	unsigned char a[ECC_MAX_BLOCK_LEN];		//参数a
	unsigned char b[ECC_MAX_BLOCK_LEN];		//参数b
	unsigned char Gx[ECC_MAX_BLOCK_LEN];	//G点的x坐标
	unsigned char Gy[ECC_MAX_BLOCK_LEN];	//G点的y坐标
	unsigned char Gn[ECC_MAX_BLOCK_LEN];	//G点的阶
} ECCParameter;

//ECC公钥结构
typedef struct 
{
	unsigned char Qx[ECC_MAX_BLOCK_LEN];		//Q点的x坐标
	unsigned char Qy[ECC_MAX_BLOCK_LEN];		//Q点的y坐标
} ECC_PUBLIC_KEY;

//ECC私钥结构
typedef struct 
{
	unsigned char Ka[ECC_MAX_BLOCK_LEN];		//私钥Ka
} ECC_PRIVATE_KEY;

//ECC签名值结构
typedef struct 
{
	unsigned char r[ECC_MAX_BLOCK_LEN];	
	unsigned char s[ECC_MAX_BLOCK_LEN];	
} ECC_SIGNATURE;

//ECC加密值结构
typedef struct 
{
	unsigned char C1[2*ECC_MAX_BLOCK_LEN];	
	unsigned char C2[ECC_MAX_BLOCK_LEN];  //和明文等长，最大是	ECC_MAX_BLOCK_LEN
	unsigned char C3[ECC_MAX_BLOCK_LEN];	

} ECC_ENCRYPTION;


#endif
