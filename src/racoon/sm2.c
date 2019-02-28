#include <memory.h>
#include <limits.h>
#include <sys/stat.h>
#include <string.h>
#include "sm2.h"
#include "ec_bn.h"

void ECES_Test();

////////////////////////////////////////////////////////////////////////////////
#define DEBUG_SM2

////////////////////////////////////////////////////////////////////////////////


chunk_t sm_pubkey;
chunk_t sm_prtkey;
#define SM2_LOCAL_KEY_FILE "/tmp/cert/topsecca2_myself.pem.key"
#define SM2_PEER_CERT_FILE "/tmp/cert/topsecca2_myself.pem.cer" 
/**/
ECC_PUBLIC_KEY pub_test = {.Qx = {0x30, 0x31, 0x59, 0x95, 0x22, 0x99, 0xe6, 0x88,
								  0x31, 0xe1, 0xae, 0xf1, 0xb4, 0xa1, 0x7d, 0x9b,
								  0xd2, 0x73, 0x10, 0x95, 0xc2, 0xd7, 0x5b, 0x62,
								  0xb0, 0x91, 0xec, 0x72, 0xce, 0xe5, 0x76, 0x9a
								 },
						   .Qy = {0x92, 0x43, 0x20, 0x0e, 0x30, 0x31, 0xdf, 0xf0,
								  0xbb, 0x2c, 0x06, 0x59, 0xa2, 0xf5, 0x77, 0x80,
								  0x2f, 0xd1, 0xe1, 0x15, 0x67, 0x6c, 0xff, 0x15,
								  0xb6, 0x8f, 0xcc, 0x2d, 0x44, 0xcf, 0x3e, 0x25
								 }
						  };


ECC_PRIVATE_KEY priv_test = {.Ka = { 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
									 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
									 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
									 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a
								   }
							};



/**
 * SM2 standards http://www.oscca.gov.cn/News/201012/News_1197.htm
*/

#ifdef CONFIG_SUPPORT_CIPHER_CARD
//SM_PIPE_HANDLE      hPipe = NULL;
#endif

unsigned char SM2_ALG_FLAG[10] = {0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d};
unsigned char SM2_PARA_STR[14] = {0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0x03, 0x42, 0x00, 0x04};
unsigned char SM2_PRIVATE_PARA_STR[5] = {0x02, 0x01, 0x01, 0x04, 0x20};

void SM2_ECC_InitParameter(ECCParameter *pECCPara, EC_GROUP *group)
{
	//国密标准曲线
	unsigned char p_256[ECC_MAX_BLOCK_LEN] = {
	0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };

	unsigned char a_256[ECC_MAX_BLOCK_LEN] = {
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
    };

	unsigned char b_256[ECC_MAX_BLOCK_LEN] = {
    0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34,
    0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
    0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92,
    0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93
    };

	unsigned char Gx_256[ECC_MAX_BLOCK_LEN] = {
    0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19,
    0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
    0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1,
    0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7
    };

	unsigned char Gy_256[ECC_MAX_BLOCK_LEN] = {
    0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C,
    0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
    0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
    0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0
    };

	unsigned char Gn_256[ECC_MAX_BLOCK_LEN] = {
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x72, 0x03, 0xDF, 0x6B, 0x21, 0xC6, 0x05, 0x2B,
    0x53, 0xBB, 0xF4, 0x09, 0x39, 0xD5, 0x41, 0x23
    };
    int      ii;
    uint32_t u4_data;

	if (!pECCPara || !group)
    {
		return;
	}

	/*国密规范验证曲线初始化*/
	memcpy(pECCPara->p, p_256, ECC_MAX_BLOCK_LEN);
	memcpy(pECCPara->a, a_256, ECC_MAX_BLOCK_LEN);
	memcpy(pECCPara->b, b_256, ECC_MAX_BLOCK_LEN);
	memcpy(pECCPara->Gx, Gx_256, ECC_MAX_BLOCK_LEN);
	memcpy(pECCPara->Gy, Gy_256, ECC_MAX_BLOCK_LEN);
	memcpy(pECCPara->Gn, Gn_256, ECC_MAX_BLOCK_LEN);

	ECC_InitParameter(pECCPara, group, ECC_BITS);
}


int SM2_Encryption(unsigned char *e, size_t e_len, ECC_PUBLIC_KEY *pECCPK, ECC_ENCRYPTION *pEncryption)
{
	int ret = 0, j = 0;
	ECCParameter stECCPara;
	EC_GROUP group;
	int point_on_curve_flag = 0;
	//unsigned char rand_num[1024];
	
	//当输入的e_len 于ECC_MAX_BLOCK_LEN时,ECES_Encryption()中的字节序操作会导致越界,这里进行保护

	if (e_len > ECC_MAX_BLOCK_LEN) {
		return 0;
	}

	SM2_ECC_InitParameter(&stECCPara, &group);
	point_on_curve_flag = POINT_is_on_curve(&group, &stECCPara, pECCPK);

	if(point_on_curve_flag) {
		ret =  ECES_Encryption(&group, e, e_len, NULL, pECCPK, (unsigned char *)pEncryption);
		
		plogdumpf(LLV_INFO, pEncryption->C1, sizeof(pEncryption->C1), "encryption C1\n");
		plogdumpf(LLV_INFO, pEncryption->C2, sizeof(pEncryption->C2), "encryption C2\n");
		plogdumpf(LLV_INFO, pEncryption->C3, sizeof(pEncryption->C3), "encryption C3\n");
		return ret;
	}
	
	return ret;
}

// 1:success;0:failed
int  SM2_Decryption(ECC_ENCRYPTION *pEncryption, int c2_len , ECC_PRIVATE_KEY *pECCSK, unsigned char *e)
{
	ECCParameter stECCPara;
	EC_GROUP group;
	ECC_PUBLIC_KEY QQ;
	unsigned char t[ECC_MAX_BLOCK_LEN];
	int   point_on_curve_flag, hg;
	int i;

	SM2_ECC_InitParameter(&stECCPara, &group);
	printf("==========%s:%d==================\n", __FUNCTION__, __LINE__);	
	printf("%s:%d ECCParameter\n", __FUNCTION__, __LINE__);
	sw_memdump((unsigned char *)&stECCPara, sizeof(ECCParameter));
	printf("%s:%d EC_GROUP\n", __FUNCTION__, __LINE__);
	sw_memdump((unsigned char *)&group, sizeof(EC_GROUP));

	//  初始化C1,判断该点是否在曲线上
	memset(&QQ.Qx, 0, ECC_MAX_BLOCK_LEN);

	for (i = 0; i < ECC_MAX_BLOCK_LEN; i++) {
		t[i] = pEncryption->C1[i];
	}
	memcpy(&QQ.Qx, t, ECC_MAX_BLOCK_LEN);

	memset(&QQ.Qy , 0, ECC_MAX_BLOCK_LEN);

	for (i = 0; i < ECC_MAX_BLOCK_LEN; i++) {
		t[i] =  pEncryption->C1[32 + i];
	}

	memcpy(QQ.Qy, t, ECC_MAX_BLOCK_LEN);
        printf("%s:%d QQ\n", __FUNCTION__, __LINE__);
        sw_memdump((unsigned char *)&QQ, sizeof(ECC_PUBLIC_KEY));
	point_on_curve_flag = POINT_is_on_curve(&group, &stECCPara, &QQ);
	printf("%s:%d ECCParameter curve_flag %d\n", __FUNCTION__, __LINE__, point_on_curve_flag);

	if (point_on_curve_flag == 1) { // 点C1在曲线上
		hg = ECES_Decryption(&group, (unsigned char *)pEncryption, c2_len, pECCSK, e);
		if (hg == 1) { // 解密成功
			return 1;
		}
	}

	return 0;
}

int SM2_Signature(unsigned char *e, size_t e_len, ECC_PRIVATE_KEY *pECCSK, ECC_SIGNATURE *pECCSign)
{
	ECCParameter stECCPara;
	EC_GROUP group;

	SM2_ECC_InitParameter(&stECCPara, &group);

	ECDSA_Sig(&group, e, e_len, NULL, pECCSK, pECCSign);

	return 1;
}

int SM2_Verification(unsigned char *e, size_t e_len, ECC_PUBLIC_KEY *pECCPK, ECC_SIGNATURE *pECCSign)
{
	ECCParameter stECCPara;
	EC_GROUP group;

	SM2_ECC_InitParameter(&stECCPara, &group);

	return ECDSA_Verify(&group, e, e_len, pECCPK, pECCSign);
}

void SM2_GenerateKeyPair(ECC_PUBLIC_KEY *pECCPK, ECC_PRIVATE_KEY *pECCSK)
{
	ECCParameter stECCPara;
	EC_GROUP group;

	SM2_ECC_InitParameter(&stECCPara, &group);

	ECC_GenerateKeyPair(&group, pECCPK, pECCSK);
}

/*************************************************
  Function		: oakley_get_file_size
  Description	: 获取文件大小封装接口
  Input			: path 文件全路径
  Output		: N/A
  Return		: filesize 文件大小
  				  -1 文件状态错误

  Author		: Leon
  Date			: 2017/12/18
  Others		: N/A
*************************************************/
int oakley_get_file_size(const char *path)
{
	int  filesize = -1;
	struct stat statbuff;
	if (stat(path, &statbuff) < 0) {
		return filesize;
	} else {
		filesize = statbuff.st_size;
	}
	return filesize;
}

/*************************************************
  Function		: get_privkey_from_sm2_key_file
  Description	: 国密证书私钥获取函数
  Input			: filename	证书文件全路径
  Output		: pECCSK	获取的私钥
  Return		: TRUE	获取成功
  				  FALSE	获取失败
  Author		: Leon
  Date			: 2017/12/18
  Others		: N/A
*************************************************/
bool get_privkey_from_sm2_key_file(const char *filename, ECC_PRIVATE_KEY *pECCSK)
{
	int bytes = 0;
	err_t ugh;
	bool pgp;
	vchar_t *blob = NULL;

	bytes = oakley_get_file_size(filename);
	if (bytes <= 0)
		return FALSE;

	FILE *fd = fopen(filename, "r");
	if (NULL == fd)
		return FALSE;
	
	blob = vmalloc(bytes);
	if (NULL == blob) {
		/**Todo error debug*/
		fclose(fd);
		return FALSE;
	}

	bytes = fread(blob->v, 1, blob->l, fd);
	fclose(fd);

	pgp = FALSE;

	/* try DER format */
	if (is_asn1(blob)) {
		/**debug*/
		vfree(blob);
		return TRUE;
	}

	/* try PEM format */
	ugh = pemtobin(blob, NULL, filename, &pgp);
	if (ugh == NULL) {
		unsigned char *p_pos = NULL, *p_aa;
		unsigned int i;
		int key_valid = 0;


		for (i = 0; i < blob->l - sizeof(SM2_ALG_FLAG); i++) {
			if (!memcmp(blob->v + i, SM2_ALG_FLAG, sizeof(SM2_ALG_FLAG))) {
				key_valid = 1;
				break;
			}
		}

		if (!key_valid) {
			vfree(blob);
			return FALSE;
		}

		for (i = 0; i < blob->l - sizeof(SM2_PRIVATE_PARA_STR); i++) {
			if (!memcmp(blob->v + i, SM2_PRIVATE_PARA_STR, sizeof(SM2_PRIVATE_PARA_STR))) {
				p_pos = (unsigned char *)(blob->v + i);
				break;
			}
		}

		if (p_pos) {
			p_pos += sizeof(SM2_PRIVATE_PARA_STR);
			memcpy(pECCSK->Ka, p_pos, ECC_MAX_BLOCK_LEN);
			p_aa = (unsigned char*)(pECCSK);
			vfree(blob);
			return TRUE;
		}

		vfree(blob);
		return FALSE;
	} 
	
	vfree(blob);
	return FALSE;
}


/*************************************************
  Function		: get_pubkey_from_sm2_cert_file
  Description	: 国密证书公钥获取函数
  Input			: filename	证书文件全路径
  Output		: pECCPK	获取的公钥
  Return		: TRUE	获取成功
  				  FALSE	获取失败
  Author		: Leon
  Date			: 2017/12/18
  Others		: N/A
*************************************************/
bool get_pubkey_from_sm2_cert_file(const char *filename, ECC_PUBLIC_KEY *pECCPK)
{
	int bytes;
	err_t ugh;
	bool pgp;
	vchar_t *blob = NULL;

	bytes = oakley_get_file_size(filename);
	if (bytes <= 0)
		return FALSE;

	FILE *fd = fopen(filename, "r");
	if (NULL == fd)
		return FALSE;
	
	blob = vmalloc(bytes);
	if (NULL == blob) {
		/**Todo error debug*/
		fclose(fd);
		return FALSE;
	}

	bytes = fread(blob->v, 1, blob->l, fd);
	fclose(fd);

	pgp = FALSE;

	/* try DER format */
	if (is_asn1(blob)) {
		vfree(blob);
		return TRUE;
	}

	/* try PEM format */
	ugh = pemtobin(blob, NULL, filename, &pgp);
	if (ugh == NULL) {
		unsigned char *p_pos = NULL, *p_aa;
		int i;

		for (i = 0; i < blob->l - sizeof(SM2_PARA_STR); i++) {
			if (!memcmp(blob->v + i, SM2_PARA_STR, sizeof(SM2_PARA_STR))) {
				p_pos = (unsigned char *)(blob->v + i);
				break;
			}
		}

		if (p_pos) {
			p_pos += sizeof(SM2_PARA_STR);
			memcpy(pECCPK->Qx, p_pos, ECC_MAX_BLOCK_LEN);
			memcpy(pECCPK->Qy, p_pos + ECC_MAX_BLOCK_LEN, ECC_MAX_BLOCK_LEN);

			p_aa = (unsigned char*)(pECCPK);
			vfree(blob);
			return TRUE;
		}

		vfree(blob);
		return FALSE;
	}
		
	vfree(blob);
	return FALSE;
}


