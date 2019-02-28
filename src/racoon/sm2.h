#ifndef _SM2_H_
#define _SM2_H_

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <sys/param.h>
#include <stdarg.h>

#include "config.h"

#include "var.h"
#include "misc.h"
#include "vmbuf.h"
#include "plog.h"
#include "sockmisc.h"
#include "debug.h"

#include "schedule.h"
#include "localconf.h"

#include "isakmp_var.h"
#include "isakmp.h"
#include "oakley.h"
#include "handler.h"
#include "evt.h"
#include "pfkey.h"
#include "ipsec_doi.h"
#include "admin.h"
#include "admin_var.h"
#include "isakmp_inf.h"

#include "ec_bn.h"
#include "ec_lcl.h"
#include "cert.h"
#include "SM2_DSA.h"
#include "ec_general.h"
#include "ec_bn.h"
#include "SM2_ES.h"
#include "var.h"
#include <openssl/opensslconf.h>

////////////////////////////////////////////////////////////////////////////////

#define BIGNUM_SIZE	sizeof(BIGNUM_SM2)


////////////////////////////////////////////////////////////////////////////////
extern unsigned char SM2_PARA_STR[14];

#define ECC_BITS		    256	                //ECC模长比特数 

#define RSA_MAX_OCTETS 1024

/* the EC_KEY stuff */
typedef struct ec_key_st EC_KEY;

int SM2_Encryption(unsigned char *e, size_t e_len, ECC_PUBLIC_KEY *pECCPK,ECC_ENCRYPTION *pEncryption);
int SM2_Decryption(ECC_ENCRYPTION *pEncryption, int c2_len , ECC_PRIVATE_KEY *pECCSK, unsigned char *e);

int SM2_Signature(unsigned char *e, size_t e_len, ECC_PRIVATE_KEY *pECCSK, ECC_SIGNATURE *pECCSign);


int SM2_Verification(unsigned char *e, size_t e_len, ECC_PUBLIC_KEY *pECCPK, ECC_SIGNATURE *pECCSign);
void SM2_GenerateKeyPair(ECC_PUBLIC_KEY *pECCPK, ECC_PRIVATE_KEY *pECCSK);


void ECC_GenerateKeyPair(EC_GROUP *group, ECC_PUBLIC_KEY *pECCPK, ECC_PRIVATE_KEY *pECCSK);

void Exchange_DWORD(unsigned char* arr,unsigned int len,int Flag);

bool get_privkey_from_sm2_key_file(const char *filename, ECC_PRIVATE_KEY *pECCSK);
bool get_pubkey_from_sm2_cert_file(const char *filename, ECC_PUBLIC_KEY *pECCPK);
void load_sm2_cert_key();

void sw_memdump(unsigned char * buf, unsigned int len);



//SM2_sign_setup
//int SM2_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM_SM2 **kinvp, BIGNUM_SM2 **rp);

//SM2 DH, comupting shared point
int SM2_DH_key(const EC_GROUP * group,const EC_POINT *b_pub_key_r, const EC_POINT *b_pub_key, const BIGNUM_SM2 *a_r,EC_KEY *a_eckey,
			   unsigned char *outkey,size_t keylen);

#endif

