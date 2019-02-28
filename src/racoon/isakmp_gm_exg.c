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

#include "schedule.h"
#include "localconf.h"
#include "remoteconf.h"
#include "grabmyaddr.h"
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

#include "handler.h"
#include "sm2.h"
#include "vmbuf.h"



#define SM2_SIG_SUCCESS		1
void plog(int pri, const char *func, struct sockaddr *sa, const char *fmt, ...);

struct ph1handle;

extern int g_ike_crypto_card;

vchar_t *eay_set_random(u_int32_t size);

int SM2_sign(const unsigned char *dgst, int dlen, unsigned char
			 *sig, unsigned int *siglen, EC_KEY *eckey);

int SM2_verify(const unsigned char *dgst, int dgst_len,
			   const unsigned char *sigbuf, int sig_len, EC_KEY *eckey);


/******************************************************************************
 * 功能:构造SK载荷Asymmetric_Encrypt(SKi,pub_r)或Asymmetric_Encrypt(SKr,pub_i);
 *
 *
 * 载荷格式:
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                             SK*                               ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 ******************************************************************************/

/*************************************************
 Function		: oakley_sk_payload_gen
 Description	: SK加密载荷生成函数，同时更新iph1结构的skl字段
 Input			: iph1 一阶段句柄
 Output			: N/A
 Return			: NULL	未生成SK
			  	  sk_pld 加密后的载荷
 Author			: Leon
 Date			: 2017/12/2
 Others			: N/A
*************************************************/
vchar_t *oakley_sk_payload_gen(struct ph1handle *iph1)
{
	int ret = 0;
	vchar_t *sk = NULL;
	vchar_t *sk_pld = NULL;
	u_int16_t sk_len = 0;
	ECC_ENCRYPTION encData;
	unsigned char sk_enc[sizeof(ECC_ENCRYPTION) + 1];    /**extra one byte for DER encode*/
	int pos;

	if (NULL == iph1->pubkey_p) {
		plog(LLV_ERROR, LOCATION, NULL, "%s: Has no public key\n", __FUNCTION__);
		return NULL;
	}

	/**Get SK length*/
	sk_len = alg_oakley_encdef_blocklen(iph1->approval->enctype);
	if (((sk_len % BITS_PER_BYTE) != 0)
		|| (sk_len > ECC_MAX_BLOCK_LEN)) {
		plog(LLV_ERROR, LOCATION, NULL, "%s: Invaild para sk_len %d pubkey %p \n",
			 __FUNCTION__, sk_len, iph1->pubkey_p);
		return NULL;
	}

	/**SK genearted randomly*/
	sk = eay_set_random((u_int32_t)sk_len);
	if (NULL == sk) return NULL;

	plogdumpf(LLV_INFO, sk->v, sk->l, "oakley_sk_payload_gen sk:");
	plogdumpf(LLV_INFO, ((ECC_PUBLIC_KEY *)iph1->pubkey_p->v)->Qx, ECC_MAX_BLOCK_LEN, "pubkey_p Qx gen:");
	plogdumpf(LLV_INFO, ((ECC_PUBLIC_KEY *)iph1->pubkey_p->v)->Qy, ECC_MAX_BLOCK_LEN, "pubkey_p Qy gen:");
	/**use SM2_Encrypt*/
	ret = SM2_Encryption((unsigned char *)sk->v, (int)sk->l, (ECC_PUBLIC_KEY *)iph1->pubkey_p->v, &encData);
	if (!ret) {
		plog(LLV_INFO, LOCATION, NULL, "IKE*:SM2 encryption failed in bulid and ship sk!\n");
        VPTRINIT(sk);
		return sk_pld;
	}

	/**Encode the encrypt data to DER format*/
	pos = 0;
	sk_enc[pos++] = 0x04;	//Begin with 0x04
	memcpy(sk_enc + pos, encData.C1, 2 * ECC_MAX_BLOCK_LEN);
	pos  += 2 * ECC_MAX_BLOCK_LEN;
	memcpy(sk_enc + pos, encData.C2, sk->l);
	pos += sk->l;
	memcpy(sk_enc + pos, encData.C3, ECC_MAX_BLOCK_LEN);
	pos += ECC_MAX_BLOCK_LEN;

	/**The under process generate the SK encrypt payload*/
	sk_pld = vmalloc(pos);
	if (NULL == sk_pld) {
		plog(LLV_ERROR, LOCATION, NULL, "failed to allocate sk buffer\n");
        VPTRINIT(sk);
		return sk_pld;
	}
	memcpy(sk_pld->v, sk_enc, sk_pld->l);

	plog(LLV_INFO, LOCATION, NULL, "sk payload encryption\n");
	plogdumpf(LLV_INFO, sk_pld->v, sk_pld->l, __func__);

	/**update iph1 sk*/
	iph1->skl = sk;  /**free iph1->skl in delph1()*/

	return sk_pld;
}

/*************************************************
 Function		: oakley_sk_payload_gen
 Description	: NONCE加密载荷生成函数，同时更新iph1结构的skl字段
 Input			: iph1 一阶段句柄
 Output			: N/A
 Return			: NULL	未生成SK
				  sk_pld 加密后的载荷
 Author			: Leon
 Date			: 2017/12/18
 Others			: N/A
*************************************************/
vchar_t *oakley_noce_de_gen(struct ph1handle *iph1)
{
	int pad_len = 0, blocklen = 0;
	vchar_t *nonce_pld = NULL;
	vchar_t *plaintext = NULL;
	//struct isakmp_gen *gen_hdr = NULL;

	/* 取得密钥(sk载荷体) */
	if (NULL == iph1->skl) {
		plog(LLV_ERROR, LOCATION, NULL, "%s : SK is NULL\n", __func__);
		return NULL;
	}

	/**set iv*/
	if (NULL == iph1->ivm) {
		/* allocate IVM */
		iph1->ivm = racoon_calloc(1, sizeof(struct isakmp_ivm));
		if (iph1->ivm == NULL) {
			plog(LLV_ERROR, LOCATION, NULL,	"failed to get iv buffer\n");
			return NULL;
		}

		iph1->ivm->iv = vmalloc(DEFAULT_NONCE_SIZE);
		iph1->ivm->ive = vmalloc(DEFAULT_NONCE_SIZE);
		if ((NULL == iph1->ivm->iv) || (NULL == iph1->ivm->ive)) {
			plog(LLV_ERROR, LOCATION, NULL, "%s : allocate iv (%p) or ivm (%p) failed\n",
				 __func__, iph1->ivm->iv,  iph1->ivm->ive);
			racoon_free(iph1->ivm);
			return NULL;
		}
	}

	memset(iph1->ivm->ive->v, 0, iph1->ivm->ive->l);
	memset(iph1->ivm->iv->v, 0, iph1->ivm->iv->l);

	/* 生成nonce值 */
	blocklen = alg_oakley_encdef_blocklen(iph1->approval->enctype);
	pad_len = blocklen - (DEFAULT_NONCE_SIZE % blocklen);
	plaintext = vmalloc(DEFAULT_NONCE_SIZE + pad_len);
	if (NULL == plaintext) {
		return NULL ;
	}

	iph1->nonce = eay_set_random((u_int32_t)DEFAULT_NONCE_SIZE);

    plog(LLV_INFO, LOCATION, NULL, "\n\n%s:Encrypt IV buffer ivl %lu\n", __FUNCTION__, iph1->ivm->ive->l);
    plogdumpf(LLV_INFO, iph1->ivm->ive->v, iph1->ivm->ive->l, __func__);

	/**Pad plaintext*/
	memcpy(plaintext->v, iph1->nonce->v, iph1->nonce->l);
	memset(plaintext->v + iph1->nonce->l, 0, pad_len - 1);
	plaintext->v[plaintext->l - 1] = pad_len - 1;

	plog(LLV_INFO, LOCATION, NULL, "\n%s:Encrypt NONCE plaintext len %lu\n", __FUNCTION__, plaintext->l);
	plogdumpf(LLV_INFO, plaintext->v, plaintext->l, __func__);

	/*Do encrypt and update IV */
	nonce_pld = oakley_do_encrypt_de(iph1, plaintext, iph1->ivm->ive, iph1->ivm->iv);

	plog(LLV_INFO, LOCATION, NULL, "\n%s:Encrypt text len %lu\n", __FUNCTION__, nonce_pld->l);
	if ((NULL != nonce_pld)) plogdumpf(LLV_INFO, nonce_pld->v, nonce_pld->l, __func__);

	VPTRINIT(plaintext);
	
    return nonce_pld;
}


vchar_t *oakley_id_de_gen(struct ph1handle *iph1)
{
	int pad_len = 0, blocklen = 0;			/**plaint data length*/
	vchar_t *id_pld = NULL;
	vchar_t *sk = iph1->skl, *plaintext = NULL;

	/* make ID payload */
	if ((NULL == sk) || (NULL == iph1->ivm)) {
		plog(LLV_INFO, LOCATION, NULL, "%s: sk = %p iph1->ivm %p\n", __func__, sk, iph1->ivm);
		return NULL;
	}

	if (ipsecdoi_setid1(iph1) < 0) {
		plog(LLV_INFO, LOCATION, NULL, "%s: set ID failed.\n", __func__);
		return NULL;
	}

	blocklen = alg_oakley_encdef_blocklen(iph1->approval->enctype);
	pad_len = blocklen - (iph1->id->l % blocklen);

	plaintext = vmalloc(iph1->id->l + pad_len);
	if (NULL == plaintext) {
		/*clear id when delph1()*/
		return NULL ;
	}

	plog(LLV_INFO, LOCATION, NULL,	"\n%s:Encrypt ID IV buffer len %lu", __FUNCTION__, iph1->ivm->ive->l);
	plogdumpf(LLV_INFO, iph1->ivm->ive->v, iph1->ivm->ive->l, __func__);

	memcpy(plaintext->v, iph1->id->v, iph1->id->l);
	memset(plaintext->v + iph1->id->l, 0, pad_len - 1);
	plaintext->v[plaintext->l - 1] = pad_len - 1;

	/* 加密并更新IV */
	plog(LLV_INFO, LOCATION, NULL, "\n%s:Encrypt ID plaintext  len %lu", __FUNCTION__, plaintext->l);
	plogdumpf(LLV_INFO, plaintext->v, plaintext->l, __func__);
	id_pld = oakley_do_encrypt_de(iph1, plaintext, iph1->ivm->ive, iph1->ivm->iv);

	if (id_pld) plogdumpf(LLV_INFO, id_pld->v, id_pld->l, __func__);
	VPTRINIT(plaintext);

	return id_pld;
}


vchar_t *oakley_cert_payload_gen(struct ph1handle *iph1)
{
	int pad_len = 0, blocklen = 0, cert_len = 0;
	vchar_t *cert_pld = NULL, *tmp = NULL;
	vchar_t *sk = iph1->skl, *plaintext = NULL;

	if ((NULL == sk) || (NULL == iph1->ivm) || (NULL == iph1->rmconf->mycert)) {
		plog(LLV_INFO, LOCATION, NULL, "%s: para is  NULL \n", __func__);
		return NULL;
	}

	cert_len = iph1->rmconf->mycert->l;
	tmp = iph1->rmconf->mycert;

	blocklen = alg_oakley_encdef_blocklen(iph1->approval->enctype);
	pad_len = blocklen - (cert_len % blocklen);

	plaintext = vmalloc(cert_len + pad_len);
	if (NULL == plaintext) {
		return NULL ;
	}

	memcpy(plaintext->v, tmp->v, tmp->l);
	memset(plaintext->v + tmp->l, 0, pad_len - 1);
	plaintext->v[plaintext->l - 1] = pad_len - 1;

	/* 加密并更新IV */
	plog(LLV_INFO, LOCATION, NULL, "\n\n%s:Encrypt IV buffer ivl %lu\n", __FUNCTION__, iph1->ivm->ive->l);
	plogdumpf(LLV_INFO, tmp->v, tmp->l, "oakley_cert_payload_gen: CERT content");
	cert_pld = oakley_do_encrypt_de(iph1, plaintext, iph1->ivm->ive, iph1->ivm->iv);

	if (cert_pld) plogdumpf(LLV_INFO, cert_pld->v, cert_pld->l, __func__);
	VPTRINIT(plaintext);

	return cert_pld;
}

/*************************************************
  Function		: hex2str
  Description	: 16进制转字符串
  Input			: src 输入的16进展数组
  				  len 数组长度
  Output		: dst 输出的16进制字符串
  Return		: N/A

  Author		: Leon
  Date			: 2017/12/18
  Others		: N/A
*************************************************/

void hex2str(char *dst, u_char *src, int len)
{
	unsigned char low, hig;
	int i;
	char tab[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',};
	for (i = 0; i < len; i++) {
		hig = (*(src + i) >> 4) & 0xf;
		low = *(src + i) & 0xf;
		if (hig <= 0xf)
			dst[i * 2] = tab[hig];
		if (low <= 0xf)
			dst[i * 2 + 1] = tab[low];
	}

	dst[len * 2] = '\0';
}

/* <IPSec VPN技术规范>5.1.2.1 SIGi_b=Asym_Sig(Hash(Ski_b|Ni_b|IDi_b[|CERT_b]),priv_i) */
vchar_t *oakley_sig_payload_gen(struct ph1handle *iph1)
{
	int sig_len;
	int enc_len = 0;			/**encrypt data length*/
	char *p = NULL;
	//u_char sig_val[RSA_MAX_OCTETS];
	vchar_t *tmp_hash = NULL;
	vchar_t *sig_pld = NULL;
	vchar_t *sig_hash = NULL;
	vchar_t *nonce = iph1->nonce;
	vchar_t *sk = iph1->skl;
	//EC_KEY *priv_key = NULL;

	if (!sk || !iph1->privkey_l || !nonce || !iph1->id) {
		plog(LLV_INFO, LOCATION, NULL, "%s: para is NULL \n", __func__);
		return NULL;
	}

	/**set the private key*/
	sig_pld = vmalloc(sizeof(ECC_SIGNATURE));
	if (NULL == sig_pld) {
		goto end;
	}

	//plogdumpf(LLV_INFO, iph1->privkey_l->v, iph1->privkey_l->l, "\noakley_sig_payload_gen: Signature Private Key");

	/**compute payload length*/
	if (iph1->rmconf->mycert &&  iph1->rmconf->send_cert && iph1->side == INITIATOR) {
		enc_len = sk->l + nonce->l + iph1->id->l + iph1->rmconf->mycert->l;
	} else {
		enc_len = sk->l + nonce->l + iph1->id->l;
	}

	/**alloc hash buffer*/
	tmp_hash = vmalloc(enc_len);
	if (NULL == tmp_hash) {
		plog(LLV_INFO, LOCATION, NULL, "%s: can not malloc temp hash. \n", __func__);
		goto end;
	}

	p = tmp_hash->v;
	memcpy(p, sk->v, sk->l);
	p += sk->l;
	plogdumpf(LLV_INFO, sk->v, sk->l, "\noakley_sig_payload_gen:  Hash SKI body");

	/**Add nonce field*/
	memcpy(p, nonce->v, nonce->l);
	p += nonce->l;
	plogdumpf(LLV_INFO, nonce->v, nonce->l, "\noakley_sig_payload_gen:  Hash NONCE body");

	/**Add ID field*/
	memcpy(p, iph1->id->v, iph1->id->l);
	p += iph1->id->l;
	plogdumpf(LLV_INFO, iph1->id->v, iph1->id->l, "\noakley_sig_payload_gen:  Hash ID body");

	if (iph1->rmconf->mycert != NULL && iph1->side == INITIATOR) {
		memcpy(p, iph1->rmconf->mycert->v, iph1->rmconf->mycert->l);
		p +=  iph1->rmconf->mycert->l;
	}

	/* make sig payload Hash(Ski_b|Ni_b|IDi_b[|CERT_b])*/
	sig_hash =  oakley_hash(tmp_hash, iph1);
	if (NULL == sig_hash) {
		plog(LLV_INFO, LOCATION, NULL, "%s:%d\n", __func__, __LINE__);
		goto end;
	}
	plogdumpf(LLV_INFO, sig_hash->v, sig_hash->l, "\noakley_sig_payload_gen: Signature Hash");


	/**if (SM2_SIG_SUCCESS != SM2_sign(sig_hash->v, sig_hash->l, sig_val, &sig_len,  priv_key)) {
		plog(LLV_INFO, LOCATION, NULL, "SM2 signature faileds.\n");
        goto end;
	}*/
	plogdumpf(LLV_INFO, sig_hash->v, sig_hash->l, "\noakley_sig_payload_gen: hash value\n");
	SM2_Signature((unsigned char *)sig_hash->v, sig_hash->l, (ECC_PRIVATE_KEY *)iph1->privkey_l->v, (ECC_SIGNATURE *)sig_pld->v);
	plogdumpf(LLV_INFO, sig_pld->v, sig_pld->l, "\noakley_sig_payload_gen: Signature Resualt\n");
	
	//memcpy(sig_pld->v,  sig_val, sig_len);
	iph1->sig = vdup(sig_pld);

end:
	//EC_KEY_free(priv_key);
	if(NULL != tmp_hash) VPTRINIT(tmp_hash);
	if(NULL != sig_hash) VPTRINIT(sig_hash);

	return sig_pld;
}
