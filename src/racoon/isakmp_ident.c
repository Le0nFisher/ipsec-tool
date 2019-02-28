/*	$NetBSD: isakmp_ident.c,v 1.6 2006/10/02 21:41:59 manu Exp $	*/

/* Id: isakmp_ident.c,v 1.21 2006/04/06 16:46:08 manubsd Exp */

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* Identity Protecion Exchange (Main Mode) */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include "var.h"
#include "misc.h"
#include "vmbuf.h"
#include "plog.h"
#include "sockmisc.h"
#include "schedule.h"
#include "debug.h"

#include "localconf.h"
#include "remoteconf.h"
#include "isakmp_var.h"
#include "isakmp.h"
#include "evt.h"
#include "oakley.h"
#include "handler.h"
#include "ipsec_doi.h"
#include "crypto_openssl.h"
#include "pfkey.h"
#include "isakmp_ident.h"
#include "isakmp_inf.h"
#include "vendorid.h"

#ifdef ENABLE_NATT
#include "nattraversal.h"
#endif
#ifdef HAVE_GSSAPI
#include "gssapi.h"
#endif
#ifdef ENABLE_HYBRID
#include <resolv.h>
#include "isakmp_xauth.h"
#include "isakmp_cfg.h"
#endif
#ifdef ENABLE_FRAG 
#include "isakmp_frag.h"
#endif

static vchar_t *ident_ir2mx __P((struct ph1handle *));
static vchar_t *ident_ir3mx __P((struct ph1handle *));
static vchar_t *ident_ir2mx_de(struct ph1handle *iph1);
static int ident_ir2_phase_de(struct ph1handle *iph1, struct isakmp_parse_t *pbuf);

vchar_t *oakley_sk_payload_gen(struct ph1handle *iph1);
vchar_t *oakley_noce_de_gen(struct ph1handle *iph1);
vchar_t *oakley_id_de_gen(struct ph1handle *iph1);
vchar_t *oakley_cert_payload_gen(struct ph1handle *iph1);
vchar_t *oakley_sig_payload_gen(struct ph1handle *iph1);

#define SM2_SIG_SUCCESS		1

/* %%%
 * begin Identity Protection Mode as initiator.
 */
/*
 * send to responder
 * 	psk: HDR, SA
 * 	sig: HDR, SA
 * 	rsa: HDR, SA
 * 	rev: HDR, SA
 */
int ident_i1send(struct ph1handle *iph1, vchar_t *msg)
{
	struct payload_list *plist = NULL;
	int error = -1;
#ifdef ENABLE_NATT
	vchar_t *vid_natt[MAX_NATT_VID_COUNT] = { NULL };
	int i;
#endif
#ifdef ENABLE_HYBRID  
	vchar_t *vid_xauth = NULL;
	vchar_t *vid_unity = NULL;
#endif
#ifdef ENABLE_FRAG 
	vchar_t *vid_frag = NULL;
#endif 
#ifdef ENABLE_DPD
	vchar_t *vid_dpd = NULL;
#endif
	/* validity check */
	if (msg != NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"msg has to be NULL in this function.\n");
		goto end;
	}
	if (iph1->status != PHASE1ST_START) {
		plog(LLV_ERROR, LOCATION, NULL,
			"status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* create isakmp index */
	memset(&iph1->index, 0, sizeof(iph1->index));
	isakmp_newcookie((caddr_t)&iph1->index, iph1->remote, iph1->local);

	/* create SA payload for my proposal */
	iph1->sa = ipsecdoi_setph1proposal(iph1->rmconf->proposal);
	if (iph1->sa == NULL)
		goto end;

	/* set SA payload to propose */
	plist = isakmp_plist_append(plist, iph1->sa, ISAKMP_NPTYPE_SA);

#ifdef ENABLE_NATT
	/* set VID payload for NAT-T if NAT-T support allowed in the config file */
	if (iph1->rmconf->nat_traversal) 
		plist = isakmp_plist_append_natt_vids(plist, vid_natt);
#endif
#ifdef ENABLE_HYBRID
	/* Do we need Xauth VID? */
	switch (RMAUTHMETHOD(iph1)) {
	case FICTIVE_AUTH_METHOD_XAUTH_PSKEY_I:
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_RSA_I:
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_DSS_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSASIG_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_DSSSIG_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAENC_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAREV_I:
		if ((vid_xauth = set_vendorid(VENDORID_XAUTH)) == NULL)
			plog(LLV_ERROR, LOCATION, NULL,
			     "Xauth vendor ID generation failed\n");
		else
			plist = isakmp_plist_append(plist,
			    vid_xauth, ISAKMP_NPTYPE_VID);
			
		if ((vid_unity = set_vendorid(VENDORID_UNITY)) == NULL)
			plog(LLV_ERROR, LOCATION, NULL,
			     "Unity vendor ID generation failed\n");
		else
                	plist = isakmp_plist_append(plist,
			    vid_unity, ISAKMP_NPTYPE_VID);
		break;
	default:
		break;
	}
#endif
#ifdef ENABLE_FRAG
	if (iph1->rmconf->ike_frag) {
		if ((vid_frag = set_vendorid(VENDORID_FRAG)) == NULL) {
			plog(LLV_ERROR, LOCATION, NULL,
			    "Frag vendorID construction failed\n");
		} else {
			vid_frag = isakmp_frag_addcap(vid_frag,
			    VENDORID_FRAG_IDENT);
			plist = isakmp_plist_append(plist, 
			    vid_frag, ISAKMP_NPTYPE_VID);
		}
	}
#endif
#ifdef ENABLE_DPD
	if(iph1->rmconf->dpd){
		vid_dpd = set_vendorid(VENDORID_DPD);
		if (vid_dpd != NULL)
			plist = isakmp_plist_append(plist, vid_dpd,
			    ISAKMP_NPTYPE_VID);
	}
#endif

	iph1->sendbuf = isakmp_plist_set_all (&plist, iph1);

#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(iph1->sendbuf, iph1->local, iph1->remote, 0);
#endif

	/* send the packet, add to the schedule to resend */
	iph1->retry_counter = iph1->rmconf->retry_counter;
	if (isakmp_ph1resend(iph1) == -1)
		goto end;

	iph1->status = PHASE1ST_MSG1SENT;

	error = 0;

end:
#ifdef ENABLE_FRAG
	if (vid_frag) 
		vfree(vid_frag);
#endif  
#ifdef ENABLE_NATT
	for (i = 0; i < MAX_NATT_VID_COUNT && vid_natt[i] != NULL; i++)
		vfree(vid_natt[i]);
#endif
#ifdef ENABLE_HYBRID
	if (vid_xauth != NULL)
		vfree(vid_xauth);
	if (vid_unity != NULL)
		vfree(vid_unity);
#endif
#ifdef ENABLE_DPD
	if (vid_dpd != NULL)
		vfree(vid_dpd);
#endif

	return error;
}

/*
 * receive from responder
 * 	psk: HDR, SA
 * 	sig: HDR, SA
 * 	rsa: HDR, SA
 * 	rev: HDR, SA
 */
int
ident_i2recv(iph1, msg)
	struct ph1handle *iph1;
	vchar_t *msg;
{
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;
	vchar_t *satmp = NULL;
	int error = -1;
	int vid_numeric;

	/* validity check */
	if (iph1->status != PHASE1ST_MSG1SENT) {
		plog(LLV_ERROR, LOCATION, NULL,
			"status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* validate the type of next payload */
	/*
	 * NOTE: RedCreek(as responder) attaches N[responder-lifetime] here,
	 *	if proposal-lifetime > lifetime-redcreek-wants.
	 *	(see doi-08 4.5.4)
	 *	=> According to the seciton 4.6.3 in RFC 2407, This is illegal.
	 * NOTE: we do not really care about ordering of VID and N.
	 *	does it matters?
	 * NOTE: even if there's multiple VID/N, we'll ignore them.
	 */
	pbuf = isakmp_parse(msg);
	if (pbuf == NULL)
		goto end;
	pa = (struct isakmp_parse_t *)pbuf->v;

	/* SA payload is fixed postion */
	if (pa->type != ISAKMP_NPTYPE_SA) {
		plog(LLV_ERROR, LOCATION, iph1->remote,
			"received invalid next payload type %d, "
			"expecting %d.\n",
			pa->type, ISAKMP_NPTYPE_SA);
		goto end;
	}
	if (isakmp_p2ph(&satmp, pa->ptr) < 0)
		goto end;
	pa++;

	for (/*nothing*/;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {

		switch (pa->type) {
		case ISAKMP_NPTYPE_VID:
			vid_numeric = check_vendorid(pa->ptr);
#ifdef ENABLE_NATT
			if (iph1->rmconf->nat_traversal && natt_vendorid(vid_numeric))
			  natt_handle_vendorid(iph1, vid_numeric);
#endif
#ifdef ENABLE_HYBRID
			switch (vid_numeric) {
			case VENDORID_XAUTH:
				iph1->mode_cfg->flags |=
				    ISAKMP_CFG_VENDORID_XAUTH;
				break;
	
			case VENDORID_UNITY:
				iph1->mode_cfg->flags |=
				    ISAKMP_CFG_VENDORID_UNITY;
				break;
	
			default:
				break;
			}
#endif  
#ifdef ENABLE_DPD
			if (vid_numeric == VENDORID_DPD && iph1->rmconf->dpd)
				iph1->dpd_support=1;
#endif
			break;
		default:
			/* don't send information, see ident_r1recv() */
			plog(LLV_ERROR, LOCATION, iph1->remote,
				"ignore the packet, "
				"received unexpecting payload type %d.\n",
				pa->type);
			goto end;
		}
	}

#ifdef ENABLE_NATT
	if (NATT_AVAILABLE(iph1))
		plog(LLV_INFO, LOCATION, iph1->remote,
		     "Selected NAT-T version: %s\n",
		     vid_string_by_id(iph1->natt_options->version));
#endif

	/* check SA payload and set approval SA for use */
	if (ipsecdoi_checkph1proposal(satmp, iph1) < 0) {
		plog(LLV_ERROR, LOCATION, iph1->remote,
			"failed to get valid proposal.\n");
		/* XXX send information */
		goto end;
	}
	VPTRINIT(iph1->sa_ret);

	iph1->status = PHASE1ST_MSG2RECEIVED;

	error = 0;

end:
	if (pbuf)
		vfree(pbuf);
	if (satmp)
		vfree(satmp);
	return error;
}

/*
 * send to responder
 * 	psk: HDR, KE, Ni
 * 	sig: HDR, KE, Ni
 *   gssapi: HDR, KE, Ni, GSSi
 * 	rsa: HDR, KE, [ HASH(1), ] <IDi1_b>PubKey_r, <Ni_b>PubKey_r
 * 	rev: HDR, [ HASH(1), ] <Ni_b>Pubkey_r, <KE_b>Ke_i,
 * 	          <IDi1_b>Ke_i, [<<Cert-I_b>Ke_i]
 */
int
ident_i2send(struct ph1handle *iph1, vchar_t *msg)
{
	int error = -1;

	/* validity check */
	if (iph1->status != PHASE1ST_MSG2RECEIVED) {
		plog(LLV_ERROR, LOCATION, NULL,
			"status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* fix isakmp index */
	memcpy(&iph1->index.r_ck, &((struct isakmp *)msg->v)->r_ck,
		sizeof(cookie_t));
	
	if(OAKLEY_ATTR_AUTH_METHOD_SM_DE == AUTHMETHOD(iph1)){	
		iph1->sendbuf = ident_ir2mx_de(iph1);
		if (iph1->sendbuf == NULL){
			plog(LLV_ERROR, LOCATION, NULL,	"send buffer is null. auth mode de\n");
			goto end;
		}
	}else {
		/* generate DH public value */
		if (oakley_dh_generate(iph1->approval->dhgrp,
					&iph1->dhpub, &iph1->dhpriv) < 0)
			goto end;

		/* generate NONCE value */
		iph1->nonce = eay_set_random(iph1->rmconf->nonce_size);
		if (iph1->nonce == NULL)
			goto end;

#ifdef HAVE_GSSAPI
	if (AUTHMETHOD(iph1) == OAKLEY_ATTR_AUTH_METHOD_GSSAPI_KRB &&
	    gssapi_get_itoken(iph1, NULL) < 0)
		goto end;
#endif

		/* create buffer to send isakmp payload */
		iph1->sendbuf = ident_ir2mx(iph1);
		if (iph1->sendbuf == NULL)
			goto end;
	}
#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(iph1->sendbuf, iph1->local, iph1->remote, 0);
#endif

	/* send the packet, add to the schedule to resend */
	iph1->retry_counter = iph1->rmconf->retry_counter;
	if (isakmp_ph1resend(iph1) == -1)
		goto end;

	/* the sending message is added to the received-list. */
	if (add_recvdpkt(iph1->remote, iph1->local, iph1->sendbuf, msg) == -1) {
		plog(LLV_ERROR , LOCATION, NULL,
			"failed to add a response packet to the tree.\n");
		goto end;
	}

	iph1->status = PHASE1ST_MSG2SENT;

	error = 0;

end:
	return error;
}


/*************************************************
  Function		: ident_ir2mx_de
  Description	: 国密协商封包
  Input			: iph1 一阶段数据结构
  Output		: N/A
  Return		: NULL 获取随机数失败
  				  0 成功
  Author		: Leon
  Others		: N/A
  Date			: 2017/12/12
*************************************************/
static vchar_t *ident_ir2mx_de(struct ph1handle *iph1)
{
	vchar_t *buf = NULL;
	struct payload_list *plist = NULL;
	vchar_t *sk = NULL, *nonce = NULL, *id = NULL;
	vchar_t *cert = NULL, *sig	=NULL;
	int error = -1;

#ifdef ENABLE_NATT
	vchar_t *natd[2] = { NULL, NULL };
#endif
	sk = oakley_sk_payload_gen(iph1);	
	if(NULL == sk) {
		plog(LLV_ERROR, LOCATION, NULL, "%s sk is null\n", __func__);
		return NULL;
	}	


	/**donot exchange the order*/
	nonce = oakley_noce_de_gen(iph1);			/* create nonce payload and init the IV*/	
	id 	  = oakley_id_de_gen(iph1);
	sig   = oakley_sig_payload_gen(iph1);		/* create sig payload */	
	
	if(!sk || !nonce || !id || !sig){
		/*Todo free*/
		plog(LLV_ERROR, LOCATION, NULL, "%s id %p sig %p nonce %p\n", 
					__func__, id, sig, nonce);
		return NULL;
	}

	/**Responder need not send cert*/
	if(iph1->rmconf->mycert &&  iph1->rmconf->send_cert && iph1->side == INITIATOR) {
		cert = oakley_cert_payload_gen(iph1);
		if(NULL == cert){
			vfree(sk);	
			plog(LLV_INFO, LOCATION, NULL, "%s cert is null.\n", __func__);
			return cert;
		}
	}

	/* create isakmp SK(share key) payload */
	plist = isakmp_plist_append(plist, sk, ISAKMP_NPTYPE_SK);

	/* create nonce payload */
	plist = isakmp_plist_append(plist, nonce, ISAKMP_NPTYPE_NONCE);

	/* create id payload */	
	plist = isakmp_plist_append(plist, id, ISAKMP_NPTYPE_ID);

	if(NULL != cert){
		/* create certificate payload */	
		plist = isakmp_plist_append(plist, cert, ISAKMP_NPTYPE_CERT);
	}

	/* create sig payload */	
	plist = isakmp_plist_append(plist, sig, ISAKMP_NPTYPE_SIG);
	
#ifdef ENABLE_NATT
	/* generate and append NAT-D payloads */
	if (NATT_AVAILABLE(iph1) && iph1->status == PHASE1ST_MSG2RECEIVED)
	{
		if ((natd[0] = natt_hash_addr (iph1, iph1->remote)) == NULL) {
			plog(LLV_ERROR, LOCATION, NULL,
				"NAT-D hashing failed for %s\n", saddr2str(iph1->remote));
			goto end;
		}

		if ((natd[1] = natt_hash_addr (iph1, iph1->local)) == NULL) {
			plog(LLV_ERROR, LOCATION, NULL,
				"NAT-D hashing failed for %s\n", saddr2str(iph1->local));
			goto end;
		}

		plog (LLV_INFO, LOCATION, NULL, "Adding remote and local NAT-D payloads.\n");
		plist = isakmp_plist_append(plist, natd[0], iph1->natt_options->payload_nat_d);
		plist = isakmp_plist_append(plist, natd[1], iph1->natt_options->payload_nat_d);
	}
#endif

	buf = isakmp_plist_set_all (&plist, iph1);

	error = 0;

end:
	if (error && buf != NULL) {
		vfree(buf);
		buf = NULL;
	}

	sk == NULL ? sk = NULL : vfree(sk);
	sig == NULL ? sig = NULL : vfree(sig);
	cert == NULL ? cert = NULL : vfree(cert);
	nonce == NULL ? nonce = NULL : vfree(nonce);
	

#ifdef ENABLE_NATT
	if (natd[0])
		vfree(natd[0]);
	if (natd[1])
		vfree(natd[1]);
#endif

	return buf;
}

/*************************************************
  Function		: ident_ir2mx_de
  Description	: 国密协商接收方解析报文处理
  Input			: iph1 一阶段数据结构
  				: pbuf 协商报文
  Output		: N/A
  Return		: 0 成功
  				  
  Author		: Leon
  Others		: N/A
  Date			: 2017/12/12
*************************************************/
static int ident_ir2_phase_de(struct ph1handle *iph1, struct isakmp_parse_t *pbuf)
{
#ifdef ENABLE_NATT
	int natd_seq = 0;
#endif
	int error = -1;
	struct isakmp_parse_t *pa = NULL;
	vchar_t **sk = &iph1->skp;
	vchar_t **id = &iph1->id_p;
	vchar_t **nonce = &iph1->nonce_p;
	vchar_t *cert = &iph1->cert_p->cert;
	int enc_len = alg_oakley_encdef_blocklen(iph1->approval->enctype);

	/**set iv*/
	if(NULL != iph1->ivm){	
		oakley_delivm(iph1->ivm);
	}
	
	/* allocate IVm */
	iph1->ivm = racoon_calloc(1, sizeof(struct isakmp_ivm));
	if (iph1->ivm == NULL) {
		plog(LLV_ERROR, LOCATION, NULL, "%s: failed to alloc iv buffer\n", __FUNCTION__);
		return error;
	}

	iph1->ivm->iv = vmalloc(enc_len);
	iph1->ivm->ive = vmalloc(enc_len);
	if((NULL == iph1->ivm->iv ) || (NULL == iph1->ivm->ive)){
		/**debug*/
		if(NULL != iph1->ivm->iv )
			VPTRINIT(iph1->ivm->iv);
		if(NULL != iph1->ivm->ive)
			VPTRINIT(iph1->ivm->ive);
		racoon_free(iph1->ivm);
		iph1->ivm = NULL;
		return error;
	}
	
	/**Init IV */
	memset(iph1->ivm->ive->v, 0, iph1->ivm->ive->l);
	memset(iph1->ivm->iv->v, 0, iph1->ivm->iv->l);	
	
	for (pa = (struct isakmp_parse_t *)pbuf;
		pa->type != ISAKMP_NPTYPE_NONE;
		pa++)
	{
		struct isakmp_gen *gen = (struct isakmp_gen *)pa->ptr;

		switch (pa->type) {
			case ISAKMP_NPTYPE_SK:								
				if(isakmp_sk_p2ph(iph1, sk, gen) < 0) {
					plog(LLV_ERROR, LOCATION, iph1->remote, 
						"%s:%d Decrypt failed\n", __FUNCTION__, __LINE__);
					goto end;
				}
				
				if(*sk == NULL){
					plog(LLV_ERROR, LOCATION, iph1->remote, "get share key failed\n");
					goto end; 
				}
				/*iph1->key = *sk;  set key, sk payload must be the first, the follow field use it as key*/
				break;
				
			case ISAKMP_NPTYPE_ID:
				plog(LLV_INFO, LOCATION, iph1->remote, "ISAKMP_NPTYPE_ID\n");
				if(isakmp_dec_p2ph(iph1, id, gen) < 0){					
					plog(LLV_ERROR, LOCATION, iph1->remote, 
						"%s:%d Decrypt failed\n", __FUNCTION__, __LINE__);
					goto end;
				}
				break;
				
			case ISAKMP_NPTYPE_NONCE:		
				
				plog(LLV_INFO, LOCATION, iph1->remote, "ISAKMP_NPTYPE_NONCE\n");
				if(isakmp_dec_p2ph(iph1, nonce, gen) < 0) {
					plog(LLV_ERROR, LOCATION, iph1->remote, 
						"%s:%d Decrypt failed\n", __FUNCTION__, __LINE__);
					goto end;
				}			
				break;
				
			case ISAKMP_NPTYPE_CERT:			/**responder should not send cert at all*/						
				plog(LLV_INFO, LOCATION, iph1->remote, "ISAKMP_NPTYPE_CERT\n");
				if(isakmp_dec_p2ph(iph1,  &cert, gen) < 0) {
					plog(LLV_ERROR, LOCATION, iph1->remote, 
						"%s:%d Decrypt failed\n", __FUNCTION__, __LINE__);
					goto end;
				}
				break;

			case ISAKMP_NPTYPE_SIG:
				/**/if (TRUE != oakley_verify_de(iph1, *sk, *nonce, *id, NULL, gen)) {
					plog(LLV_ERROR, LOCATION, iph1->remote, 
											"%s:%d SM2 verify failed\n", __FUNCTION__, __LINE__);
					goto end;
				}
				break;
				
			case ISAKMP_NPTYPE_VID:
				plog(LLV_ERROR, LOCATION, iph1->remote, 
						"%s:%d handle_vendorid \n", __FUNCTION__, __LINE__);
				///handle_vendorid(iph1, gen); add by leon todo fix
				break;
				
			case ISAKMP_NPTYPE_CR:
				plog(LLV_WARNING, LOCATION, iph1->remote,
					"CR received, ignore it. "
					"It should be in other exchange.\n");
				break;				
#ifdef ENABLE_NATT
			case ISAKMP_NPTYPE_NATD_DRAFT:
			case ISAKMP_NPTYPE_NATD_RFC:
				if (NATT_AVAILABLE(iph1) && iph1->natt_options != NULL &&
					pa->type == iph1->natt_options->payload_nat_d)
				{
					vchar_t *natd_received = NULL;
					int natd_verified;

					if (isakmp_p2ph (&natd_received, gen) < 0)
						goto end;

					if (natd_seq == 0)
						iph1->natt_flags |= NAT_DETECTED;

					natd_verified = natt_compare_addr_hash (iph1,
						natd_received, natd_seq++);

					plog (LLV_INFO, LOCATION, NULL, "NAT-D payload #%d %s\n",
						natd_seq - 1,
						natd_verified ? "verified" : "doesn't match");

					vfree (natd_received);
					break;
				}
				/* passthrough to default... */
#endif				
			default:
				plog(LLV_ERROR, LOCATION, iph1->remote,	"ignore the packet, "
				"received unexpecting payload type %d.\n",	pa->type);
				goto end;
		}
	}

	error = 0;
end:
	if (error) {
		VPTRINIT(iph1->dhpub_p);
		VPTRINIT(iph1->nonce_p);
		VPTRINIT(iph1->id_p);
		oakley_delcert(iph1->cr_p);
	}

	return error;
}	

/*
 * receive from responder
 * 	psk: HDR, KE, Nr
 * 	sig: HDR, KE, Nr [, CR ]
 *   gssapi: HDR, KE, Nr, GSSr
 * 	rsa: HDR, KE, <IDr1_b>PubKey_i, <Nr_b>PubKey_i
 * 	rev: HDR, <Nr_b>PubKey_i, <KE_b>Ke_r, <IDr1_b>Ke_r,
 */
int
ident_i3recv(struct ph1handle *iph1, vchar_t *msg)
{
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;
	int error = -1;
#ifdef HAVE_GSSAPI
	vchar_t *gsstoken = NULL;
#endif
#ifdef ENABLE_NATT
	vchar_t	*natd_received;
	int natd_seq = 0, natd_verified;
#endif

	/* validity check */
	if (iph1->status != PHASE1ST_MSG2SENT) {
		plog(LLV_ERROR, LOCATION, NULL,
			"status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* validate the type of next payload */
	pbuf = isakmp_parse(msg);
	if (pbuf == NULL)
		goto end;

	if(OAKLEY_ATTR_AUTH_METHOD_SM_DE == AUTHMETHOD(iph1)) {
		if(ident_ir2_phase_de(iph1, (struct isakmp_parse_t *)pbuf->v) < 0) {
			/** Todo debug*/		
			goto end;
		}
	} else {	
		for (pa = (struct isakmp_parse_t *)pbuf->v;
		     pa->type != ISAKMP_NPTYPE_NONE;
		     pa++) {

		switch (pa->type) {
		case ISAKMP_NPTYPE_KE:
			if (isakmp_p2ph(&iph1->dhpub_p, pa->ptr) < 0)
				goto end;
			break;
		case ISAKMP_NPTYPE_NONCE:
			if (isakmp_p2ph(&iph1->nonce_p, pa->ptr) < 0)
				goto end;
			break;
		case ISAKMP_NPTYPE_VID:
			(void)check_vendorid(pa->ptr);
			break;
		case ISAKMP_NPTYPE_CR:
			if (oakley_savecr(iph1, pa->ptr) < 0)
				goto end;
			break;
#ifdef HAVE_GSSAPI
		case ISAKMP_NPTYPE_GSS:
			if (isakmp_p2ph(&gsstoken, pa->ptr) < 0)
				goto end;
			gssapi_save_received_token(iph1, gsstoken);
			break;
#endif

#ifdef ENABLE_NATT
		case ISAKMP_NPTYPE_NATD_DRAFT:
		case ISAKMP_NPTYPE_NATD_RFC:
			if (NATT_AVAILABLE(iph1) && iph1->natt_options != NULL &&
			    pa->type == iph1->natt_options->payload_nat_d) {
				natd_received = NULL;
				if (isakmp_p2ph (&natd_received, pa->ptr) < 0)
					goto end;
                        
				/* set both bits first so that we can clear them
				   upon verifying hashes */
				if (natd_seq == 0)
					iph1->natt_flags |= NAT_DETECTED;
                        
				/* this function will clear appropriate bits bits 
				   from iph1->natt_flags */
				natd_verified = natt_compare_addr_hash (iph1,
					natd_received, natd_seq++);
                        
				plog (LLV_INFO, LOCATION, NULL, "NAT-D payload #%d %s\n",
					natd_seq - 1,
					natd_verified ? "verified" : "doesn't match");
                        
				vfree (natd_received);
				break;
			}
			/* passthrough to default... */
#endif

		default:
			/* don't send information, see ident_r1recv() */
			plog(LLV_ERROR, LOCATION, iph1->remote,
				"ignore the packet, "
				"received unexpecting payload type %d.\n",
				pa->type);
			goto end;
			}
		}
	}

#ifdef ENABLE_NATT
	if (NATT_AVAILABLE(iph1)) {
		plog (LLV_INFO, LOCATION, NULL, "NAT %s %s%s\n",
		      iph1->natt_flags & NAT_DETECTED ? 
		      		"detected:" : "not detected",
		      iph1->natt_flags & NAT_DETECTED_ME ? "ME " : "",
		      iph1->natt_flags & NAT_DETECTED_PEER ? "PEER" : "");
		if (iph1->natt_flags & NAT_DETECTED)
			natt_float_ports (iph1);
	}
#endif
	if(iph1->approval->authmethod != OAKLEY_ATTR_AUTH_METHOD_SM_DE) {
		/* payload existency check */
		if (iph1->dhpub_p == NULL || iph1->nonce_p == NULL) {
			plog(LLV_ERROR, LOCATION, iph1->remote,
				"few isakmp message received.\n");
			goto end;
		}
	}
	if (oakley_checkcr(iph1) < 0) {
		/* Ignore this error in order to be interoperability. */
		;
	}

	iph1->status = PHASE1ST_MSG3RECEIVED;

	error = 0;

end:
#ifdef HAVE_GSSAPI
	if (gsstoken)
		vfree(gsstoken);
#endif
	if (pbuf)
		vfree(pbuf);
	if (error) {
		VPTRINIT(iph1->dhpub_p);
		VPTRINIT(iph1->nonce_p);
		VPTRINIT(iph1->id_p);
		oakley_delcert(iph1->cr_p);
		iph1->cr_p = NULL;
	}

	return error;
}

/*
 * send to responder
 * 	psk: HDR*, IDi1, HASH_I
 * 	sig: HDR*, IDi1, [ CR, ] [ CERT, ] SIG_I
 *   gssapi: HDR*, IDi1, < Gssi(n) | HASH_I >
 * 	rsa: HDR*, HASH_I
 * 	rev: HDR*, HASH_I
 */
int
ident_i3send(struct ph1handle *iph1, vchar_t *msg0)
{
	int error = -1;
	int dohash = 1;
#ifdef HAVE_GSSAPI
	int len;
#endif

	/* validity check */
	if (iph1->status != PHASE1ST_MSG3RECEIVED) {
		plog(LLV_ERROR, LOCATION, NULL,
			"status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* compute sharing secret of DH */
	if(OAKLEY_ATTR_AUTH_METHOD_SM_DE == AUTHMETHOD(iph1)) {
		plog(LLV_INFO, LOCATION, NULL,
			"---------------%s---compute IV and enc key.\n", __FUNCTION__);
		if (oakley_skeyid(iph1) < 0)
			goto end;
		if (oakley_skeyid_dae_de(iph1) < 0)
			goto end;
		if (oakley_compute_enckey(iph1) < 0)
			goto end;
		if (oakley_newiv_de(iph1) < 0)
			goto end;
	}else{
		if (oakley_dh_compute(iph1->approval->dhgrp, iph1->dhpub,
					iph1->dhpriv, iph1->dhpub_p, &iph1->dhgxy) < 0)
			goto end;

		/* generate SKEYIDs & IV & final cipher key */
		if (oakley_skeyid(iph1) < 0)
			goto end;
		if (oakley_skeyid_dae(iph1) < 0)
			goto end;
		if (oakley_compute_enckey(iph1) < 0)
			goto end;
		if (oakley_newiv(iph1) < 0)
			goto end;
	}
	
	/* make ID payload into isakmp status */
	if (ipsecdoi_setid1(iph1) < 0)
		goto end;

#ifdef HAVE_GSSAPI
	if (AUTHMETHOD(iph1) == OAKLEY_ATTR_AUTH_METHOD_GSSAPI_KRB &&
	    gssapi_more_tokens(iph1)) {
		plog(LLV_DEBUG, LOCATION, NULL, "calling get_itoken\n");
		if (gssapi_get_itoken(iph1, &len) < 0)
			goto end;
		if (len != 0)
			dohash = 0;
	}
#endif

	/* generate HASH to send */
	if (dohash) {
		iph1->hash = oakley_ph1hash_common(iph1, GENERATE);
		if (iph1->hash == NULL)
			goto end;
	} else
		iph1->hash = NULL;

	/* set encryption flag */
	iph1->flags |= ISAKMP_FLAG_E;

	/* create HDR;ID;HASH payload */
	iph1->sendbuf = ident_ir3mx(iph1);
	if (iph1->sendbuf == NULL)
		goto end;

	/* send the packet, add to the schedule to resend */
	iph1->retry_counter = iph1->rmconf->retry_counter;
	if (isakmp_ph1resend(iph1) == -1)
		goto end;

	/* the sending message is added to the received-list. */
	if (add_recvdpkt(iph1->remote, iph1->local, iph1->sendbuf, msg0) == -1) {
		plog(LLV_ERROR , LOCATION, NULL,
			"failed to add a response packet to the tree.\n");
		goto end;
	}

	/* see handler.h about IV synchronization. */
	memcpy(iph1->ivm->ive->v, iph1->ivm->iv->v, iph1->ivm->iv->l);

	iph1->status = PHASE1ST_MSG3SENT;

	error = 0;

end:
	return error;
}

/*
 * receive from responder
 * 	psk: HDR*, IDr1, HASH_R
 * 	sig: HDR*, IDr1, [ CERT, ] SIG_R
 *   gssapi: HDR*, IDr1, < GSSr(n) | HASH_R >
 * 	rsa: HDR*, HASH_R
 * 	rev: HDR*, HASH_R
 */
int
ident_i4recv(struct ph1handle *iph1, vchar_t *msg0)
{
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;
	vchar_t *msg = NULL;
	int error = -1;
	int type;
#ifdef HAVE_GSSAPI
	vchar_t *gsstoken = NULL;
#endif

	/* validity check */
	if (iph1->status != PHASE1ST_MSG3SENT) {
		plog(LLV_ERROR, LOCATION, NULL,
			"status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* decrypting */
	if (!ISSET(((struct isakmp *)msg0->v)->flags, ISAKMP_FLAG_E)) {
		plog(LLV_ERROR, LOCATION, iph1->remote,
			"ignore the packet, "
			"expecting the packet encrypted.\n");
		goto end;
	}
	msg = oakley_do_decrypt(iph1, msg0, iph1->ivm->iv, iph1->ivm->ive);
	if (msg == NULL)
		goto end;

	/* validate the type of next payload */
	pbuf = isakmp_parse(msg);
	if (pbuf == NULL)
		goto end;

	iph1->pl_hash = NULL;

	for (pa = (struct isakmp_parse_t *)pbuf->v;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {

		switch (pa->type) {
		case ISAKMP_NPTYPE_ID:
			if (isakmp_p2ph(&iph1->id_p, pa->ptr) < 0)
				goto end;
			break;
		case ISAKMP_NPTYPE_HASH:
			iph1->pl_hash = (struct isakmp_pl_hash *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_CERT:
			if (oakley_savecert(iph1, pa->ptr) < 0)
				goto end;
			break;
		case ISAKMP_NPTYPE_SIG:
			if (isakmp_p2ph(&iph1->sig_p, pa->ptr) < 0)
				goto end;
			break;
#ifdef HAVE_GSSAPI
		case ISAKMP_NPTYPE_GSS:
			if (isakmp_p2ph(&gsstoken, pa->ptr) < 0)
				goto end;
			gssapi_save_received_token(iph1, gsstoken);
			break;
#endif
		case ISAKMP_NPTYPE_VID:
			(void)check_vendorid(pa->ptr);
			break;
		case ISAKMP_NPTYPE_N:
			isakmp_check_notify(pa->ptr, iph1);
			break;
		default:
			/* don't send information, see ident_r1recv() */
			plog(LLV_ERROR, LOCATION, iph1->remote,
				"ignore the packet, "
				"received unexpecting payload type %d.\n",
				pa->type);
			goto end;
		}
	}

	/* payload existency check */

	/* verify identifier */
	if (ipsecdoi_checkid1(iph1) != 0) {
		plog(LLV_ERROR, LOCATION, iph1->remote,
			"invalid ID payload.\n");
		goto end;
	}

	/* validate authentication value */
#ifdef HAVE_GSSAPI
	if (gsstoken == NULL) {
#endif
		type = oakley_validate_auth(iph1);
		if (type != 0) {
			if (type == -1) {
				/* msg printed inner oakley_validate_auth() */
				goto end;
			}
			EVT_PUSH(iph1->local, iph1->remote, 
			    EVTT_PEERPH1AUTH_FAILED, NULL);
			isakmp_info_send_n1(iph1, type, NULL);
			goto end;
		}
#ifdef HAVE_GSSAPI
	}
#endif

	/*
	 * XXX: Should we do compare two addresses, ph1handle's and ID
	 * payload's.
	 */

	plog(LLV_DEBUG, LOCATION, iph1->remote, "peer's ID:");
	plogdump(LLV_DEBUG, iph1->id_p->v, iph1->id_p->l);

	/* see handler.h about IV synchronization. */
	memcpy(iph1->ivm->iv->v, iph1->ivm->ive->v, iph1->ivm->ive->l);

	/*
	 * If we got a GSS token, we need to this roundtrip again.
	 */
#ifdef HAVE_GSSAPI
	iph1->status = gsstoken != 0 ? PHASE1ST_MSG3RECEIVED : 
	    PHASE1ST_MSG4RECEIVED;
#else
	iph1->status = PHASE1ST_MSG4RECEIVED;
#endif

	error = 0;

end:
	if (pbuf)
		vfree(pbuf);
	if (msg)
		vfree(msg);
#ifdef HAVE_GSSAPI
	if (gsstoken)
		vfree(gsstoken);
#endif

	if (error) {
		VPTRINIT(iph1->id_p);
		oakley_delcert(iph1->cert_p);
		iph1->cert_p = NULL;
		oakley_delcert(iph1->crl_p);
		iph1->crl_p = NULL;
		VPTRINIT(iph1->sig_p);
	}

	return error;
}

/*
 * status update and establish isakmp sa.
 */
int
ident_i4send(struct ph1handle *iph1, vchar_t *msg)
{
	int error = -1;

	/* validity check */
	if (iph1->status != PHASE1ST_MSG4RECEIVED) {
		plog(LLV_ERROR, LOCATION, NULL,
			"status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* see handler.h about IV synchronization. */
	memcpy(iph1->ivm->iv->v, iph1->ivm->ive->v, iph1->ivm->iv->l);

	iph1->status = PHASE1ST_ESTABLISHED;

	error = 0;

end:
	return error;
}

/*
 * receive from initiator
 * 	psk: HDR, SA
 * 	sig: HDR, SA
 * 	rsa: HDR, SA
 * 	rev: HDR, SA
 */
int
ident_r1recv(struct ph1handle *iph1, vchar_t *msg)
{
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;
	int error = -1;
	int vid_numeric;

	/* validity check */
	if (iph1->status != PHASE1ST_START) {
		plog(LLV_ERROR, LOCATION, NULL,
			"status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* validate the type of next payload */
	/*
	 * NOTE: XXX even if multiple VID, we'll silently ignore those.
	 */
	pbuf = isakmp_parse(msg);
	if (pbuf == NULL){
		goto end;
	}
	pa = (struct isakmp_parse_t *)pbuf->v;

	/* check the position of SA payload */
	if (pa->type != ISAKMP_NPTYPE_SA) {
		plog(LLV_ERROR, LOCATION, iph1->remote,
			"received invalid next payload type %d, "
			"expecting %d.\n",
			pa->type, ISAKMP_NPTYPE_SA);
		goto end;
	}
	if (isakmp_p2ph(&iph1->sa, pa->ptr) < 0)
		goto end;
	pa++;

	for (/*nothing*/;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {

		switch (pa->type) {
		case ISAKMP_NPTYPE_VID:
			vid_numeric = check_vendorid(pa->ptr);
#ifdef ENABLE_NATT
			if (iph1->rmconf->nat_traversal && natt_vendorid(vid_numeric))
				natt_handle_vendorid(iph1, vid_numeric);
#endif
#ifdef ENABLE_FRAG
			if ((vid_numeric == VENDORID_FRAG) &&
			    (vendorid_frag_cap(pa->ptr) & VENDORID_FRAG_IDENT))
				iph1->frag = 1;
#endif   
#ifdef ENABLE_HYBRID
			switch (vid_numeric) {
			case VENDORID_XAUTH:
				iph1->mode_cfg->flags |=
				    ISAKMP_CFG_VENDORID_XAUTH;
				break;
		
			case VENDORID_UNITY:
				iph1->mode_cfg->flags |=
				    ISAKMP_CFG_VENDORID_UNITY;
				break;
	
			default:  
				break;
			}
#endif
#ifdef ENABLE_DPD
			if (vid_numeric == VENDORID_DPD && iph1->rmconf->dpd)
				iph1->dpd_support=1;
#endif
			break;
		default:
			/*
			 * We don't send information to the peer even
			 * if we received malformed packet.  Because we
			 * can't distinguish the malformed packet and
			 * the re-sent packet.  And we do same behavior
			 * when we expect encrypted packet.
			 */
			plog(LLV_ERROR, LOCATION, iph1->remote,
				"ignore the packet, "
				"received unexpecting payload type %d.\n",
				pa->type);
			goto end;
		}
	}

#ifdef ENABLE_NATT
	if (NATT_AVAILABLE(iph1))
		plog(LLV_INFO, LOCATION, iph1->remote,
		     "Selected NAT-T version: %s\n",
		     vid_string_by_id(iph1->natt_options->version));
#endif

	/* check SA payload and set approval SA for use */
	if (ipsecdoi_checkph1proposal(iph1->sa, iph1) < 0) {
		plog(LLV_ERROR, LOCATION, iph1->remote,
			"failed to get valid proposal.\n");
		/* XXX send information */
		goto end;
	}

	iph1->status = PHASE1ST_MSG1RECEIVED;

	error = 0;

end:
	if (pbuf)
		vfree(pbuf);
	if (error) {
		VPTRINIT(iph1->sa);
	}

	return error;
}

/*
 * send to initiator
 * 	psk: HDR, SA
 * 	sig: HDR, SA
 * 	rsa: HDR, SA
 * 	rev: HDR, SA
 */
int
ident_r1send(struct ph1handle *iph1, vchar_t *msg)
{
	struct payload_list *plist = NULL;
	int error = -1;
	vchar_t *gss_sa = NULL;
#ifdef HAVE_GSSAPI
	int free_gss_sa = 0;
#endif
#ifdef ENABLE_NATT
	vchar_t *vid_natt = NULL;
#endif
#ifdef ENABLE_HYBRID
        vchar_t *vid_xauth = NULL;
        vchar_t *vid_unity = NULL;
#endif  
#ifdef ENABLE_DPD
	vchar_t *vid_dpd = NULL;
#endif
#ifdef ENABLE_FRAG          
	vchar_t *vid_frag = NULL;
#endif 

	/* validity check */
	if (iph1->status != PHASE1ST_MSG1RECEIVED) {
		plog(LLV_ERROR, LOCATION, NULL,
			"status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* set responder's cookie */
	isakmp_newcookie((caddr_t)&iph1->index.r_ck, iph1->remote, iph1->local);

#ifdef HAVE_GSSAPI
	if (iph1->approval->gssid != NULL) {
		gss_sa = ipsecdoi_setph1proposal(iph1->approval);
		if (gss_sa != iph1->sa_ret)
			free_gss_sa = 1;
	} else 
#endif
		gss_sa = iph1->sa_ret;

	/* set SA payload to reply */
	plist = isakmp_plist_append(plist, gss_sa, ISAKMP_NPTYPE_SA);

#ifdef ENABLE_HYBRID
	if (iph1->mode_cfg->flags & ISAKMP_CFG_VENDORID_XAUTH) {
		plog (LLV_INFO, LOCATION, NULL, "Adding xauth VID payload.\n");
		if ((vid_xauth = set_vendorid(VENDORID_XAUTH)) == NULL) {
			plog(LLV_ERROR, LOCATION, NULL,
			    "Cannot create Xauth vendor ID\n");
			goto end;
		}
		plist = isakmp_plist_append(plist,
		    vid_xauth, ISAKMP_NPTYPE_VID);
	}

	if (iph1->mode_cfg->flags & ISAKMP_CFG_VENDORID_UNITY) {
		if ((vid_unity = set_vendorid(VENDORID_UNITY)) == NULL) {
			plog(LLV_ERROR, LOCATION, NULL,
			    "Cannot create Unity vendor ID\n");
			goto end;
		}
		plist = isakmp_plist_append(plist,
		    vid_unity, ISAKMP_NPTYPE_VID);
	}
#endif
#ifdef ENABLE_NATT
	/* Has the peer announced NAT-T? */
	if (NATT_AVAILABLE(iph1))
		vid_natt = set_vendorid(iph1->natt_options->version);

	if (vid_natt)
		plist = isakmp_plist_append(plist, vid_natt, ISAKMP_NPTYPE_VID);
#endif
#ifdef ENABLE_DPD
	/* XXX only send DPD VID if remote sent it ? */
	if(iph1->rmconf->dpd){
		vid_dpd = set_vendorid(VENDORID_DPD);
		if (vid_dpd != NULL)
			plist = isakmp_plist_append(plist, vid_dpd, ISAKMP_NPTYPE_VID);
	}
#endif
#ifdef ENABLE_FRAG
	if (iph1->frag) {
		vid_frag = set_vendorid(VENDORID_FRAG);
		if (vid_frag != NULL)
			vid_frag = isakmp_frag_addcap(vid_frag,
			    VENDORID_FRAG_IDENT);
		if (vid_frag == NULL)
			plog(LLV_ERROR, LOCATION, NULL,
			    "Frag vendorID construction failed\n");
		else
			plist = isakmp_plist_append(plist, 
			     vid_frag, ISAKMP_NPTYPE_VID);
	}
#endif

	iph1->sendbuf = isakmp_plist_set_all (&plist, iph1);

#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(iph1->sendbuf, iph1->local, iph1->remote, 0);
#endif

	/* send the packet, add to the schedule to resend */
	iph1->retry_counter = iph1->rmconf->retry_counter;
	if (isakmp_ph1resend(iph1) == -1) {
		goto end;
	}

	/* the sending message is added to the received-list. */
	if (add_recvdpkt(iph1->remote, iph1->local, iph1->sendbuf, msg) == -1) {
		plog(LLV_ERROR , LOCATION, NULL,
			"failed to add a response packet to the tree.\n");
		goto end;
	}

	iph1->status = PHASE1ST_MSG1SENT;

	error = 0;

end:
#ifdef HAVE_GSSAPI
	if (free_gss_sa)
		vfree(gss_sa);
#endif
#ifdef ENABLE_NATT
	if (vid_natt)
		vfree(vid_natt);
#endif
#ifdef ENABLE_HYBRID
	if (vid_xauth != NULL)
		vfree(vid_xauth);
	if (vid_unity != NULL)
		vfree(vid_unity);
#endif
#ifdef ENABLE_DPD
	if (vid_dpd != NULL)
		vfree(vid_dpd);
#endif
#ifdef ENABLE_FRAG
	if (vid_frag != NULL)
		vfree(vid_frag);
#endif

	return error;
}

/*
 * receive from initiator
 * 	psk: HDR, KE, Ni
 * 	sig: HDR, KE, Ni
 *   gssapi: HDR, KE, Ni, GSSi
 * 	rsa: HDR, KE, [ HASH(1), ] <IDi1_b>PubKey_r, <Ni_b>PubKey_r
 * 	rev: HDR, [ HASH(1), ] <Ni_b>Pubkey_r, <KE_b>Ke_i,
 * 	          <IDi1_b>Ke_i, [<<Cert-I_b>Ke_i]
 */
int ident_r2recv(struct ph1handle *iph1, vchar_t *msg)
{
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;
	int error = -1;
#ifdef HAVE_GSSAPI
	vchar_t *gsstoken = NULL;
#endif
#ifdef ENABLE_NATT
	int natd_seq = 0;
#endif

	/* validity check */
	if (iph1->status != PHASE1ST_MSG1SENT) {
		plog(LLV_ERROR, LOCATION, NULL,
			"status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* validate the type of next payload */
	pbuf = isakmp_parse(msg);
	if (pbuf == NULL)
		goto end;
	
	if(OAKLEY_ATTR_AUTH_METHOD_SM_DE == AUTHMETHOD(iph1)) {
		 if(ident_ir2_phase_de(iph1, (struct isakmp_parse_t *)pbuf->v) < 0){
			/** Todo debug*/		
			goto end;
		 }
	}else{		
		for (pa = (struct isakmp_parse_t *)pbuf->v;
		     pa->type != ISAKMP_NPTYPE_NONE;
		     pa++) {
			plog(LLV_ERROR, LOCATION, NULL,"%s:type %d.\n", __FUNCTION__, pa->type); 	
			switch (pa->type) {
			case ISAKMP_NPTYPE_KE:
				if (isakmp_p2ph(&iph1->dhpub_p, pa->ptr) < 0)
					goto end;
				break;
			case ISAKMP_NPTYPE_NONCE:
				if (isakmp_p2ph(&iph1->nonce_p, pa->ptr) < 0)
					goto end;
				break;
			case ISAKMP_NPTYPE_VID:
			(void)check_vendorid(pa->ptr);
				break;
			case ISAKMP_NPTYPE_CR:
				plog(LLV_WARNING, LOCATION, iph1->remote,
					"CR received, ignore it. "
					"It should be in other exchange.\n");
				break;
			
	#ifdef HAVE_GSSAPI
			case ISAKMP_NPTYPE_GSS:
				if (isakmp_p2ph(&gsstoken, pa->ptr) < 0)
					goto end;
				gssapi_save_received_token(iph1, gsstoken);
				break;
	#endif

	#ifdef ENABLE_NATT
			case ISAKMP_NPTYPE_NATD_DRAFT:
			case ISAKMP_NPTYPE_NATD_RFC:
				if (NATT_AVAILABLE(iph1) && iph1->natt_options != NULL &&
					pa->type == iph1->natt_options->payload_nat_d)
				{
					vchar_t *natd_received = NULL;
					int natd_verified;

					if (isakmp_p2ph (&natd_received, pa->ptr) < 0)
						goto end;

					if (natd_seq == 0)
						iph1->natt_flags |= NAT_DETECTED;

					natd_verified = natt_compare_addr_hash (iph1,
						natd_received, natd_seq++);

					plog (LLV_INFO, LOCATION, NULL, "NAT-D payload #%d %s\n",
						natd_seq - 1,
						natd_verified ? "verified" : "doesn't match");

					vfree (natd_received);
					break;
				}
				/* passthrough to default... */
	#endif

			default:
				/* don't send information, see ident_r1recv() */
				plog(LLV_ERROR, LOCATION, iph1->remote,
					"ignore the packet, "
					"received unexpecting payload type %d.\n",
					pa->type);
				goto end;
			}
		}
	}

#ifdef ENABLE_NATT
	if (NATT_AVAILABLE(iph1))
		plog (LLV_INFO, LOCATION, NULL, "NAT %s %s%s\n",
		      iph1->natt_flags & NAT_DETECTED ? 
		      		"detected:" : "not detected",
		      iph1->natt_flags & NAT_DETECTED_ME ? "ME " : "",
		      iph1->natt_flags & NAT_DETECTED_PEER ? "PEER" : "");
#endif

	if(AUTHMETHOD(iph1) != OAKLEY_ATTR_AUTH_METHOD_SM_DE){
		/* payload existency check */
		if (iph1->dhpub_p == NULL || iph1->nonce_p == NULL) {
			plog(LLV_ERROR, LOCATION, iph1->remote,
				"few isakmp message received.\n");
			goto end;
		}
	}	

	iph1->status = PHASE1ST_MSG2RECEIVED;

	error = 0;

end:
	if (pbuf)
		vfree(pbuf);
#ifdef HAVE_GSSAPI
	if (gsstoken)
		vfree(gsstoken);
#endif

	if (error) {
		VPTRINIT(iph1->dhpub_p);
		VPTRINIT(iph1->nonce_p);
		VPTRINIT(iph1->id_p);
	}

	return error;
}

/*
 * send to initiator
 * 	psk: HDR, KE, Nr
 * 	sig: HDR, KE, Nr [, CR ]
 *   gssapi: HDR, KE, Nr, GSSr
 * 	rsa: HDR, KE, <IDr1_b>PubKey_i, <Nr_b>PubKey_i
 * 	rev: HDR, <Nr_b>PubKey_i, <KE_b>Ke_r, <IDr1_b>Ke_r,
 */
int ident_r2send(struct ph1handle *iph1, vchar_t *msg)
{
	int error = -1;

	/* validity check */
	if (iph1->status != PHASE1ST_MSG2RECEIVED) {
		plog(LLV_ERROR, LOCATION, NULL,
			"status mismatched %d.\n", iph1->status);
		goto end;
	}

	if(OAKLEY_ATTR_AUTH_METHOD_SM_DE == AUTHMETHOD(iph1)) {	
		iph1->sendbuf = ident_ir2mx_de(iph1);
		if (iph1->sendbuf == NULL){
			goto end;
		}
	}else {
		/* generate DH public value */
		if (oakley_dh_generate(iph1->approval->dhgrp,
					&iph1->dhpub, &iph1->dhpriv) < 0)
			goto end;

	/* generate NONCE value */
	iph1->nonce = eay_set_random(iph1->rmconf->nonce_size);
	if (iph1->nonce == NULL)
		goto end;

#ifdef HAVE_GSSAPI
	if (AUTHMETHOD(iph1) == OAKLEY_ATTR_AUTH_METHOD_GSSAPI_KRB)
		gssapi_get_rtoken(iph1, NULL);
#endif

	/* create HDR;KE;NONCE payload */
	iph1->sendbuf = ident_ir2mx(iph1);
	if (iph1->sendbuf == NULL)
		goto end;
	}
#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(iph1->sendbuf, iph1->local, iph1->remote, 0);
#endif

	/* send the packet, add to the schedule to resend */
	iph1->retry_counter = iph1->rmconf->retry_counter;
	if (isakmp_ph1resend(iph1) == -1)
		goto end;

	/* the sending message is added to the received-list. */
	if (add_recvdpkt(iph1->remote, iph1->local, iph1->sendbuf, msg) == -1) {
		plog(LLV_ERROR , LOCATION, NULL,
			"failed to add a response packet to the tree.\n");
		goto end;
	}
	
	if(OAKLEY_ATTR_AUTH_METHOD_SM_DE == AUTHMETHOD(iph1)){
		/* generate SKEYIDs & IV & final cipher key */
		if (oakley_skeyid(iph1) < 0)
			goto end;
		if (oakley_skeyid_dae_de(iph1) < 0)
			goto end;
		if (oakley_compute_enckey(iph1) < 0)
			goto end;
		if (oakley_newiv_de(iph1) < 0)
			goto end;
	}else {
		/* compute sharing secret of DH */
		if (oakley_dh_compute(iph1->approval->dhgrp, iph1->dhpub,
					iph1->dhpriv, iph1->dhpub_p, &iph1->dhgxy) < 0)
			goto end;

		/* generate SKEYIDs & IV & final cipher key */
		if (oakley_skeyid(iph1) < 0)
			goto end;
		if (oakley_skeyid_dae(iph1) < 0)
			goto end;
		if (oakley_compute_enckey(iph1) < 0)
			goto end;
		if (oakley_newiv(iph1) < 0)
			goto end;
	}
	
	iph1->status = PHASE1ST_MSG2SENT;

	error = 0;

end:
	return error;
}

/*
 * receive from initiator
 * 	psk: HDR*, IDi1, HASH_I
 * 	sig: HDR*, IDi1, [ CR, ] [ CERT, ] SIG_I
 *   gssapi: HDR*, [ IDi1, ] < GSSi(n) | HASH_I >
 * 	rsa: HDR*, HASH_I
 * 	rev: HDR*, HASH_I
 */
int
ident_r3recv(struct ph1handle *iph1, vchar_t *msg0)
{
	vchar_t *msg = NULL;
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;
	int error = -1;
	int type;
#ifdef HAVE_GSSAPI
	vchar_t *gsstoken = NULL;
#endif

	/* validity check */
	if (iph1->status != PHASE1ST_MSG2SENT) {
		plog(LLV_ERROR, LOCATION, NULL,
			"status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* decrypting */
	if (!ISSET(((struct isakmp *)msg0->v)->flags, ISAKMP_FLAG_E)) {
		plog(LLV_ERROR, LOCATION, iph1->remote,
			"reject the packet, "
			"expecting the packet encrypted.\n");
		goto end;
	}
	msg = oakley_do_decrypt(iph1, msg0, iph1->ivm->iv, iph1->ivm->ive);
	if (msg == NULL)
		goto end;

	/* validate the type of next payload */
	pbuf = isakmp_parse(msg);
	if (pbuf == NULL)
		goto end;

	iph1->pl_hash = NULL;

	for (pa = (struct isakmp_parse_t *)pbuf->v;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {

		switch (pa->type) {
		case ISAKMP_NPTYPE_ID:
			if (isakmp_p2ph(&iph1->id_p, pa->ptr) < 0)
				goto end;
			break;
		case ISAKMP_NPTYPE_HASH:
			iph1->pl_hash = (struct isakmp_pl_hash *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_CR:
			if (oakley_savecr(iph1, pa->ptr) < 0)
				goto end;
			break;
		case ISAKMP_NPTYPE_CERT:
			if (oakley_savecert(iph1, pa->ptr) < 0)
				goto end;
			break;
		case ISAKMP_NPTYPE_SIG:
			if (isakmp_p2ph(&iph1->sig_p, pa->ptr) < 0)
				goto end;
			break;
#ifdef HAVE_GSSAPI
		case ISAKMP_NPTYPE_GSS:
			if (isakmp_p2ph(&gsstoken, pa->ptr) < 0)
				goto end;
			gssapi_save_received_token(iph1, gsstoken);
			break;
#endif
		case ISAKMP_NPTYPE_VID:
			(void)check_vendorid(pa->ptr);
			break;
		case ISAKMP_NPTYPE_N:
			isakmp_check_notify(pa->ptr, iph1);
			break;
		default:
			/* don't send information, see ident_r1recv() */
			plog(LLV_ERROR, LOCATION, iph1->remote,
				"ignore the packet, "
				"received unexpecting payload type %d.\n",
				pa->type);
			goto end;
		}
	}

	/* payload existency check */
	/* XXX same as ident_i4recv(), should be merged. */
    {
	int ng = 0;

	switch (AUTHMETHOD(iph1)) {
	case OAKLEY_ATTR_AUTH_METHOD_PSKEY:
#ifdef ENABLE_HYBRID
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_PSKEY_R:
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_RSA_R:
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_DSS_R:
#endif
		if (iph1->id_p == NULL || iph1->pl_hash == NULL)
			ng++;
		break;
	case OAKLEY_ATTR_AUTH_METHOD_DSSSIG:
	case OAKLEY_ATTR_AUTH_METHOD_RSASIG:
#ifdef ENABLE_HYBRID
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSASIG_R:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_DSSSIG_R:
#endif
		if (iph1->id_p == NULL || iph1->sig_p == NULL)
			ng++;
		break;
	case OAKLEY_ATTR_AUTH_METHOD_RSAENC:
	case OAKLEY_ATTR_AUTH_METHOD_RSAREV:
#ifdef ENABLE_HYBRID
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAENC_R:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAREV_R:
#endif
		if (iph1->pl_hash == NULL)
			ng++;
		break;
#ifdef HAVE_GSSAPI
	case OAKLEY_ATTR_AUTH_METHOD_GSSAPI_KRB:
		if (gsstoken == NULL && iph1->pl_hash == NULL)
			ng++;
		break;
#endif
	case OAKLEY_ATTR_AUTH_METHOD_SM_DE:
		if (iph1->pl_hash == NULL)
			ng++;
		break;
	default:
		plog(LLV_ERROR, LOCATION, iph1->remote,
			"invalid authmethod %d why ?\n",
			iph1->approval->authmethod);
		goto end;
	}
	if (ng) {
		plog(LLV_ERROR, LOCATION, iph1->remote,
			"few isakmp message received.\n");
		goto end;
	}
    }

	/* verify identifier */
	if (ipsecdoi_checkid1(iph1) != 0) {
		plog(LLV_ERROR, LOCATION, iph1->remote,
			"invalid ID payload.\n");
		goto end;
	}

	/* validate authentication value */
#ifdef HAVE_GSSAPI
	if (gsstoken == NULL) {
#endif
		type = oakley_validate_auth(iph1);
		if (type != 0) {
			if (type == -1) {
				/* msg printed inner oakley_validate_auth() */
				goto end;
			}
			EVT_PUSH(iph1->local, iph1->remote, 
			    EVTT_PEERPH1AUTH_FAILED, NULL);
			isakmp_info_send_n1(iph1, type, NULL);
			goto end;
		}
#ifdef HAVE_GSSAPI
	}
#endif

	if (oakley_checkcr(iph1) < 0) {
		/* Ignore this error in order to be interoperability. */
		;
	}

	/*
	 * XXX: Should we do compare two addresses, ph1handle's and ID
	 * payload's.
	 */

	plog(LLV_DEBUG, LOCATION, iph1->remote, "peer's ID\n");
	plogdump(LLV_DEBUG, iph1->id_p->v, iph1->id_p->l);

	/* see handler.h about IV synchronization. */
	memcpy(iph1->ivm->iv->v, iph1->ivm->ive->v, iph1->ivm->ive->l);

#ifdef HAVE_GSSAPI
	iph1->status = gsstoken != NULL ? PHASE1ST_MSG2RECEIVED :
	    PHASE1ST_MSG3RECEIVED;
#else
	iph1->status = PHASE1ST_MSG3RECEIVED;
#endif

	error = 0;

end:
	if (pbuf)
		vfree(pbuf);
	if (msg)
		vfree(msg);
#ifdef HAVE_GSSAPI
	if (gsstoken)
		vfree(gsstoken);
#endif

	if (error) {
		VPTRINIT(iph1->id_p);
		oakley_delcert(iph1->cert_p);
		iph1->cert_p = NULL;
		oakley_delcert(iph1->crl_p);
		iph1->crl_p = NULL;
		VPTRINIT(iph1->sig_p);
		oakley_delcert(iph1->cr_p);
		iph1->cr_p = NULL;
	}

	return error;
}

/*
 * send to initiator
 * 	psk: HDR*, IDr1, HASH_R
 * 	sig: HDR*, IDr1, [ CERT, ] SIG_R
 *   gssapi: HDR*, IDr1, < GSSr(n) | HASH_R >
 * 	rsa: HDR*, HASH_R
 * 	rev: HDR*, HASH_R
 */
int
ident_r3send(struct ph1handle *iph1, vchar_t *msg)
{
	int error = -1;
	int dohash = 1;
#ifdef HAVE_GSSAPI
	int len;
#endif

	/* validity check */
	if (iph1->status != PHASE1ST_MSG3RECEIVED) {
		plog(LLV_ERROR, LOCATION, NULL,
			"status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* make ID payload into isakmp status */
	if (ipsecdoi_setid1(iph1) < 0)
		goto end;

#ifdef HAVE_GSSAPI
	if (AUTHMETHOD(iph1) == OAKLEY_ATTR_AUTH_METHOD_GSSAPI_KRB &&
	    gssapi_more_tokens(iph1)) {
		gssapi_get_rtoken(iph1, &len);
		if (len != 0)
			dohash = 0;
	}
#endif

	if (dohash) {
		/* generate HASH to send */
		plog(LLV_DEBUG, LOCATION, NULL, "generate HASH_R\n");
		iph1->hash = oakley_ph1hash_common(iph1, GENERATE);
		if (iph1->hash == NULL)
			goto end;
	} else
		iph1->hash = NULL;

	/* set encryption flag */
	iph1->flags |= ISAKMP_FLAG_E;

	/* create HDR;ID;HASH payload */
	iph1->sendbuf = ident_ir3mx(iph1);
	if (iph1->sendbuf == NULL)
		goto end;

	/* send HDR;ID;HASH to responder */
	if (isakmp_send(iph1, iph1->sendbuf) < 0)
		goto end;

	/* the sending message is added to the received-list. */
	if (add_recvdpkt(iph1->remote, iph1->local, iph1->sendbuf, msg) == -1) {
		plog(LLV_ERROR , LOCATION, NULL,
			"failed to add a response packet to the tree.\n");
		goto end;
	}

	/* see handler.h about IV synchronization. */
	memcpy(iph1->ivm->ive->v, iph1->ivm->iv->v, iph1->ivm->iv->l);

	iph1->status = PHASE1ST_ESTABLISHED;

	error = 0;

end:

	return error;
}

/*
 * This is used in main mode for:
 * initiator's 3rd exchange send to responder
 * 	psk: HDR, KE, Ni
 * 	sig: HDR, KE, Ni
 * 	rsa: HDR, KE, [ HASH(1), ] <IDi1_b>PubKey_r, <Ni_b>PubKey_r
 * 	rev: HDR, [ HASH(1), ] <Ni_b>Pubkey_r, <KE_b>Ke_i,
 * 	          <IDi1_b>Ke_i, [<<Cert-I_b>Ke_i]
 * responders 2nd exchnage send to initiator
 * 	psk: HDR, KE, Nr
 * 	sig: HDR, KE, Nr [, CR ]
 * 	rsa: HDR, KE, <IDr1_b>PubKey_i, <Nr_b>PubKey_i
 * 	rev: HDR, <Nr_b>PubKey_i, <KE_b>Ke_r, <IDr1_b>Ke_r,
 */
static vchar_t *
ident_ir2mx(struct ph1handle *iph1)
{
	vchar_t *buf = 0;
	struct payload_list *plist = NULL;
	int need_cr = 0;
	vchar_t *cr = NULL;
	vchar_t *vid = NULL;
	int error = -1;
#ifdef HAVE_GSSAPI
	vchar_t *gsstoken = NULL;
#endif
#ifdef ENABLE_NATT
	vchar_t *natd[2] = { NULL, NULL };
#endif

	/* create CR if need */
	if (iph1->side == RESPONDER
	 && iph1->rmconf->send_cr
	 && oakley_needcr(iph1->approval->authmethod)
	 && iph1->rmconf->peerscertfile == NULL) {
		need_cr = 1;
		cr = oakley_getcr(iph1);
		if (cr == NULL) {
			plog(LLV_ERROR, LOCATION, NULL,
				"failed to get cr buffer.\n");
			goto end;
		}
	}

#ifdef HAVE_GSSAPI
	if (AUTHMETHOD(iph1) == OAKLEY_ATTR_AUTH_METHOD_GSSAPI_KRB)
		gssapi_get_token_to_send(iph1, &gsstoken);
#endif

	/* create isakmp KE payload */
	plist = isakmp_plist_append(plist, iph1->dhpub, ISAKMP_NPTYPE_KE);

	/* create isakmp NONCE payload */
	plist = isakmp_plist_append(plist, iph1->nonce, ISAKMP_NPTYPE_NONCE);

#ifdef HAVE_GSSAPI
	if (AUTHMETHOD(iph1) == OAKLEY_ATTR_AUTH_METHOD_GSSAPI_KRB)
		plist = isakmp_plist_append(plist, gsstoken, ISAKMP_NPTYPE_GSS);
#endif

	/* append vendor id, if needed */
	if (vid)
		plist = isakmp_plist_append(plist, vid, ISAKMP_NPTYPE_VID);

	/* create isakmp CR payload if needed */
	if (need_cr)
		plist = isakmp_plist_append(plist, cr, ISAKMP_NPTYPE_CR);

#ifdef ENABLE_NATT
	/* generate and append NAT-D payloads */
	if (NATT_AVAILABLE(iph1) && iph1->status == PHASE1ST_MSG2RECEIVED)
	{
		if ((natd[0] = natt_hash_addr (iph1, iph1->remote)) == NULL) {
			plog(LLV_ERROR, LOCATION, NULL,
				"NAT-D hashing failed for %s\n", saddr2str(iph1->remote));
			goto end;
		}

		if ((natd[1] = natt_hash_addr (iph1, iph1->local)) == NULL) {
			plog(LLV_ERROR, LOCATION, NULL,
				"NAT-D hashing failed for %s\n", saddr2str(iph1->local));
			goto end;
		}

		plog (LLV_INFO, LOCATION, NULL, "Adding remote and local NAT-D payloads.\n");
		plist = isakmp_plist_append(plist, natd[0], iph1->natt_options->payload_nat_d);
		plist = isakmp_plist_append(plist, natd[1], iph1->natt_options->payload_nat_d);
	}
#endif
	
	buf = isakmp_plist_set_all (&plist, iph1);
	
	error = 0;

end:
	if (error && buf != NULL) {
		vfree(buf);
		buf = NULL;
	}
	if (cr)
		vfree(cr);
#ifdef HAVE_GSSAPI
	if (gsstoken)
		vfree(gsstoken);
#endif
	if (vid)
		vfree(vid);

#ifdef ENABLE_NATT
	if (natd[0])
		vfree(natd[0]);
	if (natd[1])
		vfree(natd[1]);
#endif

	return buf;
}

/*
 * This is used in main mode for:
 * initiator's 4th exchange send to responder
 * 	psk: HDR*, IDi1, HASH_I
 * 	sig: HDR*, IDi1, [ CR, ] [ CERT, ] SIG_I
 *   gssapi: HDR*, [ IDi1, ] < GSSi(n) | HASH_I >
 * 	rsa: HDR*, HASH_I
 * 	rev: HDR*, HASH_I
 * responders 3rd exchnage send to initiator
 * 	psk: HDR*, IDr1, HASH_R
 * 	sig: HDR*, IDr1, [ CERT, ] SIG_R
 *   gssapi: HDR*, [ IDr1, ] < GSSr(n) | HASH_R >
 * 	rsa: HDR*, HASH_R
 * 	rev: HDR*, HASH_R
 */
static vchar_t * ident_ir3mx(struct ph1handle *iph1)
{
	struct payload_list *plist = NULL;
	vchar_t *buf = NULL, *new = NULL;
	int need_cr = 0;
	int need_cert = 0;
	vchar_t *cr = NULL;
	int error = -1;
#ifdef HAVE_GSSAPI
	int nptype;
	vchar_t *gsstoken = NULL;
	vchar_t *gsshash = NULL;
#endif

	switch (AUTHMETHOD(iph1)) {
	case OAKLEY_ATTR_AUTH_METHOD_PSKEY:
#ifdef ENABLE_HYBRID
	case FICTIVE_AUTH_METHOD_XAUTH_PSKEY_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_PSKEY_R:
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_RSA_I:
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_DSS_I:
#endif
		/* create isakmp ID payload */
		plist = isakmp_plist_append(plist, iph1->id, ISAKMP_NPTYPE_ID);

		/* create isakmp HASH payload */
		plist = isakmp_plist_append(plist, iph1->hash, ISAKMP_NPTYPE_HASH);
		break;
	case OAKLEY_ATTR_AUTH_METHOD_DSSSIG:
	case OAKLEY_ATTR_AUTH_METHOD_RSASIG:
#ifdef ENABLE_HYBRID
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_RSA_R:
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_DSS_R:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSASIG_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSASIG_R:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_DSSSIG_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_DSSSIG_R:
#endif 
		if (oakley_getmycert(iph1) < 0)
			goto end;

		if (oakley_getsign(iph1) < 0)
			goto end;

		/* create CR if need */
		if (iph1->side == INITIATOR
		 && iph1->rmconf->send_cr
	 	 && oakley_needcr(iph1->approval->authmethod)
		 && iph1->rmconf->peerscertfile == NULL) {
			need_cr = 1;
			cr = oakley_getcr(iph1);
			if (cr == NULL) {
				plog(LLV_ERROR, LOCATION, NULL,
					"failed to get cr buffer.\n");
				goto end;
			}
		}

		if (iph1->cert != NULL && iph1->rmconf->send_cert)
			need_cert = 1;

		/* add ID payload */
		plist = isakmp_plist_append(plist, iph1->id, ISAKMP_NPTYPE_ID);

		/* add CERT payload if there */
		if (need_cert)
			plist = isakmp_plist_append(plist, iph1->cert->pl, ISAKMP_NPTYPE_CERT);
		/* add SIG payload */
		plist = isakmp_plist_append(plist, iph1->sig, ISAKMP_NPTYPE_SIG);

		/* create isakmp CR payload */
		if (need_cr)
			plist = isakmp_plist_append(plist, cr, ISAKMP_NPTYPE_CR);
		break;
#ifdef HAVE_GSSAPI
	case OAKLEY_ATTR_AUTH_METHOD_GSSAPI_KRB:
		if (iph1->hash != NULL) {
			gsshash = gssapi_wraphash(iph1);
			if (gsshash == NULL)
				goto end;
		} else {
			gssapi_get_token_to_send(iph1, &gsstoken);
		}

		if (!gssapi_id_sent(iph1)) {
			/* create isakmp ID payload */
			plist = isakmp_plist_append(plist, iph1->id, ISAKMP_NPTYPE_ID);
			gssapi_set_id_sent(iph1);
		}

		if (iph1->hash != NULL)
			/* create isakmp HASH payload */
			plist = isakmp_plist_append(plist, gsshash, ISAKMP_NPTYPE_HASH);
		else
			plist = isakmp_plist_append(plist, gsstoken, ISAKMP_NPTYPE_GSS);
		break;
#endif
	case OAKLEY_ATTR_AUTH_METHOD_RSAENC:
	case OAKLEY_ATTR_AUTH_METHOD_RSAREV:
#ifdef ENABLE_HYBRID
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAENC_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAENC_R:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAREV_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAREV_R:
#endif
		plog(LLV_ERROR, LOCATION, NULL,
			"not supported authentication type %d\n",
			iph1->approval->authmethod);
		goto end;
	/***/	
	case OAKLEY_ATTR_AUTH_METHOD_SM_DE:
		/* create isakmp HASH payload */
		plist = isakmp_plist_append(plist, iph1->hash, ISAKMP_NPTYPE_HASH);
		break;
	default:
		plog(LLV_ERROR, LOCATION, NULL,
			"invalid authentication type %d\n",
			iph1->approval->authmethod);
		goto end;
	}

	buf = isakmp_plist_set_all (&plist, iph1);
	
#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(buf, iph1->local, iph1->remote, 1);
#endif

	/* encoding */
	plog(LLV_INFO, LOCATION, NULL, "\n%s: buf len %lu\n", __FUNCTION__, buf->l);
	plogdumpf(LLV_INFO, buf->v, buf->l, __FUNCTION__);
	new = oakley_do_encrypt(iph1, buf, iph1->ivm->ive, iph1->ivm->iv);
	if (new == NULL)
		goto end;

	vfree(buf);

	buf = new;

	error = 0;

end:
#ifdef HAVE_GSSAPI
	if (gsstoken)
		vfree(gsstoken);
#endif
	if (cr)
		vfree(cr);
	if (error && buf != NULL) {
		vfree(buf);
		buf = NULL;
	}

	return buf;
}
