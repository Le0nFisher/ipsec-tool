/*
 * Copyright (C) 2015 Sapling Technologies Co.,Ltd. All Rights Reserved.
 *
 * cert.h
 *
 *  Created on: 2015-9-16
 *      Author: leon (Liyang Yu)
 *	   Version: 1.0
 * Description:	certificate operation API include file for ike
 */

#ifndef _IPSEC_CERT_H_
#define _IPSEC_CERT_H_
#include "vmbuf.h"
#include "md5_dgst.h"
#include <openssl/des.h>

#define MD5_DIGEST_SIZE		(128 / BITS_PER_BYTE)	/* ought to be supplied by md5.h */
#define DES_CBC_BLOCK_SIZE	(64 / BITS_PER_BYTE)

#define MAX_PROMPT_PASS_TRIALS	5
#define PROMPT_PASS_LEN		64
#define MAX_DIGEST_LEN 20
#define	KEYID_BUF		10	/* up to 9 text digits plus NUL */
#define TTODATAV_IGNORESPACE  (1<<1)  /* ignore spaces in base64 encodings*/
#define BITS_PER_BYTE		8


#ifndef bool
typedef char bool;
#endif

typedef enum {
	PEM_PRE    = 0,
	PEM_MSG    = 1,
	PEM_HEADER = 2,
	PEM_BODY   = 3,
	PEM_POST   = 4,
	PEM_ABORT  = 5
} state_t;

/* struct used to prompt for a secret passphrase
 * from a console with file descriptor fd
 */
typedef struct {
    char secret[PROMPT_PASS_LEN+1];
    bool prompt;
    int fd;
} prompt_pass_t;

typedef struct chunk {
	size_t len;
	u_char *ptr;
}chunk_t;
/* Public key algorithm number
 * Same numbering as used in DNSsec
 * See RFC 2535 DNSsec 3.2 The KEY Algorithm Number Specification.
 * Also found in BIND 8.2.2 include/isc/dst.h as DST algorithm codes.
 */

enum pubkey_alg
{
	PUBKEY_ALG_RSA = 1,
	PUBKEY_ALG_SM2 = 2,
	PUBKEY_ALG_DSA = 3,
};

typedef const char *err_t;	/* error message, or NULL for success */


bool is_asn1(vchar_t *blob);
err_t pemtobin(vchar_t *blob, prompt_pass_t *pass, const char* label, bool *pgp);



#endif 
