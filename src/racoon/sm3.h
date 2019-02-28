/*
 * sm3.h
 *
 *  Created on: 2015-9-16
 *      Author: lyyu (Liyang Yu)
 *	   Version: 1.0
 * Description: sm3 include file for ike
 */

#ifndef _IPSEC_SM3_H_
#define _IPSEC_SM3_H_

#include "vmbuf.h"

#define SM3_DIGEST_SIZE	32
#define HMAC_BUFER_SIZE 64

#define HMAC_IPAD	0x36
#define HMAC_OPAD	0x5C
typedef struct sm3_ctx
{ 
	int LENGHT;
	unsigned int MIDLE_STATE[8];   
	unsigned int CONSTANT_T[64];  
	unsigned char MEM[64]; 
	unsigned char IPAD[HMAC_BUFER_SIZE];     /** MAC: inner padding        */
    unsigned char OPAD[HMAC_BUFER_SIZE];     /**HMAC: outer padding        */
} SM3_CTX;

char *sm3_init();
void sm3_update(char *c, vchar_t *data);
vchar_t * sm3_final(char *c);

void sm3_update_ex(SM3_CTX *ctx ,unsigned char * ain,int ain_len);
void sm3_final_ex(SM3_CTX *ctx, unsigned char aout[32]);
void sm3_hash(unsigned char *ain, int len, unsigned char aout[32]);
int sm3_hash_len();
vchar_t *sm3_digest_one(vchar_t *data);
char *sm3_hmac_init(vchar_t *key);
void sm3_hmac_update(char *c, vchar_t *data);
vchar_t *sm3_hmac_final(char *c);
vchar_t *sm3_hmac_one(vchar_t *key, vchar_t *data);



#endif/* _IPSEC_SM3_H_ */

