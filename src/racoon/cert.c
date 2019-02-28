/*
 * Copyright (C) 2015 Sapling Technologies Co.,Ltd. All Rights Reserved.
 *
 * cert.c
 *
 *  Created on: 2015-9-16
 *      Author: leon (Liyang Yu)
 *	   Version: 1.0
 * Description:	certificate operation API source file for ike
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "vmbuf.h"
#include "cert.h"
#include "var.h"

#define NULL_FD	(-1)	/* NULL file descriptor */

#define ASN1_INVALID_LENGTH	0xffffffff
#define MTYPE_IKE_ALLOC_BYTES 175

const chunk_t chunk_empty = { 0, NULL};
err_t ttodata(const char *src, size_t srclen, int base, char *buf,
			  size_t buflen, size_t *needed);
err_t ttodatav(const char *src, size_t srclen, int base,
			   char *buf,  size_t buflen, size_t *needed,
			   char *errp, size_t errlen, unsigned int flags);


/*
 * compare string with chunk
 */

void *clone_bytes(const void *orig, size_t size, const char *name)
{
	//void *p = malloc(size);
	void *p = malloc(size);
	if (p == NULL)
		//sapl_debug_out("unable to malloc %lu bytes for %s\n"	    , (unsigned long) size, name);
		memcpy(p, orig, size);
	return p;
}

#define clonetochunk(ch, addr, size, name) \
	{ (ch).ptr = clone_bytes((addr), (ch).len = (size), name); }

static bool
present(const char* pattern, chunk_t* ch)
{
	u_int pattern_len = strlen(pattern);

	if (ch->len >= pattern_len && strncmp((char*)ch->ptr, pattern, pattern_len) == 0) {
		ch->ptr += pattern_len;
		ch->len -= pattern_len;
		return TRUE;
	}
	return FALSE;
}
static bool match(const char *pattern, const chunk_t *ch)
{
	return ((ch->len == strlen(pattern)) &&
			strncmp(pattern, (char*)ch->ptr, ch->len) == 0);
}

/*
 * find a boundary of the form -----tag name-----
 */
static bool
find_boundary(const char* tag, chunk_t *line)
{
	chunk_t name = chunk_empty;

	if (!present("-----", line))
		return FALSE;
	if (!present(tag, line))
		return FALSE;
	if (*line->ptr != ' ')
		return FALSE;
	line->ptr++;
	line->len--;

	/* extract name */
	name.ptr = line->ptr;
	while (line->len > 0) {
		if (present("-----", line)) {
			//DBG(DBG_PARSING,		DBG_log("  -----%s %.*s-----", tag, (int)name.len, name.ptr);)
			return TRUE;
		}
		line->ptr++;
		line->len--;
		name.len++;
	}
	return FALSE;
}

/*
 * eat whitespace
 */
static void
eat_whitespace(chunk_t *src)
{
	while (src->len > 0 && (*src->ptr == ' ' || *src->ptr == '\t')) {
		src->ptr++;
		src->len--;
	}
}

/*
 * extracts a token ending with a given termination symbol
 */
static bool
extract_token(chunk_t *token, char termination, chunk_t *src)
{
	u_char *eot = memchr(src->ptr, termination, src->len);

	/* initialize empty token */
	*token = chunk_empty;

	if (eot == NULL) /* termination symbol not found */
		return FALSE;

	/* extract token */
	token->ptr = src->ptr;
	token->len = (u_int)(eot - src->ptr);

	/* advance src pointer after termination symbol */
	src->ptr = eot + 1;
	src->len -= (token->len + 1);

	return TRUE;
}

/*
 * extracts a name: value pair from the PEM header
 */
static bool
extract_parameter(chunk_t *name, chunk_t *value, chunk_t *line)
{
	//DBG(DBG_PARSING,DBG_log("  %.*s", (int)line->len, line->ptr);  )

	/* extract name */
	if (!extract_token(name, ':', line))
		return FALSE;

	eat_whitespace(line);

	/* extract value */
	*value = *line;
	return TRUE;
}

/*
 *  fetches a new line terminated by \n or \r\n
 */
static bool
fetchline(chunk_t *src, chunk_t *line)
{
	if (src->len == 0) /* end of src reached */
		return FALSE;

	if (extract_token(line, '\n', src)) {
		if (line->len > 0 && *(line->ptr + line->len - 1) == '\r')
			line->len--;  /* remove optional \r */
	} else { /*last line ends without newline */
		*line = *src;
		src->ptr += src->len;
		src->len = 0;
	}
	return TRUE;
}

/*
 * decrypts a DES-EDE-CBC encrypted data block
 */
static bool
pem_decrypt_3des(chunk_t *blob, chunk_t *iv, const char *passphrase)
{
	MD5_CTX context;
	u_char digest[MD5_DIGEST_SIZE];
	u_char des_iv[DES_CBC_BLOCK_SIZE];
	u_char key[24];
	des_cblock *deskey = (des_cblock *)key;
	des_key_schedule ks[3];
	u_char padding, *last_padding_pos, *first_padding_pos;

	/* Convert passphrase to 3des key */
	MD5_Init(&context);
	MD5_Update(&context, (u_char*)passphrase, strlen(passphrase));
	MD5_Update(&context, iv->ptr, iv->len);
	MD5_Final(digest, &context);

	memcpy(key, digest, MD5_DIGEST_SIZE);

	MD5_Init(&context);
	MD5_Update(&context, digest, MD5_DIGEST_SIZE);
	MD5_Update(&context, (u_char*)passphrase, strlen(passphrase));
	MD5_Update(&context, iv->ptr, iv->len);
	MD5_Final(digest, &context);

	memcpy(key + MD5_DIGEST_SIZE, digest, 24 - MD5_DIGEST_SIZE);

	(void) des_set_key(&deskey[0], ks[0]);
	(void) des_set_key(&deskey[1], ks[1]);
	(void) des_set_key(&deskey[2], ks[2]);

	/* decrypt data block */
	memcpy(des_iv, iv->ptr, DES_CBC_BLOCK_SIZE);
	des_ede3_cbc_encrypt((const unsigned char *)blob->ptr, (unsigned char *)blob->ptr,
						 blob->len, ks[0], ks[1], ks[2], (des_cblock *)des_iv, FALSE);

	/* determine amount of padding */
	last_padding_pos = blob->ptr + blob->len - 1;
	padding = *last_padding_pos;
	first_padding_pos = (padding > blob->len) ?
						blob->ptr : last_padding_pos - padding;

	/* check the padding pattern */
	while (--last_padding_pos > first_padding_pos) {
		if (*last_padding_pos != padding)
			return FALSE;
	}

	/* remove padding */
	blob->len -= padding;
	return TRUE;
}

/*
 * optionally prompts for a passphrase before decryption
 * currently we support DES-EDE3-CBC, only
 */
static err_t
pem_decrypt(chunk_t *blob, chunk_t *iv, prompt_pass_t *pass, const char* label)
{
	//DBG(DBG_CRYPT, DBG_log("  decrypting file using 'DES-EDE3-CBC'");   )
	if (iv->len != DES_CBC_BLOCK_SIZE)
		return "size of DES-EDE3-CBC IV is not 8 bytes";

	if (pass == NULL)
		return "no passphrase available";

	/* do we prompt for the passphrase? */
	if (pass->prompt && pass->fd != NULL_FD) {
		int i;
		chunk_t blob_copy;
		err_t ugh = "invalid passphrase, too many trials";

		//whack_log(RC_ENTERSECRET, "need passphrase for '%s'", label);

		for (i = 0; i < MAX_PROMPT_PASS_TRIALS; i++) {
			int n = 0;

			if (i > 0)
				//whack_log(RC_ENTERSECRET, "invalid passphrase, please try again");

				n = read(pass->fd, pass->secret, PROMPT_PASS_LEN);

			if (n == -1) {
				err_t ugh = "read(whackfd) failed";
				//whack_log(RC_LOG_SERIOUS,ugh);
				return ugh;
			}

			pass->secret[n - 1] = '\0';

			if (strlen(pass->secret) == 0) {
				err_t ugh = "no passphrase entered, aborted";
				//whack_log(RC_LOG_SERIOUS, ugh);
				return ugh;
			}

			clonetochunk(blob_copy, blob->ptr, blob->len, "blob copy");

			if (pem_decrypt_3des(blob, iv, pass->secret)) {
				//whack_log(RC_SUCCESS, "valid passphrase");
				free(blob_copy.ptr);
				return NULL;
			}

			/* blob is useless after wrong decryption, restore the original */
			free(blob->ptr);
			*blob = blob_copy;
		}
		//whack_log(RC_LOG_SERIOUS, ugh);
		return ugh;
	} else {
		if (pem_decrypt_3des(blob, iv, pass->secret))
			return NULL;
		else
			return "invalid passphrase";
	}
}


/*  Converts a PEM encoded file into its binary form
 *
 *  RFC 1421 Privacy Enhancement for Electronic Mail, February 1993
 *  RFC 934 Message Encapsulation, January 1985
 */
err_t pemtobin(vchar_t *blob, prompt_pass_t *pass, const char* label, bool *pgp)
{


	bool encrypted = FALSE;

	state_t state  = PEM_PRE;

	chunk_t src    = *(chunk_t *)blob;
	chunk_t dst    = *(chunk_t *)blob;
	chunk_t line   = chunk_empty;
	chunk_t iv	   = chunk_empty;

	unsigned char iv_buf[MAX_DIGEST_LEN];

	/* zero size of converted blob */
	dst.len = 0;

	/* zero size of IV */
	iv.ptr = iv_buf;
	iv.len = 0;

	while (fetchline(&src, &line)) {		
		if (state == PEM_PRE) {
			if (find_boundary("BEGIN", &line)) {
				*pgp = FALSE;
				state = PEM_MSG;
			}
			continue;
		} else {
			if (find_boundary("END", &line)) {
				state = PEM_POST;
				break;
			}
			if (state == PEM_MSG) {
				state = (memchr(line.ptr, ':', line.len) == NULL) ?
						PEM_BODY : PEM_HEADER;
			}
			if (state == PEM_HEADER) {
				chunk_t name  = chunk_empty;
				chunk_t value = chunk_empty;

				/* an empty line separates HEADER and BODY */
				if (line.len == 0) {
					state = PEM_BODY;
					continue;
				}

				/* we are looking for a name: value pair */
				if (!extract_parameter(&name, &value, &line))
					continue;

				if (match("Proc-Type", &name) && *value.ptr == '4')
					encrypted = TRUE;
				else if (match("DEK-Info", &name)) {
					const char *ugh = NULL;
					size_t len = 0;
					chunk_t dek;

					if (!extract_token(&dek, ',', &value))
						dek = value;

					/* we support DES-EDE3-CBC encrypted files, only */
					if (!match("DES-EDE3-CBC", &dek))
						return "we support DES-EDE3-CBC encrypted files, only";

					eat_whitespace(&value);
					ugh = ttodata((char*)value.ptr, value.len, 16,
								  (char*)iv.ptr, MAX_DIGEST_LEN, &len);
					if (ugh)
						return "error in IV";

					iv.len = len;
				}
			} else { /* state is PEM_BODY */
				const char *ugh = NULL;
				size_t len = 0;
				chunk_t data;

				/* remove any trailing whitespace */
				if (!extract_token(&data , ' ', &line))
					data = line;

				/* check for PGP armor checksum */
				if (*data.ptr == '=') {
					*pgp = TRUE;
					data.ptr++;
					data.len--;
					//DBG(DBG_PARSING, DBG_log("  Armor checksum: %.*s", (int)data.len, data.ptr);   )
					continue;
				}

				ugh = ttodata((char*)data.ptr, data.len, 64,
							  (char*)dst.ptr, blob->l - dst.len, &len);
				if (ugh) {
					///DBG(DBG_PARSING, DBG_log("  %s", ugh); )
					state = PEM_ABORT;
					break;
				} else {
					dst.ptr += len;
					dst.len += len;
				}
			}
		}
	}
	/* set length to size of binary blob */
	blob->l = dst.len;

	if (state != PEM_POST)
		return "file coded in unknown format, discarded";

	if (encrypted)
		return pem_decrypt((chunk_t *)blob, &iv, pass, label);
	else
		return NULL;
}

unsigned int asn1_length(vchar_t *blob)
{
	u_char n;
	size_t len;

	if (!blob || !blob->v)
		return ASN1_INVALID_LENGTH;

	/* advance from tag field on to length field */
	blob->v++;
	blob->l--;

	/* read first octet of length field */
	n = *blob->v++;
	blob->l--;

	if ((n & 0x80) == 0) /* single length octet */
		return n;

	/* composite length, determine number of length octets */
	n &= 0x7f;

	if (n > blob->l) {
		return ASN1_INVALID_LENGTH;
	}

	if (n > sizeof(len)) {
		return ASN1_INVALID_LENGTH;
	}

	len = 0;

	while (n-- > 0) {
		len = 256 * len + *blob->v++;
		blob->l--;
	}
	return len;
}


bool is_asn1(vchar_t *blob)
{
	unsigned int len;
	u_char tag;

	if (!blob || (0 == blob->l) || (NULL == blob->v)) {
		/**Todo error debug*/
		return FALSE;
	}

	tag = *blob->v;

	if (tag != 0x30 /*ASN1_SEQUENCE*/ && tag != 0x31/**ASN1_SET*/) {
		return FALSE;
	}

	len = asn1_length(blob);
	if (len != blob->l) {
		return FALSE;
	}
	return TRUE;
}




