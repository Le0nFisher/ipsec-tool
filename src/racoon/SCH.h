#ifndef HEADER_SCH_H
#define HEADER_SCH_H

#define SCH_CBLOCK	64
#define SCH_LONG	unsigned int
#define SCH_LBLOCK	16

#define SCH_160_FLAG 0
#define SCH_192_FLAG 1
#define SCH_256_FLAG 2

#define SCH_160_LEN 20
#define SCH_192_LEN 24
#define SCH_256_LEN 32

#define INIT_DATA_IV0 0x7380166F
#define INIT_DATA_IV1 0x4914B2B9
#define INIT_DATA_IV2 0x172442D7
#define INIT_DATA_IV3 0xDA8A0600
#define INIT_DATA_IV4 0xA96F30BC
#define INIT_DATA_IV5 0x163138AA
#define INIT_DATA_IV6 0xE38DEE4D
#define INIT_DATA_IV7 0xB0FB0E4E
						
#define INIT_DATA_T0 0x79CC4519
#define INIT_DATA_T1 0x7A879D8A

typedef struct SCHstate_st
{
	SCH_LONG IV0, IV1, IV2, IV3, IV4, IV5, IV6, IV7;
	SCH_LONG Nl, Nh;
	SCH_LONG data[SCH_LBLOCK];
	int num;
} SCH_CTX;


void SCH(const unsigned char *d, int n, int out_len, unsigned char *md);
void SCH_Init(SCH_CTX *c);
void SCH_Update(SCH_CTX *c, const void *data_, int len);
void SCH_Final(unsigned char *md, SCH_CTX *c, int out_len);

#endif
