#include "ec_general.h"

EC_GROUP group;

void ECC_ProduceKey(int Keylen,unsigned char *pubkey,unsigned char *prvkey)
{

	ECC_PUBLIC_KEY stECCPK;
	ECC_PRIVATE_KEY stECCSK;

	
	ECC_GenerateKeyPair(&group, &stECCPK, &stECCSK);

	printf("\n");
	memcpy(pubkey,&stECCPK.Qx[0],32);
	pubkey+=32;
	memcpy(pubkey,&stECCPK.Qy[0],32);
	
	
	memcpy(prvkey,&stECCSK.Ka[0],32);
	
}
