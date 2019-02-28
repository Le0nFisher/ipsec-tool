
#include <stdlib.h>
#include <stdio.h>

#include "bn.h"
#include "bn_lib.h"
#include "bn_div.h"
#include "bn_mod.h"
#include "bn_gcd.h"
#include "ec_lcl.h"
#include "ecp_smpl.h"
#include "ec_mult.h"



void ECDSA_Sig(EC_GROUP *group, unsigned char *e, unsigned int e_len, 
				unsigned char *pRand, ECC_PRIVATE_KEY *pECCSK, ECC_SIGNATURE *pECCSign);
int ECDSA_Verify(EC_GROUP *group, unsigned char *e, unsigned int e_len, 
				ECC_PUBLIC_KEY *pECCPK, ECC_SIGNATURE *pECCSign);


