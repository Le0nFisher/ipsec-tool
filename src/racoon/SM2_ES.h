#ifndef ECES_H
#define ECES_H

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
#include "ec_general.h"
#include "SCH.h"


int ECES_Encryption(EC_GROUP *group, unsigned char *e, int e_len, unsigned char *pRand, ECC_PUBLIC_KEY *pECCPK, unsigned char *pCodeOut);
int ECES_Decryption(EC_GROUP *group,unsigned char *pCodeIn, int c2_len , ECC_PRIVATE_KEY *pECCSK, unsigned char *e);


#endif

