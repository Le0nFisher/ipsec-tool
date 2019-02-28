#ifndef EC_GENERAL_H
#define EC_GENERAL_H

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

//#include <memory.h>
#include "bn_lib.h"
#include "bn_mont.h"
#include "ecp_smpl.h"
#include "ec_mult.h"


void ECC_InitParameter(ECCParameter *ECCPara,EC_GROUP *group, unsigned int BitLen);
void ECC_GenerateKeyPair(EC_GROUP *group, ECC_PUBLIC_KEY *pECCPK, ECC_PRIVATE_KEY *pECCSK);
int POINT_is_on_curve(EC_GROUP *group, ECCParameter *pECCPara, ECC_PUBLIC_KEY *pECCPoint);

#endif


