
#ifndef BN_H
#define BN_H

#include <stdlib.h>
#include <string.h>

#ifndef BN_ULONG
#define BN_ULONG	unsigned int
#endif

#ifndef BN_BITS
#define BN_BITS		64
#endif

#ifndef BN_BYTES
#define BN_BYTES	4
#endif

#ifndef BN_BITS2
#define BN_BITS2	32
#endif

#ifndef BN_BITS4
#define BN_BITS4	16
#endif

#ifndef BN_BITS8
#define BN_BITS8	8
#endif

#ifndef BN_MASK2
#define BN_MASK2	(0xffffffffL)
#endif

#ifndef BN_MASK2l
#define BN_MASK2l	(0xffff)
#endif

#ifndef BN_MASK2h
#define BN_MASK2h	(0xffff0000L)
#endif

#ifndef BN_TBIT
#define BN_TBIT		(0x80000000L)
#endif

#endif

