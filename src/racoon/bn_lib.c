#include "bn_lib.h"

int BN_is_zero_sm2(BN_ULONG *a, BN_ULONG al)
{
	BN_ULONG i;
	
	for(i = al-1; i > 0; i--)
		if( a[i] )
			return 0;
		return 1;
}

int BN_is_one_sm2(BN_ULONG *a, BN_ULONG al)
{
	BN_ULONG i = 0;
	
	if( a[i++] != 1)
		return 0;
	for(; i < al-1; i++)
		if( a[i] )
			return 0;
		return 1;
}

void bn_fix_top_sm2(BN_ULONG *a, int *al)
{
	if (*al > 0) 
	{ 
		for (; *al > 0; (*al)--) 
			if ( *(a+(*al)-1) ) break; 
	} 
}

int BN_num_bits_word_sm2(BN_ULONG l)
{
	int i = BN_BITS2;
	
	while( !(l & (1 << (i-1))) )
		i--;
	
	return i;				
}

/*
int BN_num_bits_sm2(BN_ULONG *a, int al)
{
BN_ULONG l;
int i;

  if (al == 0) return(0);
  l = a[al-1];
  i = (al-1) * BN_BITS2;
  return(i + BN_num_bits_word_sm2(l));
  }
*/

int BN_num_bits_sm2(BN_ULONG *a, int al)
{
	BN_ULONG l;
	int i, dwords;
	
    dwords = al;
	bn_fix_top_sm2(a, &dwords);
	
	if (dwords == 0) return(0);
	l = a[dwords-1];
	i = (dwords-1) * BN_BITS2;
	return(i + BN_num_bits_word_sm2(l));
}

int BN_ucmp_sm2(BN_ULONG *a, int al, BN_ULONG *b, int bl)
{
	int i;
	BN_ULONG t1, t2;
	
	i = al - bl;
	if (i != 0) return(i);
	for (i = al - 1; i >= 0; i--)
	{
		t1 = a[i];
		t2 = b[i];
		if (t1 != t2)
			return(t1 > t2 ? 1 : -1);
	}
	return(0);
}
