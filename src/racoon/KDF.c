#include "KDF.h"
#include "SCH.h"

// Z_in 共享数据，Z_out输出长度为klen的密钥，v_len是HASH输出的长度。 z_input_len是输入Z_IN的长度（unsigned char）
//v_len是SM3算法的输出，长度为256，192，160可选,本部分采用256长,最多协商256*2长度的密钥
//void KDF_ALGRITRHM(unsigned  char *Z_in,int z_input_len,int Klen,int v_len,unsigned char *Z_out)

void KDF_ALGRITRHM(unsigned  char *Z_in,int z_input_len,int Klen,unsigned char *Z_out)
 {
	 int j;
	 int round_number;

	 unsigned char ct[4]={0x0,0x0,0x0,0x01};
unsigned char  aout_temp[z_input_len+4];
unsigned char  aout_hash[32];


unsigned char  bout_hash[32];


if((Klen%32)==0) round_number= Klen/32;
else	 round_number =(( Klen-(Klen%32))/32) +1;


 if(round_number==1)
{

for(j=0;j<z_input_len;j++)
{
aout_temp[j] =Z_in[j];
}
aout_temp[z_input_len] =ct[0];
aout_temp[z_input_len+1] =ct[1];
aout_temp[z_input_len+2] =ct[2];
aout_temp[z_input_len+3] =ct[3];
// algrithm( aout_temp,z_input_len+4,0,aout_hash);
SCH(aout_temp,z_input_len+4,2,aout_hash);
}




 
 if(round_number==2)
{

for(j=0;j<z_input_len;j++)
{
aout_temp[j] =Z_in[j];
}
aout_temp[z_input_len] =ct[0];
aout_temp[z_input_len+1] =ct[1];
aout_temp[z_input_len+2] =ct[2];
aout_temp[z_input_len+3] =0x1;
// algrithm( aout_temp,z_input_len+4,0,aout_hash);
SCH(aout_temp,z_input_len+4,2,aout_hash);

for(j=0;j<z_input_len;j++)
{
aout_temp[j] =Z_in[j];
}
aout_temp[z_input_len] =ct[0];
aout_temp[z_input_len+1] =ct[1];
aout_temp[z_input_len+2] =ct[2];
aout_temp[z_input_len+3] =0x2;
//algrithm( aout_temp,z_input_len+4,0,bout_hash);
SCH(aout_temp,z_input_len+4,2,bout_hash);
}




if((Klen%32)==0)
{ 
	if	(round_number==1)
	{
	for(j=0;j<Klen;j++)
Z_out[j] =aout_hash[j];	
	}
else if	(round_number==2)
{

	for(j=0;j<32;j++)
Z_out[j] =aout_hash[j];	
	for(j=32;j<Klen;j++)
Z_out[j] =bout_hash[j];	
}
}
else
{

if	(round_number==1)
	{
	for(j=0;j<Klen;j++)
Z_out[j] =aout_hash[j];	
	}
else if	(round_number==2)
{

	for(j=0;j<32;j++)
Z_out[j] =aout_hash[j];	
	for(j=32;j<Klen;j++)
Z_out[j] =bout_hash[j];	
}
}
}
