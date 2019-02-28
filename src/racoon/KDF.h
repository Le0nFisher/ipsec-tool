#include "stdio.h"
#include "stdlib.h"



// Z_in 共享数据，Z_out输出长度为klen的密钥，v_len是HASH输出的长度。 z_input_len是输入Z_IN的长度（unsigned char）
//v_len是SM3算法的输出，长度为256，192，160可选,本部分采用256长,最多协商256*2长度的密钥
 //void KDF_ALGRITRHM(unsigned  char *Z_in,int z_input_len,int Klen,int v_len,unsigned char *Z_out);

  void KDF_ALGRITRHM(unsigned  char *Z_in,int z_input_len,int Klen,unsigned char *Z_out);
