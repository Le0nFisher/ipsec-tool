#include "stdio.h"
#include "stdlib.h"



// Z_in �������ݣ�Z_out�������Ϊklen����Կ��v_len��HASH����ĳ��ȡ� z_input_len������Z_IN�ĳ��ȣ�unsigned char��
//v_len��SM3�㷨�����������Ϊ256��192��160��ѡ,�����ֲ���256��,���Э��256*2���ȵ���Կ
 //void KDF_ALGRITRHM(unsigned  char *Z_in,int z_input_len,int Klen,int v_len,unsigned char *Z_out);

  void KDF_ALGRITRHM(unsigned  char *Z_in,int z_input_len,int Klen,unsigned char *Z_out);
