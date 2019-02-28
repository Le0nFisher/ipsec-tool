#include "bn_gcd.h"

//////////////////////////////////////////////
//                                          //
//  ��������:                               //
//      ����a��n�ĳ˷���                   //
//  ��������:                               //
//      a:in                                //
//      a_len:in,a���ֳ�                   //
//      n:in                                //
//      n_len:in,n���ֳ�                   //
//      in:out,a��n�ĳ˷���                  //
//      in_len:out,�˷�����ֳ�               //
//  ��������:                               //
//      ��                                   //
//                                          //
//////////////////////////////////////////////

void BN_mod_inverse_sm2(BN_ULONG *in, int *in_len, BN_ULONG *a, int a_len, BN_ULONG *n, int n_len)
{
    BN_ULONG *A, *B, *X, *Y, *M, *D, *T;
    BN_ULONG *R;
    int A_len, B_len, X_len, Y_len, M_len, D_len, T_len;
    int sign;
    int i;
    unsigned int x=0;

    //���ݲ���,A,B,X,D,M,Y���������64�ֽ�,
    //����BN_mul,BN_uadd��1�����,����A,B,X,D,M,Y�Ӵ���4�ֽ�

    A = (BN_ULONG *)malloc(80+4);
    B = (BN_ULONG *)malloc(80+4);
    X = (BN_ULONG *)malloc(80+4);
    D = (BN_ULONG *)malloc(80+4);
    M = (BN_ULONG *)malloc(80+4);
    Y = (BN_ULONG *)malloc(80+4);


    R = in;

    X_len = 0;
    Y[0] = 1; Y_len = 1;
    for(i = 0; i < a_len; i++)
        A[i] = a[i];
    A_len = a_len;
    for(i = 0; i < n_len; i++)
        B[i] = n[i];
    B_len = n_len;

    sign = 1;

    while (B_len)
    {
        x++;
        if(x>=200)
            printf("inverse:x=%d\n",x);
        BN_div_sm2(D, &D_len, M, &M_len, A, A_len, B, B_len);
        T = A; T_len = A_len;
        A = B; A_len = B_len;
        B = M; B_len = M_len;

        BN_mul_sm2(T, &T_len, D, D_len, X, X_len);
        BN_uadd_sm2(T, &T_len, T, T_len, Y, Y_len);

        M = Y; M_len = Y_len;
        Y = X; Y_len = X_len;
        X = T; X_len = T_len;
        sign = -sign;
    }
    if (sign < 0)
        BN_usub_sm2(Y, &Y_len, n, n_len, Y, Y_len);

    BN_div_sm2(NULL, NULL, R, in_len, Y, Y_len, n, n_len);

    free(A);
    free(B);
    free(X);
    free(D);
    free(M);
    free(Y);
}

