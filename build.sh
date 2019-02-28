#!/bin/sh

make clean

./configure --host=powerpc64-fsl-linux --with-openssl=/not/exist -enable-natt -enable-broken-natt -enable-dpd  CFLAGS="-fno-strict-aliasing -g -O0 -D_GNU_SOURCE -include ./src/include-glibc/glibc-bugs.h -I./src/include-glibc -I./src/include-glibc -Wno-sizeof-pointer-memaccess"

make 

