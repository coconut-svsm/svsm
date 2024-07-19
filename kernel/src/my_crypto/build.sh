#!/bin/bash

gcc -mno-sse -mno-sse2 -mno-avx -fno-tree-vectorize -nostdlib -Ihacl/karamel/ -Ihacl/karamel/krmllib/dist/minimal -Ihacl/karamel/include/ -fPIC \
	 -c my_crypto.c  
gcc -mno-sse -mno-sse2 -mno-avx -fno-tree-vectorize -nostdlib -Ihacl/karamel/ -Ihacl/karamel/krmllib/dist/minimal -Ihacl/karamel/include/ -Ihacl/include -fPIC \
	-c hacl/Hacl_Curve25519_51.c
gcc -mno-sse -mno-sse2 -mno-avx -fno-tree-vectorize -nostdlib -Ihacl/karamel/ -Ihacl/karamel/krmllib/dist/minimal -Ihacl/karamel/include/ -Ihacl/include -fPIC \
	-c hacl/Hacl_Hash_SHA3.c

gcc -mno-sse -mno-sse2 -mno-avx -fno-tree-vectorize -nostdlib -Ihacl/karamel/ -Ihacl/karamel/krmllib/dist/minimal -Ihacl/karamel/include/ -Ihacl/include -fPIC \
	-c hacl/Hacl_NaCl.c
ar rcs libmy_crypto.a Hacl_Curve25519_51.o Hacl_NaCl.o Hacl_Hash_SHA3.o my_crypto.o 
cp libmy_crypto.a ../../../libmy_crypto/libmy_crypto.a 
