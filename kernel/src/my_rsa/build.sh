#!/bin/bash

gcc -nostdlib -c my_rsa.c
ar rcs libmy_rsa.a my_rsa.o
cp libmy_rsa.a ../../../libmy_rsa/libmy_rsa.a 
