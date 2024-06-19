#include "openssl/opensslv.h"
#include "openssl/crypto.h"

int func(int n)
{
	//RSA* rsa = RSA_generate_key(2048, 65537, 0, 0);
	//(void)rsa;
	return SSLeay();
}

/*void _start()
{
	func(2);
	asm("mov $60,%rax; mov $0,%rdi; syscall");
}*/
