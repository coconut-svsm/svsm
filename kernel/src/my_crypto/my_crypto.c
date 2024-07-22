#include "my_crypto.h"
#include "hacl/include/Hacl_Curve25519_51.h" 
#include "hacl/include/Hacl_NaCl.h"
#include "hacl/include/Hacl_Hash_SHA3.h"
#include <stdint.h>

key_pair monitor_keys;

key_pair* get_keys()
{
	return &monitor_keys;
}

key_pair* gen_keys() 
{
	// Generate private key
	// FIXME: Hardcode for now, generate later
//	int private_key[32] = {0x69, 0xC8, 0xAA, 0x3E, 0x1E, 0x2D, 0x40, 0xF4, 0x1D, 0xE9, 0x30, 0xB8, 0x39, 0x34, 
//			0x4B, 0xDE, 0x1A, 0xC9, 0xFA, 0xA6, 0x00, 0xC7, 0xE7, 0x76, 0x17, 0xA2, 0xD4, 0xC0, 0x48, 0xEF, 0xFB, 0xD1};

	for(int i = 0; i < 32; i += 4)
	{
		__builtin_ia32_rdrand64_step((unsigned long long*)(monitor_keys.private_key + i));
	}

	Hacl_Curve25519_51_secret_to_public(monitor_keys.public_key, monitor_keys.private_key);
	return &monitor_keys;
}

 unsigned int get_key_size()
{
	return 32;
}

uint32_t encrypt
(
  uint8_t* dst,
  uint8_t* src,
  uint32_t len,
  uint8_t* nonce,
  uint8_t* pub_key_recipient,
  uint8_t* priv_key_sender
)
{
	return Hacl_NaCl_crypto_box_easy(dst, src, len, nonce, pub_key_recipient, priv_key_sender);
}

uint32_t decrypt(
  uint8_t* dst,
  uint8_t* src,
  uint32_t len,
  uint8_t* nonce,
  uint8_t* pub_key_sender,
  uint8_t* priv_key_recipient
)
{
	return Hacl_NaCl_crypto_box_open_easy(dst, src, len, nonce, pub_key_sender, priv_key_recipient);
}

void my_SHA512(char* buff, const unsigned int buff_len, char* hash)
{
	Hacl_Hash_SHA3_sha3_512(hash, buff, buff_len);
}
