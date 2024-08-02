#ifndef __INCLUDE_MY_CRYPTO_H
#define __INCLUDE_MY_CRYPTO_H

#include <stdint.h>
#include <stdbool.h>

typedef struct _key_pair 
{
	uint8_t public_key[32];
	uint8_t private_key[32];
} key_pair;

unsigned long get_cycles();
key_pair* get_keys();
key_pair* gen_keys();
unsigned int get_key_size();

/**
Encrypt a message using the recipient's public key, the sender's secret key, and a nonce.

@param dst:	 				Pointer to 16 (tag length) + `len` bytes of memory where the authentication tag and ciphertext is written to.
@param src:	 				Pointer to `len` bytes of memory where the message is read from.
@param len: 				Length of the message.
@param nonce: 				Pointer to 24 (`crypto_box_NONCEBYTES`) bytes of memory where the nonce is read from.
@param pub_key_recipient: 	Pointer to 32 bytes of memory where the public key of the recipient is read from.
@param priv_key_sender:		Pointer to 32 bytes of memory where the secret key of the sender is read from.
*/

uint32_t encrypt
(
  uint8_t* dst,
  uint8_t* src,
  uint32_t src_len,
  uint8_t* nonce,
  uint8_t* pub_key_recipient,
  uint8_t* priv_key_sender
);

/**
Verify and decrypt a ciphertext produced by `crypto_box_easy`.

@param dst:	 				 Pointer to `len` - 16 (tag length) bytes of memory where the decrypted message is written to.
@param stc:	 				 Pointer to `len` bytes of memory where the ciphertext is read from. Note: the ciphertext must include the tag.
@param len:	 				 Length of the ciphertext.
@param nonce: 				 Pointer to 24 (`crypto_box_NONCEBYTES`) bytes of memory where the nonce is read from.
@param pub_key_sender: 		 Pointer to 32 bytes of memory where the public key of the sender is read from.
@param priv_key_recipient:	 Pointer to 32 bytes of memory where the secret key of the recipient is read from.
*/
uint32_t decrypt(
  uint8_t* dst,
  uint8_t* src,
  uint32_t src_len,
  uint8_t* nonce,
  uint8_t* pub_key_sender,
  uint8_t* priv_key_recipient
);

void my_SHA512(uint8_t* buff, const unsigned int buff_len, uint8_t* hash);
#endif
