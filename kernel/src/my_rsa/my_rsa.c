// TODO: Change the include path to the 1.1.1 headers
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

RSA* g_rsa;

typedef struct _RSA_key {
	char* key;
	unsigned int size;
} RSA_key;

RSA_key* g_pub_key;


int gen_RSA_keys(int bits)
{
	int i;
	g_rsa = RSA_new(); // FIXME: Free when shutting down
    BIGNUM *e = BN_new();
	BIO* pub_key_bio = BIO_new(BIO_s_mem());

	g_pub_key = (RSA_key*)malloc(sizeof(RSA_key)); // FIXME: Free when shutting down

    if (g_rsa == NULL || e == NULL || pub_key_bio == NULL || g_pub_key == NULL)
        goto err;

    /*
     * The problem is when building with 8, 16, or 32 BN_ULONG, unsigned long
     * can be larger
     */
    for (i = 0; i < (int)sizeof(unsigned long) * 8; i++) {
            if (BN_set_bit(e, i) == 0)
                goto err;
    }

	// TODO: Check the exponent
    if (RSA_generate_key_ex(g_rsa, bits, e, NULL)) {
        BN_free(e);

		// get public key
		PEM_write_bio_RSAPublicKey(pub_key_bio, g_rsa);
		const int keylen = BIO_pending(pub_key_bio);
		g_pub_key->key = (char*)malloc(keylen); // FIXME: Free when shutting down
		g_pub_key->size = keylen;
		BIO_read(pub_key_bio, (void*)g_pub_key->key, keylen); 
		BIO_free(pub_key_bio);
		return keylen;
	}
 err:
    BN_free(e);
    RSA_free(g_rsa);
	BIO_free(pub_key_bio);
    return 0;
}

int RSA_encrypt(int flen, const unsigned char* from, unsigned char *to)
{
	return RSA_public_encrypt(flen, from, to, g_rsa, RSA_PKCS1_OAEP_PADDING);
}

int RSA_decrypt(int flen, const unsigned char* from, unsigned char *to)
{
	return RSA_private_decrypt(flen, from, to, g_rsa, RSA_PKCS1_OAEP_PADDING);
}

/************************************************
 * Return number of bytes for RSA chunk
 * or 0 if the RSA keys have not been initialized 
 * *********************************************/
int get_RSA_size()
{
	if(g_rsa == NULL) {
		return 0;
	}

	return RSA_size(g_rsa);
}


RSA_key* get_RSA_public_key()
{
	return g_pub_key;
}
