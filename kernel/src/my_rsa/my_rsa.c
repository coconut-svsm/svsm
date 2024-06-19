// TODO: Change the include path to the 1.1.1 headers
#include <openssl/rsa.h>
#include <openssl/bn.h>

RSA* g_rsa;

int gen_RSA_keys(int bits)
{
	int i;
	g_rsa = RSA_new();
    BIGNUM *e = BN_new();

    if (g_rsa == NULL || e == NULL)
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
        //return rsa;
		return 1;
	}
 err:
    BN_free(e);
    RSA_free(g_rsa);
    return 0;
}

/************************************************
 * Return number of bytes for RSA key
 * or 0 if the RSA keys have not been initialized 
 * *********************************************/
int get_RSA_size()
{
	if(g_rsa == NULL) {
		return 0;
	}

	return RSA_size(g_rsa);
}
