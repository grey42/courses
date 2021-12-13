#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/obj_mac.h>
#include <string.h>

void sha256_string(const char* data, size_t data_len, unsigned char* hash)
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, data_len);
    SHA256_Final(hash, &sha256);
}

static void print_hex(const char* label, const unsigned char* b, size_t s)
{
        if (label) {
                printf ("%s: ", label);
        }
        if (b) {
                size_t i = 0;
                for (i = 0; i < s; ++i) {
                        printf("%02x",b[i]);
                }
                printf("\n\n");
        }
}

#define RSA_KEY_SIZE (4096)
#define RSA_KEY_SIZE_BYTES (RSA_KEY_SIZE/8)

int main(int argc, char** argv) {
	if (argc < 2) {
		printf ("You have to pass the string\n");
		return 1;
	}
	const char* data = argv[1];
	size_t data_len = strlen(argv[1]);
	unsigned char hash[SHA256_DIGEST_LENGTH] = {0};
	sha256_string(data, data_len, hash);

	RSA* rsa = NULL;
        BIGNUM* e = NULL;
        char* n_char = NULL;
        int ret = -1;

        rsa = RSA_new();
        if (!rsa) goto done;

        e = BN_new();
        if (!e) goto done;

        BN_set_word(e, 65537);
        if (1 != RSA_generate_key_ex(rsa, RSA_KEY_SIZE, e, NULL)) goto done;

        unsigned char signature[2*RSA_KEY_SIZE_BYTES];
	unsigned int siglen = sizeof(signature);
	if (1 != RSA_sign(NID_sha256, 
			hash, 
			SHA256_DIGEST_LENGTH, 
			signature,
			&siglen,
			rsa)) {
		goto done;
	}
        print_hex("signature", signature, siglen);

	// Add your code here to verify the signature
	// Try to change any byte of the message (and hash value) 
	// to be sure that algorithm works

done:
        OPENSSL_free(n_char);
        BN_free(e);
        RSA_free(rsa);
        return ret;
}

