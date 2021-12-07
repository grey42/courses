#include <openssl/rsa.h>
#include <fcntl.h> //for pseudo-file opers
#include <unistd.h> //for pseudo-file opers

static int get_random_data(unsigned char* data, size_t length)
{
	int fp = open("/dev/urandom", O_RDONLY);
	if (fp < 0) return -1;
	if (length != read(fp, data, length)) {close(fp); return -1;}
	close (fp);
	return 0;
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

// Try different sizes: 4*1024, 8*1024, 16*1024
#define RSA_KEY_SIZE (1024)
#define RSA_KEY_SIZE_BYTES (RSA_KEY_SIZE/8)

int main(int argc, void** argv)
{
	(void)argc;
	(void)argv;

	RSA* rsa = NULL;
	BIGNUM* e = NULL;
	char* n_char = NULL;
	int ret = -1;

	rsa = RSA_new();
	if (!rsa) goto done;

	e = BN_new();
	if (!e) goto done;

	BN_set_word(e, 17);
	if (1 != RSA_generate_key_ex(rsa, RSA_KEY_SIZE, e, NULL)) goto done;
	
	const BIGNUM* n = RSA_get0_n(rsa);
	if (!n) goto done;
	
	n_char = BN_bn2hex(n);
	if (!n_char) goto done;

	printf("n: %s\n\n", n_char);

	// You should add your code here
	// Print d, p and q

	unsigned char random_data[RSA_KEY_SIZE_BYTES];
	unsigned char encrypted_data[RSA_KEY_SIZE_BYTES];

	if (0 != get_random_data(random_data, sizeof(random_data))) goto done;
	print_hex("plaintext", random_data, sizeof(random_data));
	
	if (RSA_KEY_SIZE_BYTES != RSA_public_encrypt(RSA_KEY_SIZE_BYTES, 
			random_data,
			encrypted_data,
			rsa,
			RSA_NO_PADDING)) goto done;
	print_hex("encrypted", encrypted_data, sizeof(encrypted_data));

	// You should add your code here
	// Decrypt the data and compare it with the origin 

	ret = 0;
done:
	OPENSSL_free(n_char);
	BN_free(e);
	RSA_free(rsa);
	return ret;
}
