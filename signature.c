#include <gcrypt.h>
#include <stdio.h>
#include "crypto.h"

void processDigitalSignature(char *fileName) {
	int keySize = gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA256);

	char *passkey = "passkeyfirst", *salt = "saltinhash";
	char *key = (char*) calloc(keySize, sizeof(char));

	gcry_mac_hd_t handle;

	gcry_kdf_derive(passkey, strlen(passkey), GCRY_KDF_SCRYPT, GCRY_MD_SHA256,
			salt, strlen(salt), 5, keySize, key);

	gcry_mac_open(&handle, GCRY_MAC_HMAC_SHA256, 0, NULL);

	gcry_mac_setkey(handle, key, keySize);

	char *hash = (char*) calloc(keySize, sizeof(char));
	hashFile(handle, fileName, NULL, keySize, hash);

	gcry_sexp_t plainText, cipherText, asymmetricKey;
	gcry_sexp_sscan(&asymmetricKey, NULL, key4096, strlen(key4096));
	gcry_sexp_build(&plainText, NULL, "(data (flags raw) (value %b))", keySize, hash);
	gcry_pk_sign(&cipherText, plainText, asymmetricKey);

	char buffer[10000];
	gcry_mpi_t result = gcry_sexp_nth_mpi(gcry_sexp_find_token(cipherText, "s", 1),	1, GCRYMPI_FMT_USG);
	gcry_mpi_print(GCRYMPI_FMT_HEX, buffer, 10000, NULL, result);
	printf("\nDigital Signature : %s\n", buffer);
}
