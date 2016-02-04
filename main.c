#include <gcrypt.h>
#include <stdio.h>
#include <string.h>

#include "crypto.h"

void printReport(int reportBothTimes);

int main(int argc, char *argv[]) {
	if(argc != 2){
		printf("Missing input file Parameter.\nUsage: ./cryptogator <input_file_name>\n");
		return -1;
	}

	gcry_check_version(NULL);

	char fileName[FILE_NAME_LENGTH];
	strcpy(fileName, argv[1]);

	printf("\n*******************AES128**************************\n");
	int algo = GCRY_CIPHER_AES128;
	int keyLength = gcry_cipher_get_algo_keylen(algo);
	processSymmetricCrypto(algo, keyLength, fileName);
	printReport(1);

	printf("\n*******************AES256**************************\n");
	algo = GCRY_CIPHER_AES256;
	keyLength = gcry_cipher_get_algo_keylen(algo);
	processSymmetricCrypto(algo, keyLength, fileName);
	printReport(1);

	printf("\n*******************HMAC MD5**************************\n");
	algo = GCRY_MAC_HMAC_MD5;
	keyLength = gcry_mac_get_algo_maclen(algo);
	processHashFunction(fileName, algo, keyLength);
	printReport(0);

	printf("\n*******************HMAC SHA1**************************\n");
	algo = GCRY_MAC_HMAC_SHA1;
	keyLength = gcry_mac_get_algo_maclen(algo);
	processHashFunction(fileName, algo, keyLength);
	printReport(0);

	printf("\n*******************HMAC SHA256**************************\n");
	algo = GCRY_MAC_HMAC_SHA256;
	keyLength = gcry_mac_get_algo_maclen(algo);
	processHashFunction(fileName, algo, keyLength);
	printReport(0);
	
	printf("\n*******************Digital Signature**************************\n");
	processDigitalSignature(fileName);

	printf("\n*******************RSA1024**************************\n");
	processAsymmetricCrypto(fileName, 1024, key1024);
	printReport(1);

	printf("\n*******************RSA4096**************************\n");
	processAsymmetricCrypto(fileName, 4096, key4096);
	printReport(1);

	

	/*char *data = "This is an encryption test.";

	gcry_sexp_t pub_key, plainText, cipherText, decryptedText;
	gcry_sexp_sscan(&pub_key, NULL, key, strlen(key));

	gcry_sexp_build (&plainText, NULL, "(data (flags raw) (value %b))", strlen(data), data);
	int response = gcry_pk_encrypt (&cipherText, plainText, pub_key);

	printf("%s\n", gcry_sexp_nth_string(gcry_sexp_find_token(cipherText, "a", 1), 1));

	gcry_pk_decrypt(&decryptedText, cipherText, pub_key);

	printf("%s\n", gcry_sexp_nth_string(decryptedText, 0));
	printf("done");


	gcry_sexp_t rsa_parms;
	gcry_sexp_t rsa_keypair;

	printf("generating key\n");

	time_t start = time(NULL);
	gcry_error_t err = gcry_sexp_build(&rsa_parms, NULL, "(genkey (rsa (nbits 4:4096)))");
	err = gcry_pk_genkey(&rsa_keypair, rsa_parms);

	size_t keyLength = get_keypair_size(4096);
	char* rsaKeyExpression = (char*) calloc(sizeof(char), keyLength);

	gcry_sexp_sprint(rsa_keypair, GCRYSEXP_FMT_ADVANCED, rsaKeyExpression, keyLength);
	printf("%s\n", rsaKeyExpression);

	time_t end = time(NULL);
	double encTime = (double) ((end - start));
	printf("Time: %.2f\n", encTime);

	printf("generated key\n");
		*/
}
int cmp(const void *x, const void *y) {
  double xx = *(double*)x, yy = *(double*)y;
  return xx<yy ? -1 : 1;
}
void printReport(int reportBothTimes){
	qsort(encryptionTimes, CRYPTO_CYCLES, sizeof(double), cmp);
	double median = encryptionTimes[CRYPTO_CYCLES/2], total=0;

	int i=0;
	for(i=0; i<CRYPTO_CYCLES; i++){
		total+=encryptionTimes[i];
	}
	double mean = total/CRYPTO_CYCLES;

	printf("\n..............Results..................\n");
	printf("%s: Mean-Time=%.4f Median-Time=%.4f\n",reportBothTimes? "Encryption" : "Hashing" ,mean, median);

	if(reportBothTimes){
		qsort(decryptionTimes, CRYPTO_CYCLES, sizeof(double), cmp);
		total=0;;
		for(i=0; i<CRYPTO_CYCLES; i++){
			total+=decryptionTimes[i];
		}
		median = decryptionTimes[CRYPTO_CYCLES/2];
		mean = total/CRYPTO_CYCLES;

		printf("Decryption: Mean-Time=%.4f Median-Time=%.4f\n\n",mean, median);
	}

}




