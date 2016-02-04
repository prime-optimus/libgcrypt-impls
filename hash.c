#include <gcrypt.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "crypto.h"

void hashFile(gcry_mac_hd_t handle, char *fileName, char *hashFileName, int keySize, char *hashValue);

void realeseHashingHandles(gcry_mac_hd_t *handles);

void getHashingHandles(gcry_mac_hd_t *handles, int algo, int keySize){
	char *passkey = "passkeyfirst", *salt = "saltinhash";
	char *key = (char*) calloc(keySize, sizeof(char));

	int i=0;
	for(i=0; i<CRYPTO_CYCLES; i++){
		gcry_kdf_derive(passkey, strlen(passkey), GCRY_KDF_SCRYPT, GCRY_MD_SHA256,
						salt, strlen(salt), 5, keySize, key);
		gcry_mac_open(&handles[i], algo, 0, NULL);

		gcry_mac_setkey(handles[i], key , keySize);
		passkey = key;
	}
}

void processHashFunction(char *fileName, int algo, int keySize){
	gcry_mac_hd_t hashHandles[CRYPTO_CYCLES];

	char hashFileName[FILE_NAME_LENGTH], decryptedFileName[FILE_NAME_LENGTH];
	intializeFileNames(fileName, hashFileName, decryptedFileName);

	printf("intializing hashing process..\n");
	getHashingHandles(hashHandles, algo, keySize);
	printf("Done intializing hashing process..\n");

	int i;
	for (i = 0; i < CRYPTO_CYCLES; i++) {
		clock_t start = clock();

		printf("Cycle %2d; ", i);
		hashFile(hashHandles[i], fileName, hashFileName, keySize, NULL);
		clock_t encEnd = clock();

		double encTime = ((double)(encEnd - start))/CLOCKS_PER_SEC;
		printf(" Hashing-time: %.4f\n", encTime);
		encryptionTimes[i] = encTime;
	}

	printf("Releasing Hashing Handles..\n");
	realeseHashingHandles(hashHandles);
	printf("Done releasing Hashing Handles..\n");
}
void realeseHashingHandles(gcry_mac_hd_t *handles){
	int i=0;
	for (i=0; i<CRYPTO_CYCLES; i++){
		gcry_mac_close(handles[i]);
	}
}
void hashFile(gcry_mac_hd_t handle, char *fileName, char *hashFileName, int keySize, char *hashValue){
	FILE *toRead = fopen(fileName, "rb");


	int readBufferSize = keySize;
	char readString[readBufferSize];

	size_t l1;
	while ((l1 = fread(readString, 1, readBufferSize, toRead)) != 0) {
		gcry_mac_write(handle, readString, l1);
	}

	gcry_mac_read(handle, &readString, &l1);

	printf("Hash: ");
	int i=0;
	for ( i = 0; i < strlen(readString); i++ ) {
	      printf("%02x", readString[i]);
	}

	if(hashValue != NULL){
		strcpy(hashValue, readString);
	}

	if(hashFileName != NULL){
		FILE *toWrite = fopen(hashFileName,"wb");
		fwrite(readString, 1, strlen(readString), toWrite);
		fclose(toWrite);
	}

	fclose(toRead);

}
