#include "crypto.h"
#include <stdio.h>
#include <time.h>

void getCryptographyHandles(gcry_cipher_hd_t *handles, int algo, int keySize);

void encryptFile(gcry_cipher_hd_t handle, char *fileName, char *encryptedFileName, int keySize);

void decryptFile(gcry_cipher_hd_t handle, char *encryptedFileName, char *decryptedFileName, int keySize);

void releaseCryptographyHandles(gcry_cipher_hd_t *handles);

void processSymmetricCrypto(int cipher, int keySize, char *fileName) {
	char encryptedFileName[FILE_NAME_LENGTH], decryptedFileName[FILE_NAME_LENGTH];
	intializeFileNames(fileName, encryptedFileName, decryptedFileName);

	gcry_cipher_hd_t encryptionHandles[CRYPTO_CYCLES], decryptionHandles[CRYPTO_CYCLES];

	printf("Intializing encryption process..\n");
	getCryptographyHandles(encryptionHandles, cipher, keySize);
	getCryptographyHandles(decryptionHandles, cipher, keySize);
	printf("Done intializing encryption process..\n");

	int i;
	for (i = 0; i < CRYPTO_CYCLES; i++) {
		clock_t start = clock();

		encryptFile(encryptionHandles[i], fileName, encryptedFileName, keySize);
		clock_t encEnd = clock();

		double encTime = ((double)(encEnd - start))/CLOCKS_PER_SEC;
		printf("Cycle %2d; Encryption time: %.4f", i, encTime);
		encryptionTimes[i] = encTime;

		decryptFile(decryptionHandles[i], encryptedFileName, decryptedFileName,
				keySize);
		clock_t decEnd = clock();

		double decTime = ((double)(decEnd - encEnd))/CLOCKS_PER_SEC;
		printf(" Decryption Time: %.4f\n", decTime);
		decryptionTimes[i] = decTime;
	}

	printf("Releasing cryptograhic Handles..\n");
	releaseCryptographyHandles(encryptionHandles);
	releaseCryptographyHandles(decryptionHandles);
	printf("Done Releasing cryptographic Handles..\n");
}

void releaseCryptographyHandles(gcry_cipher_hd_t *handles){
	int i;
	for (i = 0; i < CRYPTO_CYCLES; i++) {
		gcry_cipher_close(handles[i]);
	}
}

void intializeFileNames(char *fileName, char* encryptedFileName, char* decryptedFileName) {
	strcpy(encryptedFileName, fileName);
	strcat(encryptedFileName, ".enc");

	strcpy(decryptedFileName, fileName);
	strcat(decryptedFileName, ".dec");
}

void getCryptographyHandles(gcry_cipher_hd_t *handles, int algo, int keySize){
	char *passkey = "passkeyfirst", *salt = "saltinhash";
	char *key = (char*) calloc(keySize, sizeof(char));

	int i=0;
	for(i=0; i<CRYPTO_CYCLES; i++){
		gcry_kdf_derive(passkey, strlen(passkey), GCRY_KDF_SCRYPT, GCRY_MD_SHA256,
						salt, strlen(salt), 5, keySize, key);

		gcry_cipher_open(&handles[i], GCRY_CIPHER_AES,	GCRY_CIPHER_MODE_CTR, 0);

		gcry_cipher_setkey(handles[i], key , keySize);
		passkey = key;
	}
	//free(key);
}

void encryptFile(gcry_cipher_hd_t handle, char *fileName, char *encryptedFileName, int keySize){
	FILE *toRead = fopen(fileName, "rb");
	FILE *toWrite = fopen(encryptedFileName,"wb");

	int readBufferSize = keySize * 100;
	char readString[readBufferSize];

	size_t l1;
	while ((l1 = fread(readString, 1, readBufferSize, toRead)) != 0) {
		while(l1<readBufferSize){
			readString[l1++] = 0x0;
		}
		gcry_cipher_encrypt(handle, readString, readBufferSize, NULL, 0);
		fwrite(readString, 1, readBufferSize, toWrite);
	}
	fclose(toRead);
	fclose(toWrite);
}

void decryptFile(gcry_cipher_hd_t handle, char *encryptedFileName, char * decryptedFileName, int keySize){
	FILE *toRead = fopen(encryptedFileName, "rb");
	FILE *toWrite = fopen(decryptedFileName,"wb");

	int readBufferSize = keySize * 100;
	char readString[readBufferSize];
	size_t l1;
	while ((l1 = fread(readString, 1, readBufferSize, toRead)) != 0) {
		gcry_cipher_decrypt(handle, readString, readBufferSize, NULL, 0);
		fwrite(readString, 1, readBufferSize, toWrite);
	}
	fclose(toRead);
	fclose(toWrite);
}

