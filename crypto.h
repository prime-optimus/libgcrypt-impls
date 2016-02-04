#include <gcrypt.h>

#define CRYPTO_CYCLES 100

#define AES_128_KEY_SIZE 16

#define AES_256_KEY_SIZE 32

#define FILE_NAME_LENGTH 200

#define BUFFER_SIZE 16

char *key1024, *key4096;

double encryptionTimes[CRYPTO_CYCLES], decryptionTimes[CRYPTO_CYCLES];

void processSymmetricCrypto(int cipher, int keySize, char *fileName);

void processAsymmetricCrypto(char *fileName, int keySize, char* keyExpression);

void processHashFunction(char *fileName, int algo, int keySize);

void intializeFileNames(char *fileName, char* encryptedFileName, char* decryptedFileName);

void processDigitalSignature(char *fileName);
