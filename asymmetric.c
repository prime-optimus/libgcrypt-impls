#include "crypto.h"
#include <time.h>
#include <stdio.h>

char *key1024 =
		"(key-data\n"
				" (public-key\n"
				"  (rsa\n"
				"   (n\n" "#00D3331FAB2AEDB55EB53A3F596D85F48F8DBB3899B615EA2AC00E4E3061F7FF583924ABECD402A458F2C428C5AE37E4F9C105BE5E996ED599F8AD7A58A29E651E9BFFFCDFB19E0D80D5D7B97713EC8EDD7A8A2CB40C87512A390CA002A4B87DBF6142FCE827FBB836F4B0AEBBF3C3DD4EADF1397FCFDF3C67CD1376F440A4CAC3#)\n"
				"   (e #010001#)\n"
				"   )\n"
				"  )\n"
				" (private-key\n"
				"  (rsa\n"
				"   (n\n" "#00D3331FAB2AEDB55EB53A3F596D85F48F8DBB3899B615EA2AC00E4E3061F7FF583924ABECD402A458F2C428C5AE37E4F9C105BE5E996ED599F8AD7A58A29E651E9BFFFCDFB19E0D80D5D7B97713EC8EDD7A8A2CB40C87512A390CA002A4B87DBF6142FCE827FBB836F4B0AEBBF3C3DD4EADF1397FCFDF3C67CD1376F440A4CAC3#)\n"
				"   (e #010001#)\n"
				"   (d\n" "#06B4CBDFA28853C703182B64CA8E835A7F949F527A2EADF5D78D5CBC3A90266285C5FD5392D3D6A620674C2822C5119740A2CF0DAFEF8E06CA97AF97DAEA0EA9E060CC571E357D449F13CA4D4E872D393330E19B950BB9F0C88A80C610B033688050E58EA629DA454E3C4132031B88FB7C93662EC45A267D918D834E585A12E9#)\n"
				"   (p #00DF46E1E4CD1A99943CC23C51C7832EF189A2EE3A5051052E0BB1AAF812042342F2372F70B116363B03302E574D45A1273A542DAC551E60EFA971E6D7F8E6042D#)\n"
				"   (q #00F2271E305679EBF9D7673FBF75EEA22E90D100A9E0B5DE30C500411E91710D05826F17F2C33A9527CC6799553C626C015ED666F63A4D5CEB27CDBE61F34DB0AF#)\n"
				"   (u #00BC9D8FD5D0AC1C91C04A1E0A5B6A89229924AAD20E23C5F5E3FE702C3C4633E325D2084DC0CE2005A88FF0512E0CACC271DF3279865DC2C33FCF573F7788278E#)\n"
				"   )\n"
				"  )\n"
				"\n )";

char *key4096 = "(key-data "
			 "(public-key"
			  "(rsa"
			   "(n #00C567CF0A48FD99EAFC291A1DAE60584284F318C506E209A46C9B6FC09C3375D26E70F70610F784EF2622A85478A588EFCD8142DA3F1CA49AFBA3C368D1E4C54066A85B77A63BBAC1BCB4E7D09CACE30DEBA060157F874D7E20EE36265182C56E5B191B3DAD61B8099D1C645CBEB2202788671AD5BD572192429BF0C5BC8ECF8A682FA37BA59E8D79B79F36F2C687821DE60B7DDB363F0E9F6946EC4532123CEFE0F53711CA2359474A612793F4598AAC97ED4CAB25F9E5CC026F9396380A59BA5C0D4AB11544AA9A5F05A73FC4E53A7E56DEE3B3C17F1B09113A62BFACF4AB82802A85EC02698BA27F4D72AF6896DC5FE2A7011DF998E78C6312B70E3B3FC1705CBB33C07C84399AFCC5C96E8A4941F8693916C50D29581939FB4FE539C09AB949D87729398845676417A1E75654A546FD36981E83DA70C1ECB41BD703155F65C9489563EB6E040CCF5A098B420B83390204E10D3E66DC99829743F0E650629AD9C6991348A24F831F2CCFB1F7B4E687304C946F7FF29B4FF4F701248F86D76F3347094F5EDF543F0EA0C7078AE7BF91DA6E4E968A5D01E0FBA584851ACCE8DD6E6862B1FADABE48FF825AFEB631B7593AD9AB51A20D5D980480888B61801689AD434CD68FC84974D1CBE2B04FE010A6D0C8C24EB843696C182952BE991C90DE016A9D4C12C90ED36360CCFABDC74EC59D2B06331F8CC7322619DF8EE6EE2957#)"
			   "(e #010001#)"
			   ")"
			  ")"
			 "(private-key"
			  "(rsa"
			   "(n #00C567CF0A48FD99EAFC291A1DAE60584284F318C506E209A46C9B6FC09C3375D26E70F70610F784EF2622A85478A588EFCD8142DA3F1CA49AFBA3C368D1E4C54066A85B77A63BBAC1BCB4E7D09CACE30DEBA060157F874D7E20EE36265182C56E5B191B3DAD61B8099D1C645CBEB2202788671AD5BD572192429BF0C5BC8ECF8A682FA37BA59E8D79B79F36F2C687821DE60B7DDB363F0E9F6946EC4532123CEFE0F53711CA2359474A612793F4598AAC97ED4CAB25F9E5CC026F9396380A59BA5C0D4AB11544AA9A5F05A73FC4E53A7E56DEE3B3C17F1B09113A62BFACF4AB82802A85EC02698BA27F4D72AF6896DC5FE2A7011DF998E78C6312B70E3B3FC1705CBB33C07C84399AFCC5C96E8A4941F8693916C50D29581939FB4FE539C09AB949D87729398845676417A1E75654A546FD36981E83DA70C1ECB41BD703155F65C9489563EB6E040CCF5A098B420B83390204E10D3E66DC99829743F0E650629AD9C6991348A24F831F2CCFB1F7B4E687304C946F7FF29B4FF4F701248F86D76F3347094F5EDF543F0EA0C7078AE7BF91DA6E4E968A5D01E0FBA584851ACCE8DD6E6862B1FADABE48FF825AFEB631B7593AD9AB51A20D5D980480888B61801689AD434CD68FC84974D1CBE2B04FE010A6D0C8C24EB843696C182952BE991C90DE016A9D4C12C90ED36360CCFABDC74EC59D2B06331F8CC7322619DF8EE6EE2957#)"
			   "(e #010001#)"
			   "(d #032B961F1FA9F6F957A05F5B7FABEB6EF20CA766AEA41DAC86D3FE38F5293C68AB3E6431343F8D627BD5CDA741A2C2EEBAF9AAF5AF52C9EFF53F9D8946E9AA234D22C2094B61A52FAC54A96E67BDBD0DC1AD7B2D8D354290D67D8CE013AA0A7AA9BADEFDA015B42B6F5AFFDF9F6E63E6CEA17D44567C9A3CEB95EE89766C42B801D1560A4BD01E8C885EE5B6836AB4B3BF388B0664BA21857CDED7378B44D0B6B781A8A73FFC4E583F410D2E2A9BEF86B30FEC0DC997D8516CEE96CBB04DB640306F443650D59FF9C7B1E30C3AA0C5CE369DF0C137C7CF4AD77C7D0E7FFC13EF0E18E0BAB81532D962BAFF2F02FA7D428AF4CCA74B15620E969EBBD2DE2FB96F09C847E61F727CC7D54B1749EF566299B688DD24569B844A9EE47B55759990864377B284525D152B87F0DB0789BFF2FBFD7D2A71A16C1C6FEDA25B7A3B75B5406D881451D728E4D2BE572E2AEADBA03877CE1AE5FF3C608B050A72C35761CBF1855AED2162E5993403DEB4A56FD892282491C1173E6D81CD70F9C1890F35E5F3B2D7F8BC8353466842276123753AAFAB06B5A8A704CA6E2AC1607335960E1A63E4553CB752AA281AABEEAF443D19DB01E43F5FDECEF4E96572C53CF21F8BA9918D7A4D6A17B767DAEF3AE424C88AF63A297EE1657E24B5CF3F7A23B0127FD3C94227A877009317AAA6FAE86CA265903CEE9047F69C1E4628F03AAD75B1E230D9#)"
			   "(p #00D02BC8A9CFBEEDADA43581BA39914C4793ABAEA60B0AF7FA450080F88E47085C2DA5E0F8DB91911D9050C149D4894A64E400D47BC67C57D77265BC50FD96BC61929088B9BEB57DEC80781024CB7FA565A487B04FBFB7FE3C6987B4ACB2A8203F2443B79A6EC56D083B9943C306D0ACAF561DA87D1FC588CF47B249EB2A76024BC5A190DECE31B68533324D6B9470DC8E0887FCBAD3D74C99DFBF3DFD790EED2B8CE7896D012777B0AC5E47D85C138B1B3A0D38964C202BCCCA01C42CCB022602D77E56A446BF3A3E826AAAF6DE00E878321A29334BC69DBBC5B73593547486DE2AB0D6273672533711DC6D2AF8240104E9F2D805F19D249FF34D2DFFE3CA2769#)"
			   "(q #00F2C2D144CDF1DFBBB57EFDA2683BED65A4A4F506235AD7C1C144B1FE903A2E12AEFF25B0B33D3B9E52A62B8E5BDA7FFD970B37191A967078246058539100786B080456A0543051AD386704EE0ECC4DB05571D4A715C2809F99DBEBBEC12F0D22994F32A28EF39A368600252243B5A58AD099C8506135A6A47C54C42909DD598DC50BD9DB732D608BA0E6AE6E063D442240E3AD83500358CE17598BB855CEE6A818EDAEB0832164CC1FBB8F1827BF0B1A4ECF94DC7501A9602AA3CE9E701D1B294D3B1387FDFFCC9B1BBC56927B8A9197A424F4B6D69BB2864B8A84BBD2BA363F17CF6572AF5171DA2F541DC3A76DE1C27370F7D74C9C811342568F2C2D5E72BF#)"
			   "(u #7AB559FA5F6A1DEB6671BDA0AB9E96C289C35C529763A4A9D9E8DE3DD313D86F2BF3C37469460E4720FFCA51A86D553DAAA121E3B29AEFF83BD9B580260F6E80CB2957127306B24472E846409FBB4B8F890DA2B7C789A0B6E4635791B8BB45C450383D1D4D60A5F1EBD171B5AE486300B4B52EA4E16A774034CBEC6A9444045BAED077339395FB04B60A0D598021C0CE7445EDFD6A42184B0AD992DDAED906EBBD6CE3AAE47E56875BB438EA1F2F95701804B700296FAF3D7C092F9C3F3644F52E83C6FF53E9D3684C2FE474928E404170FBA9F09D0AFA4321A401A23A385AFA861867A395F2215AD68ABE546BD7D0D1C9A05D5A9CA666876320A966133AF0E8#)"
			   ")"
			  ")"
			 ")";

void encryptAsymmetric(gcry_sexp_t pub_key, char *fileName, char *encryptedFileName, int keySize) {
	gcry_sexp_t plainText, cipherText;

	FILE *toRead = fopen(fileName, "rb");
	FILE *toWrite = fopen(encryptedFileName, "wb");

	int readBufferSize = keySize/8;
	char readString[readBufferSize];

	size_t l1;
	while ((l1 = fread(readString, 1, readBufferSize, toRead)) != 0) {
		gcry_sexp_build(&plainText, NULL, "(data (flags raw) (value %b))", l1, readString);
		gcry_pk_encrypt(&cipherText, plainText, pub_key);

		/*char buffer1[10000];
		gcry_sexp_sprint(cipherText, GCRYSEXP_FMT_ADVANCED, buffer1, 10000);
		printf("CipherText : %s\n", buffer1);*/


		gcry_mpi_t result = gcry_sexp_nth_mpi(gcry_sexp_find_token(cipherText, "a", 1),	1, GCRYMPI_FMT_USG);

		char buffer[10000];
		gcry_mpi_print(GCRYMPI_FMT_STD, buffer, 10000, NULL, result);

		fwrite(buffer, 1, readBufferSize, toWrite);

		gcry_sexp_release(plainText);
		gcry_sexp_release(cipherText);
	}
	fclose(toRead);
	fclose(toWrite);
}

void decryptAsymmetric(gcry_sexp_t pub_key, char *encryptedFileName, char *decryptedFileName, int keySize) {
	gcry_sexp_t cipherText, decryptedText;
	gcry_mpi_t cipher;

	FILE *toRead = fopen(encryptedFileName, "rb");
	FILE *toWrite = fopen(decryptedFileName, "wb");

	int readBufferSize = keySize/8;
	char readString[readBufferSize];

	size_t l1;
	while ((l1 = fread(readString, 1, readBufferSize, toRead)) != 0) {
		gcry_mpi_scan(&cipher, GCRYMPI_FMT_USG, readString, l1, NULL);
		gcry_sexp_build(&cipherText, NULL, "(enc-val (rsa (a %M)))", cipher);

		/*char buffer[10000];
		gcry_sexp_sprint(cipherText, GCRYSEXP_FMT_ADVANCED, buffer, 10000);
		printf("CipherText : %s\n", buffer);*/

		gcry_pk_decrypt(&decryptedText, cipherText, pub_key);

		char *result = gcry_sexp_nth_string(decryptedText, 0);
		fwrite(result, 1, readBufferSize, toWrite);
		//printf("result: %s", result);

		gcry_mpi_release(cipher);
		gcry_sexp_release(cipherText);
		gcry_sexp_release(decryptedText);
		free(result);
	}
	fclose(toRead);
	fclose(toWrite);
}


void processAsymmetricCrypto(char *fileName, int keySize, char* keyExpression){
	char encryptedFileName[FILE_NAME_LENGTH], decryptedFileName[FILE_NAME_LENGTH];
	intializeFileNames(fileName, encryptedFileName, decryptedFileName);

	gcry_sexp_t asymmetricKey;
	gcry_sexp_sscan(&asymmetricKey, NULL, keyExpression, strlen(keyExpression));

	int i, cycles = CRYPTO_CYCLES;
	for (i = 0; i < cycles; i++) {
		clock_t start = clock();

		encryptAsymmetric(asymmetricKey, fileName, encryptedFileName, keySize);
		clock_t encEnd = clock();

		double encTime = ((double)(encEnd - start))/CLOCKS_PER_SEC;
		printf("Cycle %2d; Encryption time: %.4f", i, encTime);
		encryptionTimes[i] = encTime;

		decryptAsymmetric(asymmetricKey,encryptedFileName, decryptedFileName, keySize);
		clock_t decEnd = clock();

		double decTime = ((double)(decEnd - encEnd))/CLOCKS_PER_SEC;
		printf(" Decryption Time: %.4f\n", decTime);
		decryptionTimes[i] = decTime;
	}

}

