/* kem-enc.c
 * simple encryption utility providing CCA2 security.
 * based on the KEM/DEM hybrid model. */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/sha.h>

#include "ske.h"
#include "rsa.h"
#include "prf.h"

static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Encrypt or decrypt data.\n\n"
"   -i,--in     FILE   read input from FILE.\n"
"   -o,--out    FILE   write output to FILE.\n"
"   -k,--key    FILE   the key.\n"
"   -r,--rand   FILE   use FILE to seed RNG (defaults to /dev/urandom).\n"
"   -e,--enc           encrypt (this is the default action).\n"
"   -d,--dec           decrypt.\n"
"   -g,--gen    FILE   generate new key and write to FILE{,.pub}\n"
"   -b,--BITS   NBITS  length of new key (NOTE: this corresponds to the\n"
"                      RSA key; the symmetric key will always be 256 bits).\n"
"                      Defaults to %lu.\n"
"   --help             show this message and exit.\n";

#define FNLEN 255

enum modes {
	ENC,
	DEC,
	GEN
};

/* Let SK denote the symmetric key.  Then to format ciphertext, we
 * simply concatenate:
 * +------------+----------------+
 * | RSA-KEM(X) | SKE ciphertext |
 * +------------+----------------+
 * NOTE: reading such a file is only useful if you have the key,
 * and from the key you can infer the length of the RSA ciphertext.
 * We'll construct our KEM as KEM(X) := RSA(X)|H(X), and define the
 * key to be SK = KDF(X).  Naturally H and KDF need to be "orthogonal",
 * so we will use different hash functions:  H := SHA256, while
 * KDF := HMAC-SHA512, where the key to the hmac is defined in ske.c
 * (see KDF_KEY).
 * */

#define HASHLEN 32 /* for sha256 */


int kem_encrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	/* TODO: encapsulate random symmetric key (SK) using RSA and SHA256;
	 * encrypt fnIn with SK; concatenate encapsulation and cihpertext;
	 * write to fnOut. */

	//encapsulate the key
	//call the rsa encrypty function

	// creating symmetric key.
	size_t len = rsa_numBytesN(K);
	unsigned char* x = malloc(len);
	//randBytes(x, len);
	SKE_KEY SK;
	// generating SK 	
	ske_keyGen(&SK, x, len);

	// 1- Encapsulate the above created SK with RSA encryption and SHA256
	
	
	// create outBuf
	size_t outBufLen = len +  HASHLEN;
	unsigned char* outBuf = malloc(outBufLen);	
	
	// RSA encryption of SK
	unsigned char* tempBuf;
	size_t rsa_encryption = rsa_encrypt(outBuf, x, len, K);
	
	// checking if rsaencryption is same as the rsalength
	if (rsa_encryption != len) {
		printf("RSA Encryption failed! Expected size: %u \n  Output size: %u\n", outBufLen, rsa_encryption);
	}
	//memcpy(outBuf, tempBuf, len);
	//for (int i =0; i<len; i++) {
	//	outBuf[i] = tempBuf[i];
	//}
	
	// open output file to write ciphertext from rsa_encrypt
	int output_file = open(fnOut, O_CREAT|O_RDWR|O_TRUNC, 0);
	//fwrite(outBuf, 1, len, output_file);
	
	
	// calculate SHA256

	//create SHABuf
	unsigned char* shaBuf = malloc(HASHLEN);
	SHA256(x, len , shaBuf);
	//memcpy(outBuf+rsa_encryption, shaBuf, HASHLEN);
	// write SHA256 of SK to output file
	//size_t kemFile; //= fwrite(outBuf, sizeof(unsigned char), outBufLen, output_file);
	
	if (write(output_file, outBuf, len)<0 ) {
	perror("open"); return 1;
	}

	if (write(output_file, shaBuf, HASHLEN)<0 ) {
	perror("open"); return 1;
	}
	close(output_file);
	/*
	for (int ch = 0; ch < len; ch++) {
	printf("pos %d char %c\n",ch,outBuf[ch]);
		fputc(outBuf[ch], output_file);
	}
	for (int ch = 0; ch < HASHLEN; ch++) {
	printf("pos %d char %c\n",ch,shaBuf[ch]);
		fputc(shaBuf[ch], output_file);
	}*/



	//size_t kemFile = fread(output_file, "r");
/*	if (outBufLen != kemFile) {
		printf("KEM Encryption unsuccessfull as failed to write: outbuflen: %u and kemFile: %u \n", outBufLen, kemFile);

		//return -1;
	}
*/
	
	//close output file
	//fclose(output_file);
	// free output buffer
	//free(outBuf);
	//free(shaBuf);
	

	// 2- Encrypt fnIn with SymmetricKey (SK)
	// what is char IV??
	/*FILE * o_file = fopen(fnOut, "wrb+");
	
	fwrite(outBuf, 1, len, o_file);
	fseek(o_file, len-1, SEEK_SET);

	fwrite(shaBuf, 1, HASHLEN, o_file);
	fclose(o_file);
*/
	size_t i;
	unsigned char IV[16];
	for (i = 0; i < 16; i++) IV[i] = i;
	size_t outputEncryption = ske_encrypt_file(fnOut, fnIn, &SK, IV, outBufLen);
	
	
	// RETURN 1 if encryption successful else RETURN 0
	return (outputEncryption == -1)? 0:1;
}

/* NOTE: make sure you check the decapsulation is valid before continuing */
int kem_decrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	/* TODO: write this. */
	/* step 1: recover the symmetric key */
	/* step 2: check decapsulation */
	/* step 3: derive key from ephemKey and decrypt data. */

	/* step 1: recover the symmetric key */
	// create inBuf and outBuf
	printf("Start dec\n");
	size_t len = rsa_numBytesN(K);
	//size_t inBufLen = (len > HASHLEN)? len: HASHLEN;
	size_t inBufLen = len + HASHLEN;
	unsigned char* inBuf = malloc(inBufLen);
	unsigned char* outBuf = malloc(len);

	// open fnIn to read the key encryption
	int inFile;
	struct stat fv;
	if ((inFile = open(fnIn, O_RDONLY, 0)) == -1){        
		perror("open");
		return 1;
	}	
	if(fstat(inFile, &fv) == -1){
		perror("fstat");
		return 1;
	}

	
	if (read(inFile, &inBuf, inBufLen)<0) {
	perror("read");
	return 1;
	}
	
	int inRead = fv.st_size;
	close(inFile);

	/*if (inRead != inBufLen) {
		printf("File size expected: %u \n Actual size: %u\n", inBufLen, inRead);	
	}*/
	printf("read the ct file\n");
		

	// decrypting fnIn contents with rsa_decrypt
	size_t rsa_decryption = rsa_decrypt(outBuf, inBuf, len, K);
	printf("rsa dec comp\n");
	if (rsa_decryption != len) {
		printf("RSA Decryption unsuccessfull\n");
		return -1;
	}
	

	// retireve SK from outBuf
	SKE_KEY SK;
	memcpy(&SK, outBuf, len); 
	
	
	/* step 2: check decapsulation */
	fread(inBuf, 1, HASHLEN, inFile);
	unsigned char* shaBuf = malloc(HASHLEN);	
	SHA256(outBuf, len, shaBuf);
	if (shaBuf != outBuf) {
		printf("encapsulation != decapsulation");
		fclose(inFile);
		free(outBuf);
		free(outBuf);		
	}

	fclose(inFile);
	free(inBuf);
	free(outBuf);

	/* step 3: derive key from ephemKey and decrypt data. */
	// ske_decrypt_file of fnIn
	
	size_t skeDecryption = ske_decrypt_file(fnOut, fnIn, &SK, inBufLen);


	return (skeDecryption == -1)? 0: 1;
}

int main(int argc, char *argv[]) {
	/* define long options */
	static struct option long_opts[] = {
		{"in",      required_argument, 0, 'i'},
		{"out",     required_argument, 0, 'o'},
		{"key",     required_argument, 0, 'k'},
		{"rand",    required_argument, 0, 'r'},
		{"gen",     required_argument, 0, 'g'},
		{"bits",    required_argument, 0, 'b'},
		{"enc",     no_argument,       0, 'e'},
		{"dec",     no_argument,       0, 'd'},
		{"help",    no_argument,       0, 'h'},
		{0,0,0,0}
	};
	/* process options: */
	char c;
	int opt_index = 0;
	char fnRnd[FNLEN+1] = "/dev/urandom";
	fnRnd[FNLEN] = 0;
	char fnIn[FNLEN+1];
	char fnOut[FNLEN+1];
	char fnKey[FNLEN+1];
	memset(fnIn,0,FNLEN+1);
	memset(fnOut,0,FNLEN+1);
	memset(fnKey,0,FNLEN+1);
	int mode = ENC;
	// size_t nBits = 2048;
	size_t nBits = 1024;
	while ((c = getopt_long(argc, argv, "edhi:o:k:r:g:b:", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'h':
				printf(usage,argv[0],nBits);
				return 0;
			case 'i':
				strncpy(fnIn,optarg,FNLEN);
				break;
			case 'o':
				strncpy(fnOut,optarg,FNLEN);
				break;
			case 'k':
				strncpy(fnKey,optarg,FNLEN);
				break;
			case 'r':
				strncpy(fnRnd,optarg,FNLEN);
				break;
			case 'e':
				mode = ENC;
				break;
			case 'd':
				mode = DEC;
				break;
			case 'g':
				mode = GEN;
				strncpy(fnOut,optarg,FNLEN);
				break;
			case 'b':
				nBits = atol(optarg);
				break;
			case '?':
				printf(usage,argv[0],nBits);
				return 1;
		}
	}

	/* TODO: finish this off.  Be sure to erase sensitive data
	 * like private keys when you're done with them (see the
	 * rsa_shredKey function). */
	
	switch (mode) {
		case ENC: {
			RSA_KEY K ;
			rsa_initKey(&K);
			FILE* keyFile = fopen(fnKey, "rb");
			rsa_readPublic(keyFile, &K);
			fclose(keyFile);
			//rsa_shredKey(K);
			kem_encrypt(fnOut, fnIn, &K);
			break;
			}
		case DEC: {

			RSA_KEY K ;
			rsa_initKey(&K);
			FILE* keyFile = fopen(fnKey, "rb");

			rsa_readPrivate(keyFile, &K);
			printf("Start dec\n");
			fclose(keyFile);

			kem_decrypt(fnOut, fnIn, &K);
			//rsa_shredKey(K);
			break;	
			}
		case GEN: {
			RSA_KEY K;
			FILE* private = fopen(fnOut, "wb");
			rsa_keyGen(nBits, &K);
			rsa_writePrivate(private, &K);

			char *pubExtension = ".pub";
			char *publicKeyFile = malloc(strlen(fnOut)+4+1);
			strcpy(publicKeyFile, fnOut);
			strcat(publicKeyFile, pubExtension);
			//printf("did concat\n");

			FILE* public = fopen(publicKeyFile, "wb");			
			rsa_writePublic(public, &K);

			fclose(private);
			fclose(public);
			//rsa_shredKey(K);
			break;
			}
	default:
			return 1;
	}

	

	return 0;
}
