/* kem-enc.c
 * simple encryption utility providing CCA2 security.
 * based on the KEM/DEM hybrid model. */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

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
{/* TODO: encapsulate random symmetric key (SK) using RSA and SHA256;
	 * encrypt fnIn with SK; concatenate encapsulation and cihpertext;
	 * write to fnOut. */

	// 1- creating symmetric key.
	size_t len = rsa_numBytesN(K);
	unsigned char* x = malloc(len);
	SKE_KEY SK;
	// generating SK 	
	ske_keyGen(&SK, x, len);


	// 2- Encapsulate the above created SK with RSA encryption and SHA256
	// create outBuf
	size_t outBufLen = len +  HASHLEN;
	unsigned char* outBuf = malloc(len);
	FILE* output_file = fopen(fnOut, "w");
	
	// RSA encryption of SK
	memset(outBuf,0,len);
	size_t rsa_encryption = rsa_encrypt(outBuf, (unsigned char*)&SK, sizeof (SKE_KEY), K);
	
	// checking if rsaencryption is same as the rsalength
	if (rsa_encryption != len) {
	  printf("RSA Encryption failed! Expected size: %d \n  Output size: %d\n",(int) outBufLen,(int) rsa_encryption);
	  exit(3);
	}
	
	// open output file to write ciphertext from rsa_encrypt
	fwrite(outBuf, sizeof(unsigned char), rsa_encryption, output_file);
	
	
	// 3- calculate SHA256
	//create SHABuf
	unsigned char* shaBuf = malloc(HASHLEN);
	SHA256((unsigned char *) &SK, sizeof(SKE_KEY), shaBuf);

	// write SHA256 of SK to output file
	size_t kemFile = fwrite(shaBuf, sizeof(unsigned char), HASHLEN, output_file);
	
	// checking if KEM Encryption is same as HASHLEN
	if (HASHLEN != kemFile) {
		printf("KEM Encryption unsuccessfull as failed to write\n");
		return -1;
	}
	
	
	// close output file
	fclose(output_file);
	// free buffers
	free(outBuf);
	free(shaBuf);
	

	// 4- Encrypt fnIn with SymmetricKey (SK)
	size_t outputEncryption = ske_encrypt_file(fnOut, fnIn, &SK, NULL, outBufLen);
	
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
  	size_t len = rsa_numBytesN(K);
	size_t skeLen = sizeof(SKE_KEY);
	
	unsigned char* wholeBuf = malloc(len + HASHLEN);	
	unsigned char* rsaBuf1 = malloc(len+1);
	unsigned char* rsaBuf = malloc(len);	
	unsigned char* shaBuf = malloc(HASHLEN);

	// open fnIn to read the key encryption
	FILE* inFile = fopen(fnIn, "r");
       
	size_t sz = fread(rsaBuf1,1,len, inFile);

	if (sz != len) {printf("fread file  error\n"); exit (3);}
	
	// decrypting fnIn contents with rsa_decrypt
	memset(rsaBuf,0,len);
    rsa_decrypt(rsaBuf, rsaBuf1, len, K);	    

	// retireve SK from outBuf
	SKE_KEY SK;
	memcpy(&SK, rsaBuf, skeLen);
	
	// retrive hash
	fread(shaBuf,1,HASHLEN,inFile);
	
	
	/* step 2: check decapsulation */
	unsigned char * tempBufHash = malloc(HASHLEN);
	SHA256(	(unsigned char*) &SK, skeLen, tempBufHash);
	
	if (memcmp (tempBufHash, shaBuf, HASHLEN) != 0){
	    printf("incorrect hash\n");
	    return 1;
	  }
	
	fclose(inFile);
	free(rsaBuf);
	free(shaBuf);
	free(wholeBuf);
	

	/* step 3: derive key from ephemKey and decrypt data. */
	// ske_decrypt_file of fnIn
	size_t offset_in = len + HASHLEN;
	ske_decrypt_file(fnOut, fnIn, &SK, offset_in);

	return 1;
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
	int mode = -1;
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
			FILE* keyFile = fopen(fnKey, "rb");
			rsa_readPublic(keyFile, &K);
			fclose(keyFile);
			//	gmp_printf("e: \n%Zd\n",K.e);
			//	gmp_printf("n: \n%Zd\n",K.n);
			//	rsa_shredKey(&K);
			kem_encrypt(fnOut, fnIn, &K);
			break;
			}
		case DEC: {

			RSA_KEY K ;;
			FILE* keyFile = fopen(fnKey, "rb");

			rsa_readPrivate(keyFile, &K);
			//	gmp_printf("d: \n%Zd\n",K.d);
			//	gmp_printf("n: \n%Zd\n",K.n);
			
			printf("Start dec\n");
			fclose(keyFile);

			kem_decrypt(fnOut, fnIn, &K);
			//rsa_shredKey(&K);
			break;	
			}
		case GEN: {
			RSA_KEY K;
		
			rsa_keyGen(nBits, &K);
			
			char *pubExtension = ".pub";
			char *publicKeyFile = malloc(strlen(fnOut)+4+1);
			strcpy(publicKeyFile, fnOut);
			strcat(publicKeyFile, pubExtension);
			//printf("did concat\n");

			FILE* public = fopen(publicKeyFile, "wb");			

			FILE* private = fopen(fnOut, "wb");

			rsa_writePrivate(private, &K);
			rsa_writePublic(public, &K);
				
			fclose(private);
			fclose(public);
			//rsa_shredKey(K);
			break;
			}
	default:
	  printf("%s", usage);
	  return 1;
	}

	

	return 0;
}
