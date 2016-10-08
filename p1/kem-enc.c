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
#define ENTLEN 512 /* entropy length for skey_keyGen */

int kem_encrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	/* TODO: encapsulate random symmetric key (SK) using RSA and SHA256;
	 * encrypt fnIn with SK; concatenate encapsulation and cihpertext;
	 * write to fnOut. */

	//encapsulate the key
	//call the rsa encrypty function

	// creating symmetric key.
	unsigned char* x = malloc(ENTLEN);
	randBytes(x, ENTLEN);
	SKE_KEY SK;
	// generating SK with entlen:512	
	ske_keyGen(&SK, x, ENTLEN);

	// 1- Encapsulate the above created SK with RSA encryption and SHA256
	//create inBuf
	unsigned char* inBuf = 	&SK;
	
	// create outBuf
	size_t len = rsa_numBytesN(K);
	size_t outBufLen = (len > HASHLEN)? len: HASHLEN;
	unsigned char* outBuf = malloc(outBufLen);	
	
	// RSA encryption of SK
	rsa_encrypt(outBuf, inBuf, sizeof(SK), K);
	
	// open output file to write ciphertext from rsa_encrypt
	FILE* output_file = fopen(fnOut, "wb");
	fwrite(outBuf, 1, len, output_file);
	
	
	// calculate SHA256
	SHA256(inBuf, sizeof(SK), outBuf);
	// write SHA256 of SK to output file
	fwrite(outBuf, 1, HASHLEN, output_file);
	
	// close output file
	fclose(output_file);
	// free output buffer
	free(outBuf);
	

	// 2- Encrypt fnIn with SymmetricKey (SK)
	size_t offset_out = outBufLen + HASHLEN;
	ske_encrypt_file(fnOut, fnIn, &SK, NULL, offset_out);
	
	// RETURN 1 if encryption successful else RETURN 0
	return 1;
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
	size_t inBufLen = (len > HASHLEN)? len: HASHLEN;
	unsigned char* inBuf = malloc(inBufLen);
	unsigned char* outBuf = malloc(inBufLen);

	// open fnIn to read the key encryption
	FILE* inFile = fopen(fnIn, "rb");
	fread(inBuf, 1, inBufLen, inFile);
	
	// decrypting fnIn contents with rsa_decrypt
	rsa_decrypt(outBuf, inBuf, inBuflen, K)
	

	// retireve SK from outBuf
	SKE_KEY SK;
	memcpy(&SK, outBuf, ENTLEN); 
	
	/* step 2: check decapsulation */
	fread(inBuf, 1, HASHLEN, inFile);
	unsigned char* d = &SK;
	SHA256(d, sizeof(SK), outBuf);
	if (inBuf != outBuf) {
		printf("encapsulation != decapsulation");
		fclose(inFile);
		free(inBuf);
		free(outBuf);		
	}

	fclose(inFile);
	free(inBuf);
	free(outBuf);

	/* step 3: derive key from ephemKey and decrypt data. */
	// ske_decrypt_file of fnIn
	size_t offset_in = inBufLen + HASHLEN;
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
			RSA_KEY* K ;
			FILE* keyFile = fopen(fnKey, "rb");
			rsa_readPublic(keyFile, K);
			kem_encrypt(fnOut, fnIn, K);
			rsa_shredKey(K);
			break;
			}
		case DEC: {
			RSA_KEY* K ;
			FILE* keyFile = fopen(fnKey, "rb");
			rsa_readPublic(keyFile, K);
			kem_decrypt(fnOut, fnIn, K);
			rsa_shredKey(K);
			break;	
			}
		case GEN: {
			RSA_KEY* K;
			FILE* keyFile = fopen(fnKey, "wb");
			rsa_keyGen(nBits, K);
			rsa_writePublic(fnOut, K);
			rsa_writePrivate(keyFile, K);
			rsa_shredKey(K);
			break;
			}
	default:
			return 1;
	}

	fclose(keyFile);

	return 0;
}
