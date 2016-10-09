#include "ske.h"
#include "prf.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memcpy */
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#ifdef LINUX
#define MMAP_SEQ MAP_PRIVATE|MAP_POPULATE
#else
#define MMAP_SEQ MAP_PRIVATE
#endif

/* NOTE: since we use counter mode, we don't need padding, as the
 * ciphertext length will be the same as that of the plaintext.
 * Here's the message format we'll use for the ciphertext:
 * +------------+--------------------+-------------------------------+
 * | 16 byte IV | C = AES(plaintext) | HMAC(C) (32 bytes for SHA256) |
 * +------------+--------------------+-------------------------------+
 * */

/* we'll use hmac with sha256, which produces 32 byte output */
#define BYTES2Z(x,buf,len) mpz_import(x,len,-1,1,0,0,buf)
#define HM_LEN 32
#define KDF_KEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I"
/* need to make sure KDF is orthogonal to other hash functions, like
 * the one used in the KDF, so we use hmac with a key. */

int ske_keyGen(SKE_KEY* K, unsigned char* entropy, size_t entLen)
{
	/* TODO: write this.  If entropy is given, apply a KDF to it to get
	 * the keys (something like HMAC-SHA512 with KDF_KEY will work).
	 * If entropy is null, just get a random key (you can use the PRF). */
	printf("aes--  %s\n , hmac--  %s\n", K->aesKey, K->hmacKey); 
	printf("generating Keys..\n");
	if(entropy != NULL){

		HMAC(EVP_sha256(),KDF_KEY, HM_LEN,entropy, entLen,K->aesKey,NULL);
		HMAC(EVP_sha256(),KDF_KEY,HM_LEN,entropy, entLen,K->hmacKey,NULL);
		//printf("Inside if aes--  %s\n , hmac--  %s\n", K->aesKey, K->hmacKey); 
		//printf("else\n");
		//printf("aes-- %s, hmackey--  %s",K->aesKey, K->hmacKey);
		//HMAC(EVP_sha512(),K->aesKey ,HM_LEN,(unsigned char*)mpz_limbs_read(rcount),
				//sizeof(mp_limb_t)*mpz_size(rcount),outBuf,NULL);

		//printf("aes--  %s , hmac--  %s", K->aesKey, K->hmacKey); 
	}
	else{


			randBytes(K->aesKey, HM_LEN);
			randBytes(K->hmacKey, HM_LEN);
	printf("aes--  %s\n , hmac--  %s\n", K->aesKey, K->hmacKey); 
		
	}

		//printf("aes--  %s , hmac--  %s", K->aesKey, K->hmacKey); 
	return 0;
}
size_t ske_getOutputLen(size_t inputLen)
{
//printf("block size %i,  inputlne  %lu  and Hmlen   %i\n", AES_BLOCK_SIZE, inputLen, HM_LEN); 
	printf("getting output len...\n");
	return AES_BLOCK_SIZE + inputLen + HM_LEN;
}
size_t ske_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K, unsigned char* IV)
{
	printf("Encrypting...\n");
//printf("aesKey   %s,  and Hmac key   %s\n", K->aesKey, K->hmacKey);
//printf("len  %lu\n", len);
//printf("outbuf   %s,     inbuf   %s   and IV   %s\n", outBuf, inBuf, IV);
	/* TODO: finish writing this.  Look at ctr_example() in aes-example.c
	 * for a hint.  Also, be sure to setup a random IV if none was given.
	 * You can assume outBuf has enough space for the result. */
	 /* TODO: should return number of bytes written, which
	             hopefully matches ske_getOutputLen(...). */

	//unsigned char key[32];
	//unsigned char key = K->aesKey;
	//printf("key is %c", key);
	
	//unsigned char ct[512];
	//unsigned char pt[512];
	/* so you can see which bytes were written: */
	/*memset(ct,0,512);
	memset(pt,0,512);
	char* message = inBuf;
	size_t Len = strlen(message);*/
	unsigned char* temp_iv;

	unsigned char iv_arr[HM_LEN];

	if(IV==NULL){

		randBytes(iv_arr, HM_LEN);	
		temp_iv = iv_arr;
	
	}else{
		temp_iv = IV;
	}
	memcpy (outBuf, temp_iv, AES_BLOCK_SIZE);//copies IV to outBuf upto AES_BLOCK_SIZE bytes


	/* encrypt: */
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	if (1!=EVP_EncryptInit_ex(ctx,EVP_aes_256_ctr(),0,K->aesKey,temp_iv))
		ERR_print_errors_fp(stderr);
	int nWritten;
	//append inBuf after IV and encrypt it the len is now AES_BLOCK_SIZE + len
	if (1!=EVP_EncryptUpdate(ctx, outBuf+AES_BLOCK_SIZE, &nWritten, inBuf, len))
		ERR_print_errors_fp(stderr);
	EVP_CIPHER_CTX_free(ctx);
	
	size_t hmac = len + AES_BLOCK_SIZE;

	//hash encrypted message which is hmac length long and put it on position starting from outBuf+hmac of outBuf
    	HMAC (EVP_sha256(), K->hmacKey, HM_LEN, outBuf, hmac, outBuf + hmac, NULL);
	
    return ske_getOutputLen (len);

//printf("outbuf   %s,     inbuf   %s   and IV  %d  and ctLen %lu\n", outBuf, inBuf, IV, ctLen);
//printf("Iv    %d\n", IV);
/*
ske_encrypt 
outBuf is a pointer to unsigned char and holds output
inBuf is a the plain text, len is the length of the text, K is the symmetric key to encrypt the inbuf and Iv is the initialized vector 
algo
how do I encrypt the input plain text
use K 
*/
}
size_t ske_encrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, unsigned char* IV, size_t offset_out)
{
	/* TODO: write this.  Hint: mmap. */

			
	return 0;
}
size_t ske_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K)
{
	/* TODO: write this.  Make sure you check the mac before decypting!
	 * Oh, and also, return -1 if the ciphertext is found invalid.
	 * Otherwise, return the number of bytes written.  See aes-example.c
	 * for how to do basic decryption. */
	/* now decrypt.  NOTE: in counter mode, encryption and decryption are
	 * actually identical, so doing the above again would work. */


	//printf("Decrypting...\n");
	if (len < AES_BLOCK_SIZE + HM_LEN)
        	return -1;

    // Eliminating the length of HMAC and keeping only encrypted iv + message length
    len -= HM_LEN;

    // Getting HMAC of encrypted iv+message

    unsigned char HmacValue[HM_LEN];
    HMAC(EVP_sha256(), K->hmacKey, HM_LEN, inBuf, len, HmacValue, NULL);

    // Comparing the generated hmac with the hmac of inBuf
    //if Hmac calculated and the one obtained with inBuf are same perform decryption
    if (memcmp(HmacValue, inBuf + len, HM_LEN) == 0) {

    // HMAC test passed, decrypting. iv in the begin of the inBuf

		int nWritten = 0;
		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

		if (1!=EVP_DecryptInit (ctx,EVP_aes_256_ctr(),K->aesKey, inBuf))
			ERR_print_errors_fp(stderr);
		//moving the pointer to the ciphered message location skipping the iv
	    	inBuf += AES_BLOCK_SIZE;
	    	len   -= AES_BLOCK_SIZE; //only need the len of ciphered message
		//len   -= HM_LEN;

		if (1!=EVP_DecryptUpdate(ctx,outBuf,&nWritten,inBuf,len))
			ERR_print_errors_fp(stderr);


	    return len; // return number of bytes written

    }else {

		return -1;
    }

/////////
	//nWritten = 0;
	//ctx = EVP_CIPHER_CTX_new();
	//if (1!=EVP_DecryptInit_ex(ctx,EVP_aes_256_ctr(),0,key,iv))
	//	ERR_print_errors_fp(stderr);
	//if (1!=EVP_DecryptUpdate(ctx,pt,&nWritten,ct,ctLen))
	//	ERR_print_errors_fp(stderr);
	//fprintf(stderr, "%s\n",pt);
////////
	return 0;
}
size_t ske_decrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, size_t offset_in)
{
	/* TODO: write this. */


	return 0;
}