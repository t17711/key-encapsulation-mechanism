#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "rsa.h"
#include "prf.h"

/* NOTE: a random composite surviving 10 Miller-Rabin tests is extremely
 * unlikely.  See Pomerance et al.:
 * http://www.ams.org/mcom/1993-61-203/S0025-5718-1993-1189518-9/
 * */
#define ISPRIME(x) mpz_probab_prime_p(x,10)
#define NEWZ(x) mpz_t x; mpz_init(x)
#define BYTES2Z(x,buf,len) mpz_import(x,len,-1,1,0,0,buf)
#define Z2BYTES(buf,len,x) mpz_export(buf,&len,-1,1,0,0,x)

/* utility function for read/write mpz_t with streams: */
int zToFile(FILE* f, mpz_t x) {
  size_t i, len = mpz_size(x) * sizeof(mp_limb_t);
  unsigned char* buf = malloc(len);
  /* force little endian-ness: */

  for (i = 0; i < 8; i++) {
    unsigned char b = (len >> 8 * i) % 256;
    fwrite(&b, 1, 1, f);
  }
  Z2BYTES(buf, len, x);
  fwrite(buf, 1, len, f);
  /* kill copy in buffer, in case this was sensitive: */
  memset(buf, 0, len);
  free(buf);
  return 0;
}
int zFromFile(FILE* f, mpz_t x) {

  size_t i, len = 0;
 
  /* force little endian-ness: */
  for (i = 0; i < 8; i++) {
    unsigned char b;
    /* XXX error check this; return meaningful value. */
    fread(&b, 1, 1, f);
		
    len += (b << 8 * i);
  }
  unsigned char* buf = malloc(len);
  fread(buf, 1, len, f);
 
  BYTES2Z(x, buf, len);

  /* kill copy in buffer, in case this was sensitive: */
  memset(buf, 0, len);
  free(buf);
  return 0;

}

int rsa_keyGen(size_t keyBits, RSA_KEY* K) {
  rsa_initKey(K);

  /* TODO: write this.  Use the prf to get random byte strings of
   * the right length, and then test for primality (see the ISPRIME
   * macro above).  Once you've found the primes, set up the other
   * pieces of the key ({en,de}crypting exponents, and n=pq). */
  keyBits /= CHAR_BIT;  // need bytes instead of bit
  unsigned char* buf = malloc(keyBits);  // prf randBytes needs this
	
  int prime_or_not = 0;

  // get random p
  while (1) {
    randBytes(buf, keyBits); // generates random byte string

    // rand char to int
    BYTES2Z(K->p, buf, keyBits);
  
    prime_or_not = ISPRIME(K->p); // sheck prime

    if (prime_or_not > 0) { // if 2 prime if 1 probably or the other way around, but good enough for us
      //	printf("prime found for p\n");
      break;
    }
  }


  // set the random value for K->q
  while (1) {

    randBytes(buf, keyBits); // generates random byte string

    BYTES2Z(K->q, buf, keyBits); // copy bits to mpz variable
    
    prime_or_not = ISPRIME(K->q); // sheck prime

    if (prime_or_not > 0) { // if 2 prime if 1 probably or the other way around, but good enough for us
      //printf("prime found for q\n");
      break;
    }
  }


  // get n
  mpz_mul(K->n, K->p, K->q); // n = p*q

  // find e
  // use d for temporarily store phi
  // phi(n) = (p-1)(q - 1)
  mpz_sub_ui(K->q, K->q, 1);
  mpz_sub_ui(K->p, K->p, 1);

  mpz_mul(K->d, K->p, K->q);

  // reset pa and q	
  mpz_add_ui(K->q, K->q, 1);
  mpz_add_ui(K->p, K->p, 1);

  // fine e now , s.t. gcd(en phi) = 1
  unsigned int k = 6537; // let k be 6537 1st , as it seems to be recommended # online

  // currently i have K->d as phi after i find real e i set K->e to that and calculate d to det to K->d
  while (1) {
    if (mpz_gcd_ui(0, K->d, k) == 1) {

      // gmp_printf("Encryption key e found %Zd\n", K->e);
      mpz_set_ui(K->e, k);
      break; // if e found return
    }
    k += 2; // keep k odd since primes are odd, p-1 * q-1 is even so e must be odd
  }

  // now find d s.t. d*e mod phi ==1,here K-> d is initially phi
  mpz_invert(K->d, K->e, K->d);

  // gmp_printf("d found  %Zd\n",K->d);
  free(buf); // clear memory

  return 0;
}

size_t rsa_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		   RSA_KEY* K) {
  /* TODO: write this.  Use BYTES2Z to get integers, and then
   * Z2BYTES to write the output buffer. */

  //printf("Start encrypt\n");
  // printf("In length %d\n",(int)len);
  NEWZ(m); // to hold message
  NEWZ(c); // to hold cypher text

  BYTES2Z(m, inBuf, len); // get integer from message
  
  // gmp_printf("message is : %Zd\n",m);

  mpz_powm_sec(c, m, K->e, K->n); // c =m^e mod n
 //gmp_printf("ct is : %Zd\n, n is %Zd, e is %Zd\n", c, K->n, K->e);

  size_t len2;

  //  gmp_printf("encrypted %Zd\n",c);
  Z2BYTES(outBuf, len2, c);

  return len2; /* TODO: return should be # bytes written */
}

size_t rsa_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		   RSA_KEY* K) {
  /* TODO: write this.  See remarks above. */
  // gmp_printf("mod : %Zd\n", K->n);

  NEWZ(c);  // to hold cypher text
  NEWZ(m); // message 

  BYTES2Z(c, inBuf, len); // read integer from cypher text

  // gmp_printf("to decrypt : %Zd\n",c);

  mpz_powm_sec(m, c, K->d, K->n); // m =c^d mod n

  size_t len2;
  
  //  gmp_printf("decrypted  %Zd\n",m);
  Z2BYTES(outBuf, len2, m); // this sets  num bytes written to len2
  
  return len2; /* TODO: return should be # bytes written */

}

size_t rsa_numBytesN(RSA_KEY* K) {
	return mpz_size(K->n) * sizeof(mp_limb_t);
}

int rsa_initKey(RSA_KEY* K) {
	mpz_init(K->d);
	mpz_set_ui(K->d, 0);
	mpz_init(K->e);
	mpz_set_ui(K->e, 0);
	mpz_init(K->p);
	mpz_set_ui(K->p, 0);
	mpz_init(K->q);
	mpz_set_ui(K->q, 0);
	mpz_init(K->n);
	mpz_set_ui(K->n, 0);
	return 0;
}

int rsa_writePublic(FILE* f, RSA_KEY* K) {
	/* only write n,e */
	zToFile(f, K->n); gmp_printf("k->n : %Zd\n", K->n);
	zToFile(f, K->e); gmp_printf("k->e : %Zd\n", K->e);
	return 0;
}
int rsa_writePrivate(FILE* f, RSA_KEY* K) {
	zToFile(f, K->n);
	/*	zToFile(f, K->e);gmp_printf("k->e : %Zd\n", K->e);
	zToFile(f, K->p);
	zToFile(f, K->q);*/
	zToFile(f, K->d);
	return 0;
}
int rsa_readPublic(FILE* f, RSA_KEY* K) {
	rsa_initKey(K); /* will set all unused members to 0 */
	zFromFile(f, K->n);
	zFromFile(f, K->e);
	return 0;
}
int rsa_readPrivate(FILE* f, RSA_KEY* K) {
	rsa_initKey(K);
	zFromFile(f, K->n);
      /*zFromFile(f, K->e);
	zFromFile(f, K->p);
	zFromFile(f, K->q);*/
	zFromFile(f, K->d);
	return 0;
}
int rsa_shredKey(RSA_KEY* K) {
	/* clear memory for key. */
	mpz_t* L[5] = { &K->d, &K->e, &K->n, &K->p, &K->q };
	size_t i;
	for (i = 0; i < 5; i++) {
		size_t nLimbs = mpz_size(*L[i]);
		if (nLimbs) {
			memset(mpz_limbs_write(*L[i], nLimbs), 0,
					nLimbs * sizeof(mp_limb_t));
			mpz_clear(*L[i]);
		}
	}
	/* NOTE: a quick look at the gmp source reveals that the return of
	 * mpz_limbs_write is only different than the existing limbs when
	 * the number requested is larger than the allocation (which is
	 * of course larger than mpz_size(X)) */
	return 0;
}
