#include <stdlib.h> 
#include <stdio.h>
#include <string>
#include <iostream>
#include <fstream>
#include <time.h>
#include "ecn.h"
#include "big.h"

using namespace std;

extern "C"
{
#include "miracl.h"
}

extern "C" { FILE _iob[3] = {__iob_func()[0], __iob_func()[1], __iob_func()[2]}; }

#define MR_WORD mr_unsign32

/* this is fixed */
#define NB 4

extern "C"
{
	extern BOOL  aes_init(aes *, int, int, char *, char *);
	extern void  aes_getreg(aes *, char *);
	extern void  aes_ecb_encrypt(aes *, MR_BYTE *);
	extern void  aes_ecb_decrypt(aes *, MR_BYTE *);
	extern mr_unsign32 aes_encrypt(aes *, char *);
	extern mr_unsign32 aes_decrypt(aes *, char *);
	extern void   aes_reset(aes *, int, char *);
	extern void  aes_end(aes *);
	extern void macKey(char **C_S_Mac_key, char *password);
}

char *aes_decryption(char *ciphertext,char *iv,char *key)
{
	int i, j, nk;
	aes a;
	// aes Initilization/Reset
	nk=32;
	a.mode=MR_CBC;

	if (!aes_init(&a, a.mode, nk, key, iv))       //Check whether initilization of AES is successful
	{
		cout << "Failed to Initialize." << endl;
		return 0;
	} 
	aes_decrypt(&a,ciphertext);

	char *plaintext;
	memcpy(plaintext,ciphertext,strlen(ciphertext));

	//print out the decryption results
	cout<<"Decryption result is "<<plaintext<<endl;
	
	aes_end(&a);

	return plaintext;
}