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

char *genIV()
{
//Generat random numbers, and then set IV, using function strong_bigdig(_MIPD_ csprng *rng,int n,int b,big x)
//	for (i = 0; i<16; i++) iv[i] = i;
//----------------------------Set vector IV-------------------------------------//
 char iv[17];
 char raw[256];
 big x;
 time_t seed;
 csprng rng;
 miracl *mip=mirsys(200,256);
 x=mirvar(0);
 cout<<"Please enter a raw random string to generator a random IV vector: "<<endl;
 cin>>raw;
 getchar();
 time(&seed);
 //Initialize random number generator
 strong_init(&rng,strlen(raw),raw,(long)seed);
 //show vector IV is in hexdecimal
 mip->IOBASE=16;
 //Generator random hexdecimal number x
 strong_bigdig(&rng,64,2,x);
 //Store x as hexdecimal string into iv
 cotstr(x,iv);

 cout<<"iv= "<<iv<<endl;

 return iv;
}

char *GettimeStampNonce()
{
  char *NonceTimestamp;
  time_t seed;
  char *systemTime=ctime(&seed);                       //Store system time in timeStamp

  char raw[256];
  big x;

  csprng rng;
  miracl *mip=mirsys(200,256);
  x=mirvar(0);
  cout<<"Please enter a raw random string to generator a random IV vector: "<<endl;
  cin>>raw;
  getchar();
  time(&seed);
  //Initialize random number generator
  strong_init(&rng,strlen(raw),raw,(long)seed); 
  //show nonce in decimal
  mip->IOBASE=10;                                      
  //Generator nonce x using function strong_bigdig()  
  strong_bigdig(&rng,64,2,x);
  //Store x as a decimal string into mip->IOBUFF
  cotstr(x,mip->IOBUFF);
  cout<<"Nonce: "<<mip->IOBUFF<<endl;

  memcpy(NonceTimestamp,mip->IOBUFF,strlen(mip->IOBUFF));
  strcat(NonceTimestamp,systemTime);

  return NonceTimestamp;
}
char *GetPlaintext(char *GettimeStampNonce)
{
	char *plaintext;
	char message[5000];
	cout<<"Please type the message you want to send."<<endl;
	cin>>message;
	memcpy(plaintext,GettimeStampNonce,strlen(GettimeStampNonce));
	strcat(plaintext,message);

	return plaintext;
}

char * aes_encryption(char *plaintext, char *iv, char *key)
{
	int i, j, nk;
	aes a;
	int buffSize=16;

	// aes Initilization 
	nk=32;
	a.mode=MR_CBC;

	int len=strlen(plaintext);
	cout<<"Message length is "<<len<<endl;

	if (!aes_init(&a, a.mode, nk, key, iv))       //Check whether initilization of AES is successful
	{
		cout << "Failed to Initialize." << endl;
		return 0;
	}
	cout<<"Plaintext is "<<plaintext<<endl;

	aes_encrypt(&a,plaintext);
	char *ciphertext;
	memcpy(ciphertext,plaintext,strlen(plaintext));
	
	//Print out the encryption results in hexdecimal form
    printf("Encryption results= ");
	for (i=0;i<len;i++) printf("%02x",(unsigned char)ciphertext[i]);
    printf("\n");
	
	aes_end(&a);

	return ciphertext;
}
