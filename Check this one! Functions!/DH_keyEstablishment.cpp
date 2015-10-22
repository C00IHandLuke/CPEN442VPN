/*
 *   Code for Diffie-Hellman Key Establishment using 2048 bit prime
 *
 *   Requires: big.cpp ecn.cpp
 */

#include <iostream>
#include <stdlib.h> 
#include <stdio.h>
#include <string>
#include "ecn.h"
#include "big.h"
#include <ctime>

extern "C"
{
#include "miracl.h"
}

using namespace std;

extern "C" { FILE _iob[3] = {__iob_func()[0], __iob_func()[1], __iob_func()[2]}; }

/* large 2048 bit prime p for which (p-1)/2 is also prime, we found it from RFC 3526.
 * Check the link below to see RFC 3526
 * <http://tools.ietf.org/html/rfc3526#page-3>
 */

char *primetext=(char *)
"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

#ifndef MR_NOFULLWIDTH
Miracl precision(500,0);
#else 
Miracl precision(500,MAXBASE);
#endif

// If MR_STATIC is defined in mirdef.h, it is assumed to be 100

//Miracl precision(120,(1<<26))

void paGen(Big pa, Big randNum)
{
	time_t seed;
	Big p;
	miracl *mip=mirsys(500,0);

	time(&seed);
    irand((long)seed);   /* change parameter for different values */

	mip->IOBASE=16;
    p=primetext;

	cout << "\nGenerate random big number for key establishment." << endl;
	randNum=rand(160,2);

	//Send pa to the other party
	/* 2 generates the prime sub-group of size (p-1)/2 */
	pa=pow(2,randNum,p);             // pa =2^a mod p

	return;
}

char *DH_KeyEstablishment(Big randNum,Big pa,Big pb,char *sessionKey)
{
    Big p,key;
    miracl *mip=&precision;

    cout << "First Diffie-Hellman Key exchange .... " << endl;

	mip->IOBASE=16;
    p=primetext;

//using randNum, pb and p to generate original shared key here
    key=pow(pb,randNum,p);

//Store key into "char" buffer mip->IOBUFF in hexdecimal form
	mip->IOBASE=16;
	mip->IOBUFF << key;

//----Here, client begins to hash the long session key, to get 32bytes new session key for AES encryption----//

    int i;
    sha256 sh;
    shs256_init(&sh);
	for (i=0;mip->IOBUFF[i]!=0;i++) shs256_process(&sh,mip->IOBUFF[i]);
    shs256_hash(&sh,sessionKey); 

	cout<<"Finished key establishment, and the session key is: "<<endl;
    for (i=0;i<32;i++) 
		printf("%02x",(unsigned char)sessionKey[i]);
    printf("\n");


//////--------------------Client and Server finished to create key using 2048 bit prime--------------//////
    return 0;
}