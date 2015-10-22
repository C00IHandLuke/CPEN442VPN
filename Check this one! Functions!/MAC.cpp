/* This is the file for computing MAC */

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
extern void macKey(char **C_S_Mac_key, char *password);

#define MR_WORD mr_unsign32

#ifndef MR_NOFULLWIDTH
Miracl precision(500,0);
#else 
Miracl precision(500,MAXBASE);
#endif

// If MR_STATIC is defined in mirdef.h, it is assumed to be 100

//Miracl precision(120,(1<<26));

void macKey(char **C_S_Mac_key, char *password)
{
	char hash_c[20];
    int i;
    sha sh_c;
    shs_init(&sh_c);
    for (i=0;password[i]!=0;i++) shs_process(&sh_c,password[i]);
    shs_hash(&sh_c,hash_c);
	C_S_Mac_key[0]=hash_c;
	
	cout<<"Client_write_mac_key: "<<endl;
    for (i=0;i<20;i++) printf("%02x",(unsigned char)hash_c[i]);
    printf("\n");
	
    char hash_s[32];
    sha256 sh_s;
    shs256_init(&sh_s);
    for (i=0;password[i]!=0;i++) shs256_process(&sh_s,password[i]);
    shs256_hash(&sh_s,hash_s);   
	C_S_Mac_key[1]=hash_s;
	
	cout<<"Server_write_mac_key: "<<endl;
    for (i=0;i<32;i++) printf("%02x",(unsigned char)hash_s[i]);
    printf("\n");
    
    return;
}

char *MAC_compute(char *ciphertext, char * MAC_key)
{
	miracl *mip=&precision;
	int i;
	char hash[32];
    sha256 sh;
    shs256_init(&sh);
    for (i=0;mip->IOBUFF[i]!=0;i++) shs256_process(&sh,mip->IOBUFF[i]);
    shs256_hash(&sh,hash);    

	cout<<"Hash value of the message is: "<<endl;
    for (i=0;i<32;i++) printf("%02x",(unsigned char)hash[i]);
    printf("\n");

	return hash;
}

int MAC_check(char *ciphertext, char * MAC_key,char *recvHash)
{
	miracl *mip=&precision;
	int i;
	char checkHash[32];
    sha256 sh;
    shs256_init(&sh);
    for (i=0;ciphertext[i]!=0;i++) shs256_process(&sh,ciphertext[i]);
    shs256_hash(&sh,checkHash);    

	cout<<"Hash value of encrypted message computed by receiver is: "<<endl;
    for (i=0;i<32;i++) printf("%02x",(unsigned char)checkHash[i]);
    printf("\n");

	if(!strcmp(recvHash,checkHash))
		return 1;
	else
		return 0;
}