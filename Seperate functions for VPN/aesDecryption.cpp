/*
This is the code for AES decryption, which needs parameters: IV vector, key, .
And encrypted plaintext includes a timeStamp, a random generated nonce, and the message. 

Required files:
"mraes.c" 
"mrstrong.c"

Required library:
"miracl.lib"
*/

#include <stdlib.h> 
#include <stdio.h>
#include <string>
#include <iostream>
#include <fstream>
#include <time.h>
#include "ecn.h"
#include "big.h"
#include <winsock2.h>

#pragma comment(lib,"ws2_32.lib") //Winsock Library

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
	extern int MAC_check(char *systemType, int buffSize, FILE *fileWaitForCheck, FILE *recvHashMAC,char *key);
}


int aesDecryption(char *systemType,int mode,int buffSize,int keySize,char *key,SOCKET s,char *iv,char *recvMessage)
{
	int i, j, nk;
	aes a;
	
	//Set key size here
	switch (keySize)
	{
	case 1:nk = 16; break;
	case 2:nk = 24; break;
	case 3:nk = 32; break;
	default:;
	}

	//Set encryption mode
	switch (mode)
	{
	case 1:a.mode = MR_ECB;   break;
	case 2:a.mode = MR_CBC;   break;
	case 3:a.mode = MR_CFB4;  break;
	case 4:a.mode = MR_OFB16; break;
	default:;
	}

	// aes Initilization/Reset
	if (!aes_init(&a, a.mode, nk, key, iv))       //Check whether initilization of AES is successful
	{
		cout << "Failed to Initialize." << endl;
		return 0;
	} 

	//Define a FILE* handle to store received encryption results in file recvEncryptionResult.bin
	FILE *toStoreRecvEncryptionResult=NULL;

	//fopen_s, safe fopen() function from Microsoft
	fopen_s(&toStoreRecvEncryptionResult,"recvEncryptionResult.bin","wb");
	if (!toStoreRecvEncryptionResult) {
		cerr << "Can't open decryption file to write." << endl;
		exit(EXIT_FAILURE);
	}

	//Define a FILE* handle to store received hash value in recvHashMAC.bin
	FILE *toStoreRecvHashMAC=NULL;
	fopen_s(&toStoreRecvHashMAC,"recvHashMAC.bin","wb");
	if(!toStoreRecvHashMAC){
		cerr<<"Can't open HashMAC file to write."<<endl;
		exit(EXIT_FAILURE);
	}

	//Define a FILE* handle to store the decryption results in file recvEncryptionResult.bin
	FILE *toStoreDecryptionResult = NULL;
	
	//fopen_s, safe fopen() function from Microsoft
	fopen_s(&toStoreDecryptionResult,"DecryptionResult.txt","w");
	if (!toStoreDecryptionResult) {
		cerr << "Can't open decryption file to write." << endl;
		exit(EXIT_FAILURE);
	}


	// Define a buffer encryptBlock, used to read ciphertext in memory buffer while decrypting
	// Read "buffSize" bytes ciphertext each time
	char *encryptBlock = new char[buffSize+1];
	char *hashBlock=new char[32];                 //To receive the first 32bytes hash value
	
	// Each time, receive buffSize+1 bytes ciphertext, recvMessage=="End."
		while(!strcmp((const char*)recvMessage,"End."))
		{
			recv(s,encryptBlock,buffSize+1,0);
			strcpy(recvMessage,encryptBlock);
			fwrite(encryptBlock, sizeof(char), buffSize+1, toStoreRecvEncryptionResult);
			//Judge whether begin to receive MAC
			if(strcmp((const char*)recvMessage,"MAC Begin."))
			{
				recv(s,hashBlock,32,0);
			    strcpy(recvMessage,hashBlock);
				fwrite(hashBlock, sizeof(char), 32, toStoreRecvHashMAC);
			}
		}
	//Hash recvEncryptionReuslt and compare, then decide whether to decrypt or not
/////////////////-----------------------------------------------------------------------------////////////////

//---------------------------------------------Do MAC check here--------------------------------------------//


//Call function MAC_check() to computer Client_write_MAC_key and Server_write_MAC_key, then store them in char *MACKey[2]
	    int macCheck;
		macCheck = MAC_check(systemType, buffSize, toStoreRecvEncryptionResult, toStoreRecvHashMAC,key);

////////////////------------------------------------------------------------------------------////////////////
	//Decide whether to decrypt or not according to macCheck
	//Begin to decrypt
	if(macCheck==1)
	{
		//Define a FILE* handle to read received encryption results in file recvEncryptionResult.bin
	    FILE *toReadRecvEncryptionResult=NULL;

	    //fopen_s, safe fopen() function from Microsoft
	    fopen_s(&toReadRecvEncryptionResult,"recvEncryptionResult.bin","wb");
	    if (!toReadRecvEncryptionResult) {
		   cerr << "Can't open decryption file to write." << endl;
		   exit(EXIT_FAILURE);
	    }
		//Compute the length of encryption results
	    fseek(toReadRecvEncryptionResult, 0, SEEK_END);
	    int fileSize = ftell(toReadRecvEncryptionResult);
	    fseek(toReadRecvEncryptionResult, 0, SEEK_SET);
		
		//IMPORTANT!!!
	    // Before decryption, reset AES parameters 
	    aes_reset(&a, a.mode, iv);

	    cout << "Decryption result is ";
		aes_decrypt(&a, encryptBlock);
		
		//Output decryption results into file toStoreDecryptionResult.txt
	    fwrite(encryptBlock, sizeof(char), buffSize+1, toStoreDecryptionResult);
	    //Display decryption results in terminal
	    cout << encryptBlock;
	    cout << endl;
	}
	else 
		cout<<"MAC check failed."<<endl;
	
	// release encryptBlock
	delete[] encryptBlock;

	//clean up a
	aes_end(&a);

	return 0;
}