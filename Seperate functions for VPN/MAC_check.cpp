/* This is the file for MAC check */

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
extern void macKey(char **C_S_Mac_key, char *password);
#define MR_WORD mr_unsign32


int MAC_check(char *systemType, int buffSize, FILE *fileWaitForCheck, FILE *recvHashMAC,char *key)
{
	int i;
	miracl *mip=mirsys(200,256);
	//Read encrypted message which needs integrety check
	//Here, we begin to read the encryption file, and hash it, then compare it with the hash value we received
	FILE *toReadfileForCheck =NULL;
	//Read in binary mode
	fopen_s(&toReadfileForCheck, "recvEncryptionResult.bin", "rb");
	if (!toReadfileForCheck) {
		cerr << "Can't open encrypted file to read." << endl;
		exit(EXIT_FAILURE);
	}

	//Compute the length of encryption results
	fseek(toReadfileForCheck, 0, SEEK_END);
	int fileSizeForHash = ftell(toReadfileForCheck);
	fseek(toReadfileForCheck, 0, SEEK_SET);

	// Define a buffer hashBlock, used to read ciphertext in memory buffer while decrypting
	// Read "buffSize" bytes ciphertext each time

	char *hashBlock = new char[buffSize+1];

	// Each time, read buffSize bytes ciphertext, until read to the end of EncryptionResult.bin
	// i stands for how many bytes we have read
	for (i = 0; i != fileSizeForHash; i += (buffSize+1)) {
		fread(hashBlock, sizeof(char), buffSize+1, toReadfileForCheck);
		//Output data read from encryptionResult in hexdecimal mode
		if(i==0)
		{
			memcpy(mip->IOBUFF,hashBlock,buffSize);
		}
		else
			strcat(mip->IOBUFF,hashBlock);
	}
	cout<<endl;

	fclose(toReadfileForCheck);
	delete []hashBlock;
	//Call function macKey() to computer Client_write_MAC_key and Server_write_MAC_key, then store them in char *MACKey[2]
	
	char *MACKey[2];
	macKey(MACKey, key);
//According to the system type, we choose to append corresponding MAC key to mip->IOBUFF(encrypted message)
	if(systemType=="Client")
		strcat(mip->IOBUFF,MACKey[0]);
	else if(systemType=="Server")
		strcat(mip->IOBUFF,MACKey[1]);

	//Computer HMAC value for received encrypted message
	char hash[32];
    sha256 sh;
    shs256_init(&sh);
    for (i=0;mip->IOBUFF[i]!=0;i++) shs256_process(&sh,mip->IOBUFF[i]);
    shs256_hash(&sh,hash);    

	cout<<"HMAC computed from received encrypted message."<<endl;
    for (i=0;i<32;i++) printf("%02x",(unsigned char)hash[i]);
    printf("\n");

	FILE *toReadrecvHashMAC =NULL;
	//Read in binary mode
	fopen_s(&toReadrecvHashMAC, "recvHashMAC.bin", "rb");
	if (!toReadrecvHashMAC) {
		cerr << "Can't open encrypted file to read." << endl;
		exit(EXIT_FAILURE);
	}
	char recvHash[32];
	fread(recvHash, sizeof(char), 32, toReadrecvHashMAC);
	
	cout<<"Received HMAC:"<<endl;
    for (i=0;i<32;i++) printf("%02x",(unsigned char)recvHash[i]);
    printf("\n");

	fclose(toReadrecvHashMAC);
	if(!strcmp(hash,recvHash))
		return 1;
	else
		return 0;
}