#include <stdlib.h> 
#include <string>
#include <iostream>
#include <atlenc.h>
#include <fstream>
#include <assert.h>

extern "C"
{
#include "miracl.h"
}

using namespace std;

#define MR_WORD mr_unsign32

/* this is fixed */
#define NB 4

extern "C"
{
	extern BOOL  aes_init(aes *,int,int,char *,char *);
    extern void  aes_getreg(aes *,char *);
    extern void  aes_ecb_encrypt(aes *,MR_BYTE *);
    extern void  aes_ecb_decrypt(aes *,MR_BYTE *);
    extern mr_unsign32 aes_encrypt(aes *,char *);
    extern mr_unsign32 aes_decrypt(aes *,char *);
    extern void  aes_reset(aes *,int,char *);
    extern void  aes_end(aes *);
}
int main()
{ 
    int i,j,nk;
    aes a;
    MR_BYTE y,x,m;
	char key[32];

	char * block=new char[255];
	
    char iv[16];
	
	cout<<"Please type your password (encryption key): "<<endl;
	cin>>key;

    for (i=0;i<16;i++) iv[i]=i;

	cout<<"Please type the message you want to encrypt below."<<endl;
	cin>>block;
	
	int len=strlen(block);
	cout<<"Message length is "<<len<<endl;

    for (nk=16;nk<=32;nk+=8)
    {  
		cout<<"Key Size= "<<nk*8<<" bits"<<endl;

        if (!aes_init(&a,MR_CBC,nk,key,iv))
        {
			cout<<"Failed to Initialize."<<endl;
            return 0;
        }

		cout<<"Plaintext is "<<block<<endl;
		aes_encrypt(&a,block);
	    
		//Print out the encryption results in hexdecimal form
        printf("Encrypt= ");
		for (i=0;i<len;i++) printf("%02x",(unsigned char)block[i]);
        printf("\n");

		//Reset the aes parameters and decrypt ciphertext
        aes_reset(&a,MR_CBC,iv);
        aes_decrypt(&a,block);

		//print out the decryption results
		cout<<"Decryption result is "<<block<<endl;

        aes_end(&a);

    }

	system("pause");
    return 0;
}
