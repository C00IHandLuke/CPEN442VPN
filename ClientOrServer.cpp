/* This is the program for Client OR Server.
 * Type "s" to choose server mode;
 * Type "c" to choose client mode.
 */

#include <io.h>
#include <stdio.h>
#include <winsock2.h>
#include <string> 
#include <iostream>
#include "ecn.h"
#include "big.h"
#include <ctime>

#pragma comment(lib,"ws2_32.lib") //Winsock Library

#define SERVER_PORT 5208    // LISTENNING PORT

using namespace std;

char initserver(SOCKET s);
char initclient(SOCKET s);
SOCKET start();
char sendMessage();
char which();
char *genIV();
int mutualAuthentication(char *systemType,int mode,int buffSize,int keySize,char *key,SOCKET s, char *iv);
int mutualAuthenticationRecvNonce(char *systemType,int mode,int buffSize,int keySize,char *key,SOCKET s,char *iv,char *recvNonce);
char *DH_KeyEstablishment(Big pcs, char *sessionKey);
int aesWithSessionKey(char *systemType,int mode,int buffSize,int keySize,char *key,SOCKET s,char *iv);
int aesDecryption(int mode,int buffSize,int keySize,char *key,SOCKET s,char *iv,char *recvMessage);

SOCKET start()
{
	WORD wVersionRequested;
	WSADATA wsaData;    //This is the type for wsd data used in the winsock intiliazation
	SOCKET s;           //This is the type for the socket s, used to connect to a server
	int ret;
	
	cout<<"Initialising WinSock..."<<endl;

	wVersionRequested=MAKEWORD(2,2);              //Using WinSock Dll version 
	ret=WSAStartup(wVersionRequested,&wsaData);
	if(ret!=0)
	{
		cout<<"WSAStartup() failed. Error Code: "<<WSAGetLastError()<<endl;
		return 0;
	}
	else
		cout<<"WinSock initialised."<<endl;

	//Create SOCKET using TCP protocol
	s=socket(AF_INET,SOCK_STREAM,0);
	if(s==INVALID_SOCKET)
	{
		WSACleanup();
		cout<<"Could not create socket. Error Code: "<<WSAGetLastError()<<endl;
		return 0;
	}
	else
		cout<<"Socket created successfully."<<endl;

	return s;
}

char which()
{
	char type;
//	type = 'b';
	cout<<"Please choose the C/S mode you want. Enter 's' for server or 'c' for client."<<endl;
	type=getchar();
	while((type!='s')&&(type!='c'))
	{
		cout<<"You typed in an inproper system type. Please try again! (Type 's' or 'c')."<<endl;
		type=getchar();
	}
	return type;
}

int initServer(SOCKET sListen)
{
	char globaltype;

	int ret;
	SOCKET sServer;              //Used to connect with Client
	struct sockaddr_in serverAddr, clientAddr;    //Address information
	char *serverMessage;

	int addrLen;           

	//Prepare the sockaddr_in structure
	ZeroMemory((char *)&serverAddr,sizeof(serverAddr));
	serverAddr.sin_family=AF_INET;
	serverAddr.sin_port=htons(SERVER_PORT);
	serverAddr.sin_addr.S_un.S_addr=htonl(INADDR_ANY);

	//Bind here.
	ret=bind(sListen,(struct sockaddr *)&serverAddr,sizeof(serverAddr));
	if(ret==SOCKET_ERROR)
	{
		cout<<"bind() failed! Error Code: "<<WSAGetLastError()<<endl;
		closesocket(sListen); //CLOSE SOCKET
		WSACleanup();
		return 0;
	}
	else
		cout<<"Bind done."<<endl;

	//LISTENNING FOR CONNECTION REQUIREMENT
	ret=listen(sListen,5);
	if(ret==SOCKET_ERROR)
	{
		cout<<"listen() failed! code: "<<WSAGetLastError()<<endl;
		closesocket(sListen); //CLOSE SOCKET
		return 0;
	}
	
	cout<<"Waiting for client connecting!"<<endl;
	cout<<"Tips: Ctrl+c to quit!"<<endl;

	
	//Blocking to wait for client connection 
	while(1)
	{
		addrLen=sizeof(clientAddr);
		sServer=accept(sListen,(struct sockaddr *)&clientAddr,&addrLen);
		if(sServer==INVALID_SOCKET)
		{
			cout<<"accept() failed! Error Code: "<<WSAGetLastError()<<endl;
			closesocket(sListen);
			WSACleanup();
			return 0;
		}
		else 
			cout<<"Connected successfully!"<<endl;
	//Send a message back to the client
	serverMessage="Congratulations! You have created a successful connection";



	}
}

int initClient(SOCKET sClient)
{
	int ret;
	struct sockaddr_in serverAddr;
	
	//Give server's address information
	serverAddr.sin_family=AF_INET;
	serverAddr.sin_port=htons(SERVER_PORT);
	serverAddr.sin_addr.S_un.S_addr=inet_addr("127.0.0.1");

	//Connect the server
	ret=connect(sClient,(struct sockaddr *)&serverAddr,sizeof(serverAddr));
	if(ret==SOCKET_ERROR)
	{
		cout<<"connect() failed! Error Code: "<<WSAGetLastError()<<endl;
		closesocket(sClient);
		WSACleanup();
		return 0;
	}
	else 
		cout<<"Connected the server successfully!"<<endl;
//-----------------------------------------------------------------------------------------------------------//
	//Ask whether they can talk 
	while(1)
	{
		char *sendMessage=new char [5000];
		sendMessage="Here is Client. Can we talk securely? Please answer: Yes/No?";
		
		ret=send(sClient,sendMessage,strlen(sendMessage),0);
		if(ret==SOCKET_ERROR)
		{
			cout<<"Request(Message1) send() failed! Error Code: "<<WSAGetLastError()<<endl;
			return 0;
		}
		else 
		{
			cout<<"Wait for server's reply..."<<endl;
			char receiveMessage[5000];
	        char *ptr;
	            
	    	ptr=(char *)&receiveMessage;
	    	ret=recv(sClient,ptr,5000,0);
	    	if(ret==SOCKET_ERROR)
	    	{
	    		cout<<" Message1 recv() failed! Error Code: "<<WSAGetLastError()<<endl;
	    		return 0;
	    	}
			else if(ret==0)
	    	{
	    		cout<<"Server has closed the connection."<<endl;
				return 0;
	    	}
			while(ret>0)
			{
				if(strcmp((const char *)receiveMessage,"Yes")==0)
				{
					int mode_chosen,key_chosen;
					int buffSize=16;

					cout<<"Server agrees to talk. Make an agreement on what encryption algorithms you can support."<<endl;
					cout<<"Already made an agreement on algorithms chosen. Will use AES_256_CBC_SHA256."<<endl;
					cout<<"Begin mutual authentication here..."<<endl;
					char password[32];
					cout<<"Type password: "<<endl;
					cin>>password;
					char *iv;
					iv=genIV();
//Tell server to begin read encryptionResult file, which include message for authentication
					memcpy(sendMessage,iv,strlen(iv));
					strcat(sendMessage,"Begin.");
					
					ret=send(sClient,sendMessage,strlen(sendMessage),0);
					if(ret==SOCKET_ERROR)
					{
						cout<<"Mutual authentication request send() failed! Error Code: "<<WSAGetLastError()<<endl;
						return 0;
					}
					else
					{
						int mode_chosen=2;            //Related encryption mode is MR_CBC
						int keySize=3;                //Related keySize=256bits
						
//-------------------------------Client read encryption file, then write() it to send it to server-----------//					
	mutualAuthentication("Client",mode_chosen,buffSize,keySize,password,sClient, iv);

//Tell server to stop read encryptionResult file
	sendMessage="End.";
	send(sClient,sendMessage,strlen(sendMessage),0);

//----------------------------------------------------------------------------------------------------------//
						cout<<"Wait for server's reply..."<<endl;
						memset(receiveMessage,0,strlen(receiveMessage));
						ptr=(char *)&receiveMessage;
					    recv(sClient,ptr,5000,0);
						if(strcmp((const char *)receiveMessage,"Begin.")==0)
						{
							aesDecryption(mode_chosen,buffSize,keySize,password,sClient,iv,receiveMessage);
						}
						cout<<"Received reply from server and decrypted it.";
					}
				}
			}
			
			char sendMessage[100];
			scanf("%s",&sendMessage);
			ret=send(sClient,(char *)&sendMessage,sizeof(sendMessage),0);
		}
		
		
	}
}
int main(int argc , char *argv[])
{
	
	SOCKET sListen, clientServer;                 //Listenning socket and Link socket-attaching
	
	char *ptr,*ptr1,*ptr2;                        //Pointers for message sending

	
	

	

	

	

}