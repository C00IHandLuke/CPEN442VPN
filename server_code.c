/*  This is the VPN project for CPEN442
	Group: 4
	Date: October 15, 2015
*/

//Standard include file
#include <io.h>
#include <stdio.h>
//This is the include file for initializing winsock
#include <WinSock2.h>
//This is the particular winsock library so we can use
//winsock functions etc.
#pragma comment(lib, "ws2_32.lib")
 
//Here we declare a function for use as either the client/server
/*We will be passing the *message to the server to send to the client
* and that is all for now.
*/
int server_connection(char* message);
int client_connection();

int main(int argc , char *argv[]){
	char type;
	char message[25] = "The initial step works!\n";
	printf("Please enter s for server or c for client.\n");
	type = getchar();

	if (type == 's'){
		//Then we want to call our server function
		server_connection(message);
	}
	else if(type == 'c'){
		//then we want to call our client function
		client_connection();
	}
	else {
		//We must have called our client or server improperly
		return 1;
	}
    return 0;
}

int server_connection(char* message){
	WSADATA wsd; //This is the type for wsd data used in the winsock intiliazation
    SOCKET s, new_socket; //This is the type for the socket s, used to connect to a server

	//The server stores an address, port, family id and an array of zeros
    struct sockaddr_in server , client;
    int c;
	//char *MA;
 
	///////////////////////////////////////////////////////
	//This first part sends a message to initialize winsock,
	//so that we may set up a TCP socket

	printf("initializing winsock\n");

	//MAKEWORD gives us a version for WSAstartup
	if (WSAStartup(MAKEWORD(2,2),&wsd) != 0) //Make sure initialization worked
    {
		//If we dont successfully initialize Winsock, send an error message
        printf("Error! Information for error: %d\n",WSAGetLastError());
		//End the code here
        return 1;
    }

	printf("Initialization was successful\n");
     
	////////////////////////////////////////////////////
	//Now we create a socket using the socket() function

	//The socket() function accepts the address family, 
	//the type of protocol, and the protocol as paramters.
	//'0' sets the protocol automatically
	if((s = socket(AF_INET , SOCK_STREAM , 0 )) == INVALID_SOCKET) //S receives socket info
    {
		//We can use the WSAGetLastError() function to print the error for debugging
        printf("Socket was not created : %d\n" , WSAGetLastError()); 
    }
	
	//At this point, the socket was created successfuly
    printf("Socket created successfully\n");
     
	////////////////////////////////////////////////////
	//This is the information contained in the server struct
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY; //Takes in any address
    server.sin_port = htons( 8888 ); //port number
     
    //This part binds the socket to the IP address and port
    if( bind(s ,(struct sockaddr *)&server , sizeof(server)) == SOCKET_ERROR)
    {
		//Print error message
        printf("Bind failed with error code : %d" , WSAGetLastError());
    }
     
    puts("Binding successful");
 
    //This listens for connections from a client
    listen(s , 3);
     
    //Just wait until we receive a connection
    puts("Waiting for a connection");
     
    c = sizeof(struct sockaddr_in); //This int accepts the size of the address
    new_socket = accept(s , (struct sockaddr *)&client, &c); //Creates a new socket
    //We could change this to a while loop to make this a live server, 
	//constantly accepting new connections
	if (new_socket == INVALID_SOCKET)
    {
		//Tell us if the socket was valid
        printf("accept failed with error code : %d" , WSAGetLastError());
    }
     
    puts("Connection was successful");
 
    //Send a message back to the client
    //message = "You have created a successful connection\n";
	//Send sends the string (message) over to the client
    send(new_socket , message , strlen(message) , 0);
    ///////////////////////////////////////Mutual Authentication///////////////////////////////////
	/*
	printf("Please type in mutual authentication key for client and server:\n");
	scanf("%s", MA);
	printf("Mutual Authentication Password is: %s", MA);
	*/

	//We wait here until we have finished
	system("pause");
 
    closesocket(s);
    WSACleanup();
	return 0;
}

int client_connection(){
	WSADATA wsd; //This is the type for wsd data used in the winsock intiliazation
    SOCKET s; //This is the type for the socket s, used to connect to a server

    struct sockaddr_in server; //The server stores an address, port, family id and an array of zeros
    char *message , reply[3000]; //These are the two strings for sending and receiving a message
    int received_size; //This is the size of the received message

	///////////////////////////////////////////////////////
	//This first part sends a message to initialize winsock,
	//so that we may set up a TCP socket

	printf("initializing winsock\n");
	//MAKEWORD gives us a version for WSAstartup
	if (WSAStartup(MAKEWORD(2,2),&wsd) != 0) //Make sure initialization worked
    {
		//If we dont successfully initialize Winsock, send an error message
        printf("Error! Information for error: %d\n",WSAGetLastError());
		//End the code here
        return 1;
    }

	printf("Initialization was successful\n");

	////////////////////////////////////////////////////
	//Now we create a socket using the socket() function

	//The socket() function accepts the address family, 
	//the type of protocol, and the protocol as paramters.
	//'0' sets the protocol automatically
	if((s = socket(AF_INET , SOCK_STREAM , 0 )) == INVALID_SOCKET) //S receives socket info
    {
		//We can use the WSAGetLastError() function to print the error for debugging
        printf("Socket was not created : %d\n" , WSAGetLastError()); 
    }
	
	//At this point, the socket was created successfuly
    printf("Socket created successfully\n");

	////////////////////////////////////////////////////
	//This is the information contained in the server struct
    server.sin_addr.s_addr = inet_addr("127.0.0.1"); //current address
    server.sin_family = AF_INET;
    server.sin_port = htons( 8888 );

	//Now we make a connection to the server
	//connect() function takes paramaters: socket info s, the entire server struct, and the size of the server address.
    if (connect(s , (struct sockaddr *)&server , sizeof(server)) < 0) 
    {
		//Error connecting to server if connect returns -1
        printf("Did not connect properly\n");
        return 1;
    }
    
	//At this point we know we have connected to the server properly
    printf("Connected properly\n");

	/////////////////////////////////////////////////////
	//Now we will send some information to the server...
	//This messave is an HTTP command to fetch the mainpage of a website
	message = "GET / HTTP/1.1\r\n\r\n";
    if( send(s , message , strlen(message) , 0) < 0)
    {
        printf("Send failed\n");
        return 1;
    }
    printf("Data Sent Successfuly\n");

	/////////////////////////////////////////////////////
	//Receive a reply from the server

	//the received_size integer takes the value from the recv()
	//function call, which takes as paramaters: s data, reply string,
	//length of string, and any flags
    if((received_size = recv(s , reply , 3000 , 0)) == SOCKET_ERROR)
    {
		//we can use puts to send data to stdout without having to return 
        puts("recv failed"); 
    }
     
    puts("Reply received\n");

	////////////////////////////////////////////////////
	//We have to add NULL to the reply string to make it valid
    reply[received_size] = '\0';
    puts(reply); //We print this string to the console

	//We have to close the sockets afterwards, and uninitialize the socket protocol
	closesocket(s);
	WSACleanup();

	//We wait so that we can read the console
	system("pause");

	return 0;
}