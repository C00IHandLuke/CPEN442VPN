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

int main(int argc , char *argv[]){
	WSADATA wsd; //This is the type for wsd data used in the winsock intiliazation
    SOCKET s, new_socket; //This is the type for the socket s, used to connect to a server

	//The server stores an address, port, family id and an array of zeros
    struct sockaddr_in server , client;
    int c;
	char *client_message, *server_message , reply[3000]; //These are the two strings for sending and receiving a message
    int received_size; //This is the size of the received message

    //Let user decide which type of machine this will be
	char type;
	printf("Please enter s for server or c for client.\n");
	while (((type = getchar()) != 's') && (type != 'c')) {
		printf("you typed in the inproper system type, please try again!\n");
		type = getchar();
	}

	//In this part, I am going to integrate both the client and server in main
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

    //If we are a server, then we will continue as follows
	if (type == 's'){
		server.sin_family = AF_INET;
    	server.sin_addr.s_addr = INADDR_ANY; //Takes in any address
    	//Port number will have to start off being the same as the client
    	server.sin_port = htons( 8888 ); 

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
	    server_message = "You have created a successful connection\n";
		//Send sends the string (message) over to the client
	    send(new_socket , server_message , strlen(server_message) , 0);
	}

	//If we are a client, then the communication will be as follows
	else if(type == 'c'){
		//then we want to modify the server address and port
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

		///////////////////////////////////////////////////////////////////
		//Now we will send some information to the server...
		//This messave is an HTTP command to fetch the mainpage of a website
		client_message = "GET / HTTP/1.1\r\n\r\n";
	    if( send(s , client_message , strlen(client_message) , 0) < 0)
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
	}
	//We wait here until we have finished
	system("pause");
 
    closesocket(s);
    WSACleanup();
    return 0;
}