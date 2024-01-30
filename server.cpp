/*
    Created on Tue Jan 30 09:10:50 2024
    @author: Alessandro Diana
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <list>           
#include <queue>
#include <thread>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include "common.h"
#include <arpa/inet.h>
#include<pthread.h>

using namespace std;

int main(int argc, char *argv[])
{
    unsigned int counter=0;
	int ret, sock, server_port;
	socklen_t clilen;
	struct sockaddr_in addr_server, cli_addr;
	list<pthread_t> threadlist;

    // check that the correct number of parameters have been passed
    if (argc != 2)		
    {
       printf("Wrong argument number.\nThe correct syntax is  %s <server port>.\n", argv[0]);
       exit(1);
    }
    else             // correct number of parameters have been passed
    {
        if (atol(argv[1]) < 1025)   // correct server port
        {
            cout << "The port number passed as parameter is invalid.\n";
            exit(1);
        }
    }
    
    // open socket for connection
    sock =  socket(AF_INET, SOCK_STREAM, 0);
    // Sets the flags of the descriptor file to the value specified by arg. Only O_APPEND, O_NONBLOCK and O_ASYNC may be set.
    fcntl(sock, F_SETFL, O_NONBLOCK);
	if (sock < 0)                                              // error in the creation of the socket
    	perror("ERROR opening socket");    
    
    memset((char*)&addr_server, 0, sizeof(addr_server));		//cleans, sets the memory zone to 0
    server_port = atoi(argv[1]);
    addr_server.sin_family = AF_INET;  
	addr_server.sin_addr.s_addr = INADDR_ANY;  
	addr_server.sin_port = htons(server_port);
	
	ret = bind(sock, (struct sockaddr *) &addr_server, sizeof(addr_server));
	if ( ret < 0) 
	{
    	perror("ERROR on binding");
    	exit(1);
	}
    	
	clilen = sizeof(cli_addr);
	//Listen on the socket, with 20 max connection requests queued 
    if(listen(sock,MAX_CLIENTS) == 0)
        printf("Listening\n");
    else
    {
        printf("Error\n");
        exit(1);
    }
        
    
    
}

