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
#include <pthread.h>
#include <dirent.h>

using namespace std;

// ------------------------------- start: struct and global variables -------------------------------
// struct to define a user
struct User{
	char nickname[USERNAME_SIZE];       // username of the user
	EVP_PKEY* user_pubk;                // public key of the user
	bool online=false;                  // indicates if the user is conncted to the server
};

list<User> users;                       // list of the users signed in the server

string mex_serv_listening = "Cloud server operative, waiting for client connection...\n";   // message to be shown after socket settings

// semaphores
pthread_mutex_t users_mutex;            // semaphore for list<User> users

// ------------------------------- end: struct and global variables -------------------------------

// ------------------------------- start: path -------------------------------
string keys_path = "ServerFiles/Keys/";                     // path to users keys folder
string cert_path = "ServerFiles/Certificates/";             // path to certificates folder
string ded_store_path = "ServerFiles/Dedicated_Storage/";   // path to dedicated storage folder

// ------------------------------- end: path -------------------------------

// ------------------------------- start: general function -------------------------------

/*
    Description:    function to show the error message and terminate the programme
    Parameters:     error message
*/
void error(const char *msg)
{
    perror(msg);
    exit(1);
}

// ------------------------------- end: general function -------------------------------

// ------------------------------- start: semaphore management functions -------------------------------
//    Description:  function to initialize the semaphores
void semaphores_init()			
{
	if (pthread_mutex_init(&users_mutex , NULL) != 0)      // initialize mutex for the users list
	{
    	err("Error in the initialization of the semaphore for the user list.\n");  //errore nella creazione del semaforo
	}
}

//    Description:  function to destroy the semaphores
void semaphores_destroy()			
{
    if (pthread_mutex_destroy(&users_mutex) != 0)        // destroy mutex for the users list
    {
        err("Error in the destruction of the semaphore for the user list.\n");     //errore nella creazione del semaforo
	}
}
// ------------------------------- end: semaphore management functions -------------------------------

/*
    Description:  
        function that returns the user's public key corresponding to the username passed as parameter
    Parameters:
        - username: buffer conatining 
    Return:
        - public key of the user
*/
EVP_PKEY* retrieve_user_pubk(string username)
{
    EVP_PKEY* user_pubk;
    string filename = keys_path + username + "_pubk.pem";
    
    FILE* file = fopen(filename.c_str(), "r");                 // open the file containing the pubk  
    if(!file)                                              
    {
    	cerr<<"User " + username + " does not have a key file. The user is not signed or the username isn't correct.\n";
    	exit(1);
    }   
    
    user_pubk = PEM_read_PUBKEY(file, NULL, NULL, NULL);     // read the pubk
    if(!user_pubk) 
    {
        err("User_pubk Error.\n");
    }
    fclose(file);    			// close the file containing the pubk
    
    return user_pubk;			// return the user pubkey
}

/*    
    Description:  function which looks at which registered users there are and adds them to the list of users by entering 
                  the parameters for each.
*/
void users_init()
{
    // read the name of dedicated stored folder (one for each user)
    struct dirent **folder_list;
    char path[ded_store_path.length() + 1]; 
    strcpy(path, ded_store_path.c_str()); 	 // path of the folder to be scanned
    EVP_PKEY* user_pubk;			         // contain pubk of the user
    
    int n;              // number of different folder (user), plus 2
    
    n = scandir(path, &folder_list, 0, alphasort);
    if (n == -1)        // error 
    {
        error("Error in scandir: ");
    }
    
    // scroll through all the folder names found, starts with i = 2 because always the first two positions are occupied by '.' and '..'
    for (int i = 2; i < n; i++ )
    { 
        string file_name = folder_list[i]->d_name;  // take the name of i-th file in the folder
        user_pubk = retrieve_user_pubk(file_name);   // check if there is the corresponding public key
        
        // there are both the key and the dedicated store folder, add the user to users lists
        pthread_mutex_lock(&users_mutex);   // lock users mutex
        
        // check if the user is not already registered
        
        User temp_user;		     // create new user
        // insert parameters in the new user
        strcpy(temp_user.nickname, file_name.c_str());
        temp_user.user_pubk = user_pubk;
        
        users.push_back(temp_user);	     // insert new user in users list
        
        pthread_mutex_unlock(&users_mutex); // unlock users mutex
        
        cout << "Find signed user: " << file_name << "\n";
        
        free(folder_list[i]);               // free structure for this file
    }
    
    free(folder_list);                      // free all structures for the files in the folder
}

// ------------------------------- MAIN -------------------------------
// Argument of the main must be: <program_name> <server port>
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
    
    semaphores_init();              // initialize the semaphores
    users_init();		            // ininitialisation of users registered on the server
    
    // open socket for connection
    sock =  socket(AF_INET, SOCK_STREAM, 0);
    // Sets the flags of the descriptor file to the value specified by arg. Only O_APPEND, O_NONBLOCK and O_ASYNC may be set.
    fcntl(sock, F_SETFL, O_NONBLOCK);
	if (sock < 0)                                              // error in the creation of the socket
    	error("ERROR opening socket");    
    
    memset((char*)&addr_server, 0, sizeof(addr_server));		//cleans, sets the memory zone to 0
    server_port = atoi(argv[1]);
    addr_server.sin_family = AF_INET;  
	addr_server.sin_addr.s_addr = INADDR_ANY;  
	addr_server.sin_port = htons(server_port);
	
	ret = bind(sock, (struct sockaddr *) &addr_server, sizeof(addr_server));
	if ( ret < 0) 
    	error("ERROR on binding");
    	
	clilen = sizeof(cli_addr);
	//Listen on the socket, with 20 max connection requests queued 
    if(listen(sock,MAX_CLIENTS) == 0)
        cout << mex_serv_listening;         // print mex of listening
    else
        err("Error in listen.\n");
        
    // Server in listening
    while(1)
    {
        //Accept call creates a new socket and thread for the incoming connection
	if(users.size()<MAX_CLIENTS)		// check if 
	{
	    int newsocksocket = accept(sock, (struct sockaddr *) &cli_addr, &clilen);
	    if (newsocksocket < 0)
	    { 
    		if (errno != EAGAIN || errno != EWOULDBLOCK)	
    		    error("ERROR on accept");
	    }
	    else
	    {	
	    	cout << "Received connection from ip: " << cli_addr.sin_addr.s_addr << " and port number: " << cli_addr.sin_port << "\n";
	    	/*
		pthread_mutex_lock(&list_mutex);
		User u;
		users.push_back(u);
		Args *args=(Args *)malloc(sizeof(struct Args));

		args->socket=newsocksocket;
		args->arguser=&users.back();
		pthread_t thread;
		threadlist.push_back(thread);
		if(pthread_create(&threadlist.back(), NULL, &client_handler, (void *)args)  != 0 )
		printf("Failed to create thread\n");
		pthread_mutex_unlock(&list_mutex);
		*/
	     }
	 }
     }
}

/*
    NOTE 0:
        The signin phase is not considered in this project to simplify the work and because it is not the focus of the course. 
        In order to consider a user valid (i.e. able to talk to the server and perform the operation), it is checked whether the 
        public key for that username and the "dedcated storage"(folder with the name of the user in "ServerFiles\Dedicated_Storage") 
        are present. If there is not even one of the key and the folder, the user will be considered invalid and will not be able 
        to communicate with the server. In this project, for testing purposes, there are 3 valid usernames "UserA", "UserB" and "UserC".
*/
