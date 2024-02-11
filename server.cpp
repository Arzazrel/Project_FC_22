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
struct User
{
	char username[USERNAME_SIZE];       // username of the user
	EVP_PKEY* user_pubk;                // public key of the user
	unsigned int server_counter = 0;    // is the server nonce, is used for nonce in the messages sent by the server
	unsigned int client_counter = 0;    // is the client nonce, is used to verify the nonce in the messages sent by the client
	bool online = false;                // indicates if the user is connected to the server
};

list<User> users;                           // list of the users signed in the server

// struct to contain utility parameter for one client connection
struct Args
{
	int socket;                        // socket of the client connection
	User* user_ref;                    // reference to the user structure linked to the connected client user
	unsigned char* session_key = NULL;  // contain the session key between the server and the client with which the user has connected
	
};

string mex_serv_listening = "Cloud server operative, waiting for client connection...\n";   // message to be shown after socket settings
string mex_AE_conn_succ = "Successful authenticated and protected connection between client and server.\n";     // message of successful authenticated and protected connection between client and server
string mex_close_conn_succ = "Successfully closed the secure and authenticated connection with the server.\n";  // message of successfully closed the secure and authenticated connection
string mex_del_op = " file found in the cloud. Do you want to delete it?\nEnter y for confirm\nEnter n for denied.\n";    // message to be shown to confirm request in delete operation
// Error message when verifying the username when closing the connection
string mex_close_conn_err =  "ERROR: The username sent in the closing request does not match the user served. The connection will be closed..\n";
string mex_user_file_list_err = "ERROR: The username sent in the file list request does not match the user served.\n"; // Error message when verifying the username when retrieve the user file list

// semaphores
pthread_mutex_t users_mutex;            // semaphore for list<User> users
           

// ------------------------------- end: struct and global variables -------------------------------

// ------------------------------- start: path -------------------------------
string keys_path = "ServerFiles/Keys/";                     // path to users keys folder
string cert_path = "ServerFiles/Certificates/";             // path to certificates folder
string ded_store_path = "ServerFiles/Dedicated_Storage/";   // path to dedicated storage folder
string serv_cert_path = "ServerFiles/Certificates/s_cert";  // path to server certificate
string serv_privk_path = keys_path + "s_privk.pem";         // path to server private key

// ------------------------------- end: path -------------------------------

// ------------------------------- start: general function -------------------------------

//    Description:    function to retrieve the server certificate
X509* get_server_certificate()
{
    X509* server_cert;

    FILE* cert_file = fopen(serv_cert_path.c_str(), "r");                // open server certificate file
	if(!cert_file) 
    	error("Error in opening the server certificate.\n");
	
	server_cert = PEM_read_X509(cert_file, NULL, NULL, NULL);    // read server certificate
	if(!server_cert) 
    	error("Error in PEM_read_bio_X509 returned NULL\n");
	fclose(cert_file);                                          // close server certificate file
	
	return server_cert;        // return server certificate
}

//    Description:    function to retrieve the server private key
EVP_PKEY* get_server_private_key()
{
    EVP_PKEY* s_privk;
    
    FILE* s_key_file = fopen(serv_privk_path.c_str(), "r");                 // open server private key file
	if(!s_key_file) 
    	error("Error in opening the server private key pem file.\n");
	
	s_privk = PEM_read_PrivateKey(s_key_file, NULL, NULL, NULL);    // read server private key
	if(!s_privk) 
    	error("Error in PEM_read_PrivateKey returned NULL.\n");
	fclose(s_key_file);                                             // close server private key file
	
	return s_privk;        // return server private key
}

// ------------------------------- end: general function -------------------------------

// ------------------------------- start: semaphore management functions -------------------------------
//    Description:  function to initialize the semaphores
void semaphores_init()			
{
	if (pthread_mutex_init(&users_mutex , NULL) != 0)          // initialize mutex for the users list
	{
    	error("Error in the initialization of the semaphore for the user list.\n");    // error in the creation of the semaphore
	}
}

//    Description:  function to destroy the semaphores
void semaphores_destroy()			
{
    if (pthread_mutex_destroy(&users_mutex) != 0)        // destroy mutex for the users list
    {
        error("Error in the destruction of the semaphore for the user list.\n");     // error in the destruction of the semaphore
	}
}
// ------------------------------- end: semaphore management functions -------------------------------

// ------------------------------- start: functions to perform the operations required by the client -------------------------------
/*
    Description:  
        function that returns the list of files contained in the user's dedicated storage(folder) 
        of the user passed as parameter(cmd_code = 1).
    Parameters:
        - socket: client socket to send the list
        - current_user: reference to the user
        - session_key: the symmetric session key between the client and the server
*/
void send_user_file_list(int socket, User* current_user, unsigned char* session_key)
{
    // read the name of dedicated stored folder 
    struct dirent **folder_list = 0;
    char** file_name = 0;           // contain the name of the file in the folder
    unsigned char* message;         // contain the message to be sent
    int ret;
    
    string path = ded_store_path + "/" + current_user->username;  // path of the folder to be scanned
    
    unsigned int msg_len = 0;
    int n;              // number of different folder (user), plus 2
    
    n = scandir(path.c_str(), &folder_list, 0, alphasort);      // scan folder
    if (n == -1)        // error 
    {
        error("Error in scandir.\n");
    }
    // check if there are files in the folder
    if ( n <= 2)	// folder is empty 
    {
    	 char temp[] = "Dedicated stored empty.\n";
    	 msg_len = strlen(temp) + 1;			// update msg_len
    	 message = (unsigned char*)malloc(msg_len);
    	 if(!message)
        	error("Error in user_file_list: message Malloc error.\n");
    	 memcpy(message, temp, msg_len);        // copy in message
    }
    else    // there are files in the dedicated storage
    {
    	file_name = (char**)malloc((n-2)*sizeof(char*));	//
    	int temp_len;					//
        // scroll through all the folder names found, starts with i = 2 because always the first two positions are occupied by '.' and '..'
        for (int i = 2; i < n; i++ )
        { 
            temp_len = strlen(folder_list[i]->d_name) + 1;
            file_name[i-2] = (char*)malloc(temp_len);
            // take the name of i-th file in the
            memcpy(file_name[i-2], folder_list[i]->d_name, temp_len - 1);
            file_name[i-2][temp_len-1] = '\0';
            
            msg_len += temp_len;      	  // update size, one more for \n
                    
            free(folder_list[i]);               // free structure for this file
        }
        free(folder_list);                      // free all structures for the files in the folder
        
        // format correctly the file list to be sent
        message = (unsigned char*)malloc(msg_len);
    	if(!message)
        	error("Error in user_file_list: message Malloc error.\n");
        msg_len = 0;                        // reset
        // scan all filename
    	for (int i = 0; i < (n-2); i++)
    	{
        	memcpy(message + msg_len, file_name[i], strlen(file_name[i]));
        	msg_len += strlen(file_name[i]);          // update msg_len for strlen
        	memcpy(message + msg_len, "\n", 1);
        	msg_len += 1;                          // update msg_len of 1
        	
        	free(file_name[i]);               // free structure for this file
    	}
    	memcpy(message + msg_len - 1, "\0", 1);       
    }
    
    cout << "++++++ user_file_list message: " << message << "\n";      // +++++++++++++ test mode +++++++++++++
    
    // send message
    unsigned char* aad = (unsigned char*)malloc(sizeof(unsigned int));  // in this case aad is only the server nonce
	if(!aad)
    	error("Error in user_file_list: aad Malloc error.\n");
    
    memcpy(aad,(unsigned char*)&current_user->server_counter,sizeof(unsigned int));  // copy server nonce in aad
	
	unsigned char* buffer = (unsigned char*)malloc(MAX_SIZE);      // temp buffer for message 
	if(!buffer)
    	error("Error in user_file_list: buffer Malloc error.\n");
	
	// encrypt the message, cmd_code for the operation list is 1
	ret = encryptor(1,aad, sizeof(unsigned int), message, msg_len , session_key, buffer);
	if (ret >= 0)      // successfully encrypted
	{
		send_msg(socket, ret, buffer);            // send user file list to client
		
		inc_counter_nonce(current_user->server_counter);  // update server counter
	}
	cout << "User file list sent to the user: " << current_user->username << ".\n\n";
	// free all
	free(buffer);      // free buffer containing the encrypted message
	free(message);     // free the buffer containing the cleartext message (user file list)
	free(aad);         // free aad (in this case the server nonce)
	free(file_name); 
}

/*
    Description:  
        function that handle the user's request to see the list of files in its dedicated storage (folder)
    Parameters:
        - socket: client socket to send the list
        - current_user: reference to the user
        - session_key: the symmetric session key between the client and the server
        - rec_username: the received username
        - rec_username_size: the size of the received username
*/
void handle_user_file_list_req(int socket, User* current_user, unsigned char* session_key, unsigned char* rec_username, unsigned int rec_username_size)
{
    unsigned char* message;         // contain the message to be sent
    unsigned int msg_len = 0;       // len of the message sent or received
    int ret;
    short cmd_code = 1;
    char* rec_user = (char*)rec_username;
    
    // check the received username
    if( (rec_username_size < USERNAME_SIZE) && (strcmp(rec_user, current_user->username) == 0))     // received username equal to the username of current user
    {
        // all is ok, call the function to take and to send the list
        send_user_file_list(socket, current_user, session_key);
    } 
    else            // received username is not equal to the username of current user
    {
        // set error message
        cmd_code = -1;
        msg_len = strlen(mex_user_file_list_err.c_str()) + 1;			// update msg_len
       	message = (unsigned char*)malloc(msg_len);
       	if(!message)
           	error("Error in close_user_conn: message Malloc error.\n");
       	memcpy(message, mex_user_file_list_err.c_str(), msg_len);        // copy in message
       	
       	// set aad
        unsigned char* aad = (unsigned char*)malloc(sizeof(unsigned int));  // in this case aad is only the server nonce
       	if(!aad)
            error("Error in user_file_list: aad Malloc error.\n");
        memcpy(aad,(unsigned char*)&current_user->server_counter,sizeof(unsigned int));  // copy server nonce in aad
       	
       	// set buffer
       	unsigned char* buffer = (unsigned char*)malloc(MAX_SIZE);      // temp buffer for message 
       	if(!buffer)
           	error("Error in user_file_list: buffer Malloc error.\n");
           
        // encrypt message
        ret = encryptor(cmd_code, aad, sizeof(unsigned int), message, msg_len , session_key, buffer);
       	if (ret >= 0)      // successfully encrypted
       	{
           	// send error message
       		send_msg(socket, ret, buffer);                     // send user file list to client
       		inc_counter_nonce(current_user->server_counter);   // update server counter
       	}
       	// free all
        free(buffer);          // free buffer containing the encrypted message
       	free(message);         // free the buffer containing the cleartext message (user file list)
    	free(aad);             // free aad 8in this case the server nonce
    }
}

/*
    Description:  
        function that handle the user's request to rename one file in its dedicated storage (folder)
    Parameters:
        - socket: client socket to send the list
        - current_user: reference to the user
        - session_key: the symmetric session key between the client and the server
        - buffer: buffer that contain all the received message
        - cleartext: the received username
        - cleartext_size: the size of the received username
*/
void handle_rename_req(int socket, User* current_user, unsigned char* session_key, unsigned char* buffer ,unsigned char* cleartext, unsigned int cleartext_size)
{
    unsigned char* message = 0;     // contain the message to be sent
    unsigned int msg_len = 0;       // len of the message sent or received
    unsigned int aad_len;
    int ret;
    short cmd_code = 4;
    
    cout << "Rename request arrived from user: " << current_user->username << ".\n";
    
    // check the received cleartext. cleartext is composed of the old and the new name
    if( cleartext_size > (2 * MAX_DIM_FILE_NAME) )     
    {
        // set error mex
        cmd_code = -1;
        char temp[] = "The file names are too bigs.\n";
        msg_len = strlen(temp) + 1;       // update msg_len
       	message = (unsigned char*)malloc(msg_len);
       	if(!message)
           	error("Error in handle_rename_req: message Malloc error.\n");
       	memcpy(message, temp, msg_len);         // copy in message
    }
    else
    {
        // take file names size
        unsigned int old_n_len;     // take old file name len
        unsigned int new_n_len;     // take new file name len
        
        aad_len = *(unsigned int*)(buffer + MSG_AAD_OFFSET - sizeof(unsigned int)) ;
        cout << "+++++++++ " << "aad size: " << aad_len << " cleartext size: " << cleartext_size << "\n";
        
        old_n_len =*(unsigned int*)(buffer + MSG_AAD_OFFSET + sizeof(unsigned int));   //take the received client nonce
        new_n_len =*(unsigned int*)(buffer + MSG_AAD_OFFSET + sizeof(unsigned int) + sizeof(unsigned int));   //take the received client nonce
        
        cout << "+++++++++ " << "old file name size: " << old_n_len << " sizeoff: " << sizeof(unsigned int) << "\n";
        cout << "+++++++++ " << "new file name size: " << new_n_len << " sizeoff: " << sizeof(unsigned int) << "\n";
        
        char* old_file_name = (char*)malloc(old_n_len);    // buffer for old file name
        char* new_file_name = (char*)malloc(new_n_len);    // buffer for new file name
        
        memcpy(old_file_name, cleartext, old_n_len);                  // copy in message
        memcpy(new_file_name, cleartext + old_n_len, new_n_len);      // copy in message
        
        string old_s = old_file_name;   // string to contain the old file name
        string new_s = new_file_name;   // string to contain the new file name
        
        cout << "+++++++++ " << "old file name: " << old_file_name << " " << old_s << "\n";
        cout << "+++++++++ " << "new file name: " << new_file_name << " " << new_s << "\n";
        
        // white list control
        if ( check_file_name(old_s) && check_file_name(new_file_name))
        {
            // strings are correct
            string old_path = ded_store_path + current_user->username + "/" + old_file_name;
            // -- verify that the file with the old file name exist, if exist return 0 otherwhise return -1
            if(access(old_path.c_str(), F_OK ) == -1)                                                 // target file control check
            {
                // set error mex
                cmd_code = -1;
                char temp[] = "The file specified by the name passed as a parameter is not present on the server.\n";
                msg_len = strlen(temp) + 1;       // update msg_len
               	message = (unsigned char*)malloc(msg_len);
               	if(!message)
                   	error("Error in handle_rename_req: message Malloc error.\n");
               	memcpy(message, temp, msg_len);         // copy in message
            }
            else        // the file xist
            {
                // verify that the file with the new file name exist, if exist return 0 otherwhise return -1
                string new_path = ded_store_path + current_user->username + "/" + new_file_name;
                if(access(new_path.c_str(), F_OK ) == -1)                                                 // target file control check
                {
                    // the file dosn't exist, can rename the old file wih the new file
                    ret = rename(old_path.c_str() , new_path.c_str());          // rename file 
                    if ( ret == 0 )      // succesfully renamed
                    {
                        char temp[] = "File successfully renamed.\n";
                        msg_len = strlen(temp) + 1;       // update msg_len
                       	message = (unsigned char*)malloc(msg_len);
                       	if(!message)
                           	error("Error in handle_rename_req: message Malloc error.\n");
                       	memcpy(message, temp, msg_len);         // copy in message
                    }
                    else            // rename failed
                    {
                        // set error mex
                        cmd_code = -1;
                        char temp[] = "Rename failed.\n";
                        msg_len = strlen(temp) + 1;       // update msg_len
                       	message = (unsigned char*)malloc(msg_len);
                       	if(!message)
                           	error("Error in handle_rename_req: message Malloc error.\n");
                       	memcpy(message, temp, msg_len);         // copy in message
                    }
                }
                else    // already exist a file named as the new name specified, you cannot rename the file with this new file name
                {
                    // set error mex
                    cmd_code = -1;
                    char temp[] = "Error: already exist a file named as the new name specified, you cannot rename the file with this new file name.\n";
                    msg_len = strlen(temp) + 1;       // update msg_len
                   	message = (unsigned char*)malloc(msg_len);
                   	if(!message)
                       	error("Error in handle_rename_req: message Malloc error.\n");
                   	memcpy(message, temp, msg_len);         // copy in message
                }
            }
            
        }
        else        // strings aren't correct
        {
            // set error mex
            cmd_code = -1;
            char temp[] = "The file names passed did not pass the white list check, they have characters that are not allowed in them.\n";
            msg_len = strlen(temp) + 1;       // update msg_len
           	message = (unsigned char*)malloc(msg_len);
           	if(!message)
               	error("Error in handle_rename_req: message Malloc error.\n");
           	memcpy(message, temp, msg_len);         // copy in message
        }
        
        // free all
        free(old_file_name);    
        free(new_file_name);
    }
    
    // 2) send response
    // -- set aad (nonce)
    unsigned char* aad = (unsigned char*)malloc(sizeof(unsigned int));  // in this case aad is only the server nonce
	if(!aad)
        error("Error in user_file_list: aad Malloc error.\n");
    memcpy(aad,(unsigned char*)&current_user->server_counter,sizeof(unsigned int));  // copy server nonce in aad
	
	// -- set buffer
	unsigned char* buff = (unsigned char*)malloc(MAX_SIZE);      // temp buffer for message 
	if(!buff)
    	error("Error in user_file_list: buff Malloc error.\n");
    
    // encrypt message
    ret = encryptor(cmd_code, aad, sizeof(unsigned int), message, msg_len , session_key, buff);
	if (ret >= 0)      // successfully encrypted
	{
    	// send error message
		send_msg(socket, ret, buff);                     // send user file list to client
		inc_counter_nonce(current_user->server_counter);   // update server counter
	}
	
	// free all
    free(buff);          // free buffer containing the encrypted message
	free(message);         // free the buffer containing the cleartext message (user file list)
	free(aad);             // free aad 8in this case the server nonce
}

/*
    Description:  
        function that set offline an user
    Parameters:
        - username: username of the user to be checked
*/
void set_user_offline(char* username)
{	
	pthread_mutex_lock(&users_mutex);   // lock users mutex
	
	// scroll all the users list
	for(list<User>::iterator it=users.begin(); it != users.end();it++)
	{
		if(strcmp(it->username, username) == 0)       // check if the current user is the searched user
		{
			it->online = false;                   // set user as online
		}
	}
	
	pthread_mutex_unlock(&users_mutex); // unlock users mutex
}

/*
    Description:  
        function that close the connection with an user
    Parameters:
        - socket: client socket to send the list
        - current_user: reference to the user
        - session_key: the symmetric session key between the client and the server
        - rec_username: the received username
        - rec_username_size: the size of the received username
*/
void close_user_conn(int socket, User* current_user, unsigned char* session_key, unsigned char* rec_username, unsigned int rec_username_size)
{
    unsigned char* message = 0;     // contain the message to be sent
    unsigned int msg_len = 0;       // len of the message sent or received
    int ret;
    short cmd_code = 0;
    char* rec_user = (char*)rec_username;
    
    // check the received username
    if( (rec_username_size < USERNAME_SIZE) && (strcmp(rec_user, current_user->username) == 0))     // received username equal to the username of current user
    {
        // set ok message
        msg_len = strlen(mex_close_conn_succ.c_str()) + 1;			// update msg_len
       	message = (unsigned char*)malloc(msg_len);
       	if(!message)
           	error("Error in close_user_conn: message Malloc error.\n");
       	memcpy(message, mex_close_conn_succ.c_str(), msg_len);        // copy in message
    } 
    else            // received username is not equal to the username of current user
    {
        // set error message
        cmd_code = -1;
        msg_len = strlen(mex_close_conn_err.c_str()) + 1;			// update msg_len
       	message = (unsigned char*)malloc(msg_len);
       	if(!message)
           	error("Error in close_user_conn: message Malloc error.\n");
       	memcpy(message, mex_close_conn_err.c_str(), msg_len);        // copy in message
    }
    
    // set aad
    unsigned char* aad = (unsigned char*)malloc(sizeof(unsigned int));  // in this case aad is only the server nonce
	if(!aad)
    	error("Error in user_file_list: aad Malloc error.\n");
    memcpy(aad,(unsigned char*)&current_user->server_counter,sizeof(unsigned int));  // copy server nonce in aad
	
	// set buffer
	unsigned char* buffer = (unsigned char*)malloc(MAX_SIZE);      // temp buffer for message 
	if(!buffer)
    	error("Error in user_file_list: buffer Malloc error.\n");
    
    // encrypt message
    ret = encryptor(cmd_code, aad, sizeof(unsigned int), message, msg_len , session_key, buffer);
	if (ret >= 0)      // successfully encrypted
	{
    	// send message
		send_msg(socket, ret, buffer);            // send user file list to client
		// there is no need to increment the server_counter. the connection is being closed, 
		// no further messages will be sent for this session.
	}
    
    // set user as offline in the users list
    set_user_offline(current_user->username);
    
    cout << "The thread that serves the user: " << current_user->username << " has completed its task, connection closed.\n";
    // free all
    free(session_key);     // free the session key	
    free(buffer);          // free buffer containing the encrypted message
	free(message);         // free the buffer containing the cleartext message (user file list)
	free(aad);             // free aad 8in this case the server nonce
	
	// close connection
	close(socket);         // close the socket
	pthread_exit(NULL);    // terminate the thread
	return;
}

/*
    Description:  
        function that handle the user's request delete one file in its dedicated storage (folder)
    Parameters:
        - socket: client socket to send the list
        - current_user: reference to the user
        - session_key: the symmetric session key between the client and the server
        - cleartext: the received username
        - cleartext_size: the size of the received username
*/
void handle_delete_req(int socket, User* current_user, unsigned char* session_key, unsigned char* cleartext, unsigned int cleartext_size)
{
    unsigned char* message = 0;     // contain the message to be sent
    unsigned int msg_len = 0;       // len of the message sent or received
    unsigned int aad_len;
    int ret;
    short cmd_code = 5;
    char* temp_f_n = (char*)malloc(cleartext_size);    // buffer for file name
    memcpy(temp_f_n, cleartext, cleartext_size);       // copy in message
    string file_name = temp_f_n;    // string for file name
    string path;                    // string for complete path of the specified file
    
    cout << "Delete request arrived from user: " << current_user->username << ".\n";
    
    // check the received cleartext. cleartext is composed of the name of the file to be deleted
    if( cleartext_size > (MAX_DIM_FILE_NAME) )     // check if the file name exceed the maximum len allowed
    {
        // set error mex
        cmd_code = -1;
        char temp[] = "The file names are too bigs.\n";
        msg_len = strlen(temp) + 1;       // update msg_len
       	message = (unsigned char*)malloc(msg_len);
       	if(!message)
           	error("Error in handle_delete_req: message Malloc error.\n");
       	memcpy(message, temp, msg_len);         // copy in message
    }
    else
    {
        // 1) receive user request and verify
        // -- verify the file name 
        cout << "+++++++++ " << "file name: " << file_name << "\n";
        
        // white list control
        if (check_file_name(file_name))     // name is OK
        {
            // -- check if exist the specified file
            path = ded_store_path + current_user->username + "/" + file_name;
            if(access(path.c_str(), F_OK ) == 0)         // if exist return 0 otherwhise return -1
            {
                // set the message for the confirm or not
                string temp = temp_f_n + mex_del_op;
                msg_len = strlen(temp) + 1;       // update msg_len
               	message = (unsigned char*)malloc(msg_len);
               	if(!message)
                   	error("Error in handle_delete_req: message Malloc error.\n");
               	memcpy(message, temp, msg_len);         // copy in message
            }
            else        // the file to be deleted there isn't
            {
                // set error mex
                cmd_code = -1;
                char temp[] = "Error: the specified file is not present in the cloud, it cannot be deleted.\n";
                msg_len = strlen(temp) + 1;       // update msg_len
               	message = (unsigned char*)malloc(msg_len);
               	if(!message)
                   	error("Error in handle_delete_req: message Malloc error.\n");
               	memcpy(message, temp, msg_len);         // copy in message
            }
        }
        else        // name isn't ok
        {
            // set error mex
            cmd_code = -1;
            char temp[] = "Error: the file names passed did not pass the white list check, they have characters that are not allowed in them.\n";
            msg_len = strlen(temp) + 1;       // update msg_len
           	message = (unsigned char*)malloc(msg_len);
           	if(!message)
               	error("Error in handle_delete_req: message Malloc error.\n");
           	memcpy(message, temp, msg_len);         // copy in message
        }
    
        cout << "+++++++++ " << "Message in the response: " << message << "\n";     // +++++++++++++++++++++++++++++
        // 2) send to the user the delete confirmation
        // -- set aad (nonce)
        unsigned char* aad = (unsigned char*)malloc(sizeof(unsigned int));  // in this case aad is only the server nonce
    	if(!aad)
            error("Error in handle_delete_req: aad Malloc error.\n");
        memcpy(aad,(unsigned char*)&current_user->server_counter,sizeof(unsigned int));  // copy server nonce in aad
    	
    	// -- set buffer
    	unsigned char* buff = (unsigned char*)malloc(MAX_SIZE);      // temp buffer for message 
    	if(!buff)
        	error("Error in handle_delete_req: buff Malloc error.\n");
        
        // encrypt message
        ret = encryptor(cmd_code, aad, sizeof(unsigned int), message, msg_len , session_key, buff);
    	if (ret >= 0)      // successfully encrypted
    	{
        	// send error message
    		send_msg(socket, ret, buff);                     // send user file list to client
    		inc_counter_nonce(current_user->server_counter);   // update server counter
    	}
        
        // free all
        free(buff);         // free buffer containing the encrypted message
    	free(message);      // free the buffer containing the cleartext message (user file list)
    	free(aad);          // free aad 8in this case the server nonce
    	
        // 3) receive delete confirmation and perform or block the operation
        // -- set buffer
    	unsigned char* buff = (unsigned char*)malloc(MAX_SIZE);      // temp buffer for message 
    	if(!buff)
        	error("Error in handle_delete_req: buff Malloc error.\n");
        	
        // -- set aad (nonce)
        unsigned char* aad = (unsigned char*)malloc(sizeof(unsigned int));  // in this case aad is only the server nonce
    	if(!aad)
            error("Error in handle_delete_req: aad Malloc error.\n");
        memcpy(aad,(unsigned char*)&current_user->server_counter,sizeof(unsigned int));  // copy server nonce in aad
        
        unsigned char* message = (unsigned char*)malloc(MAX_SIZE);
    	if(!message)
        	error("Error in handle_delete_req: message Malloc error.\n");
        	
        unsigned char* send_mex;                // for contain the mex to be sent
        unsigned int received_counter;          // for contain the received nonce
        
        msg_len = receive_msg(socket,buff);     // take the len of the response mex from user
    	
    	received_counter =*(unsigned int*)(buff + MSG_AAD_OFFSET);  //take the received client nonce
    	// check if the nonce is correct
    	if(received_counter == current_user->client_counter)          // if is equal is correct otherwhise the message is not fresh
    	{
        	ret = decryptor(buffer, msg_len, session_key, cmd_code, aad, aad_len, message);  // decrypt the received message
        	inc_counter_nonce(current_user->client_counter);          // increment the client nonce		
        	
        	// -- check if the user confirm or not the delete
        	char choice =*(char*)(message);
        	cout << "+++++++++ " << "user response: " << choice << "\n";     // +++++++++++++++++++++++++++++
        	if((choice == 'y') || (choice == 'Y'))         // user confirm delete 
        	{
            	// delete the file 
            	if (remove(path.c_str()) == 0)     // return 0​ on success or non-zero value on error. 
            	{
                	// set the message for the confirm or not
                    char temp[] = "File successfully deleted.\n";
                    msg_len = strlen(temp) + 1;       // update msg_len
                   	send_mex = (unsigned char*)malloc(msg_len);
                   	if(!send_mex)
                       	error("Error in handle_delete_req: send_mex Malloc error.\n");
                   	memcpy(send_mex, temp, msg_len);         // copy in message
                }
            	else       // delete failed
            	{
                	// set error mex
                    cmd_code = -1;
                    char temp[] = "Error: delete operation failed.\n";
                    msg_len = strlen(temp) + 1;       // update msg_len
                   	send_mex = (unsigned char*)malloc(msg_len);
                   	if(!send_mex)
                       	error("Error in handle_delete_req: send_mex Malloc error.\n");
                   	memcpy(send_mex, temp, msg_len);         // copy in message
            	}
        	}
        	else if((choice == 'n') || (choice == 'N'))     // user doesn't confirm delete
        	{
            	cout << "Delete operation of the file: " << file_name << " for the user: " << current_user->username << " blocked by the user.\n";
            	// set the response for the user
                char temp[] = "Delete operation successfully blocked, the file was not deleted.\n";
                msg_len = strlen(temp) + 1;       // update msg_len
               	send_mex = (unsigned char*)malloc(msg_len);
               	if(!send_mex)
                   	error("Error in handle_delete_req: send_mex Malloc error.\n");
               	memcpy(send_mex, temp, msg_len);         // copy in message
        	}
        	else           // user send incorrect choice
        	{
            	// set error mex
                cmd_code = -1;
                char temp[] = "Error: user choice not recognised. delete operation failed..\n";
                msg_len = strlen(temp) + 1;       // update msg_len
               	send_mex = (unsigned char*)malloc(msg_len);
               	if(!send_mex)
                   	error("Error in handle_delete_req: send_mex Malloc error.\n");
               	memcpy(send_mex, temp, msg_len);         // copy in message
        	}
    	}
    	else
        	cerr << err_rec_nonce;         // print mex error
    	
    	// free all
        free(buff);         // free buffer containing the encrypted message
    	free(message);      // free the buffer containing the cleartext message (user file list)
    	free(aad);          // free aad in this case the server nonce
    	
    	// 4) send the final response of the delete opration
        // -- set aad (nonce)
        unsigned char* aad = (unsigned char*)malloc(sizeof(unsigned int));  // in this case aad is only the server nonce
    	if(!aad)
            error("Error in handle_delete_req: aad Malloc error.\n");
        memcpy(aad,(unsigned char*)&current_user->server_counter,sizeof(unsigned int));  // copy server nonce in aad
    	
    	// -- set buffer
    	unsigned char* buff = (unsigned char*)malloc(MAX_SIZE);      // temp buffer for message 
    	if(!buff)
        	error("Error in handle_delete_req: buff Malloc error.\n");
        
        // encrypt message
        ret = encryptor(cmd_code, aad, sizeof(unsigned int), send_mex, msg_len , session_key, buff);
    	if (ret >= 0)      // successfully encrypted
    	{
        	// send error message
    		send_msg(socket, ret, buff);                      // send user file list to client
    		inc_counter_nonce(current_user->server_counter);  // update server counter
    	}
    	
        // free all
        free(buff);         // free buffer containing the encrypted message
    	free(send_mex);      // free the buffer containing the cleartext message (user file list)
    	free(aad);          // free aad in this case the server nonce
    }
}
// ------------------------------- end: functions to perform the operations required by the client -------------------------------

// ------------------------------- start: function to manage registered user -------------------------------
/*
    Description:  
        function that returns if the user associated with the username passed as parameter is correcty logged in the server or not
    Parameters:
        - username: username of the user to be checked
        - c_user: reference to the user
    Return:
        bool : user* -> if the user is valid , NULL -> if the user isn't valid
*/
bool check_user_signed(string username, User* c_user)
{
	bool found = false;	// indicate if the user is found or not
	
	pthread_mutex_lock(&users_mutex);   // lock users mutex
	
	// scroll all the users list
	for(list<User>::iterator it=users.begin(); it != users.end();it++)
	{
		if(strcmp(it->username, username.c_str()) == 0)       // check if the current user is the searched user
		{
			// copy value in c_user
			strncpy(c_user->username, username.c_str(), strlen(username.c_str()) + 1);
			c_user->user_pubk = it->user_pubk;
			c_user->server_counter = it->server_counter;
			c_user->client_counter = it->client_counter;
			c_user->online = it->online;
			cout << "User " << c_user->username << " found among registered users.\n";
			it->online = true;                   // set user as online
			pthread_mutex_unlock(&users_mutex);  // unlock users mutex
			return true;	// return the user	
		}
	}
	
	pthread_mutex_unlock(&users_mutex); // unlock users mutex
	
	cerr << "User not found among registered users.\n";
	return false;
}

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
        error("User_pubk Error.\n");
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
        strcpy(temp_user.username, file_name.c_str());
        temp_user.user_pubk = user_pubk;
        
        users.push_back(temp_user);	     // insert new user in users list
        
        pthread_mutex_unlock(&users_mutex); // unlock users mutex
        
        cout << "Find signed user: " << file_name << "\n";
        
        free(folder_list[i]);               // free structure for this file
    }
    
    free(folder_list);                      // free all structures for the files in the folder
}

/*
    Description:   (function for threads)
        function that handles clients just connected to the server, verifying the user 
        and then establishing a secure and authenticated session.
    Parameters:
        - arguments: a agrs struct (contain username, reference to user struct and session key)
*/
void *client_handler(void* arguments) 
{
    int ret;
    Args *args = (Args*) arguments;    // take argument in args struct
	int socket = args->socket;         // take socket associated with the client     
	User u;                            // create a new user struct that rapresent the current user for this thread    
	User* current_user = &u;           // user associeted with connected client
	
	uint32_t networknumber;
	unsigned int clientnumber;
	unsigned int received = 0;
	// allocate utility buffers
	unsigned char* buffer = (unsigned char*)malloc(MAX_SIZE);
	if(!buffer)
    	error("Error in the connection establishment: buffer Malloc error.\n");
	
	unsigned char* message = (unsigned char*)malloc(MAX_SIZE);
	if(!message)
    	error("Error in the connection establishment: message Malloc error.\n");
	
	unsigned char* aad = (unsigned char*)malloc(MAX_SIZE);
	if(!aad)
    	error("Error in the connection establishment: aad Malloc error.\n");
    
    // 1) receive signature and username of the client, messages format is -> ( size_sign | sign | nonce | username )
    int msg_size = receive_msg(socket, buffer);           //receive messages from client
	if(msg_size == 0)
    	error("Error in the connection establishment: receive signed message.\n");
    
    unsigned int sgnt_size=*(unsigned int*)buffer;
	sgnt_size += sizeof(unsigned int);
    unsigned int username_size = msg_size - sgnt_size - NONCE_SIZE; // take size of username
    // -- control check for username size
    if(username_size <= 0)
        error("Error in the connection establishment: username absent.\n");
    if(username_size >= USERNAME_SIZE)
        error("Error in the connection establishment: username too long.\n");
    
    // -- take and correctly format the received username
    char username[username_size+1];	            // buffer for the username
    memcpy(username, buffer + sgnt_size + NONCE_SIZE, username_size);
	username[username_size]='\0';       
	cout << "The user: " << username << " tries to establish a secure, authenticated connection.\n\n";       
   
    // -- verify the received username
    if (check_user_signed(username, current_user) == false)
        error("Error in the connection establishment: unregistered user.\n");
        
    bool temp_curr_user_online = current_user->online;
    
    // user is already online (connected to the server) no more connections will be accepted at the same time for the same user
    if (temp_curr_user_online)          
    {
        cerr << "Error in the connection establishment: user is already online.\n";
        return NULL;       // ++++++++++++++++++++++ to modify for close connection  ++++++++++++++++++++++
    }
    
	// -- username is correct and user is not online
	pthread_mutex_lock(&users_mutex);              // lock users_mutex
	args->user_ref = current_user;
	current_user->online = true;
	pthread_mutex_unlock(&users_mutex);            // unlock users_mutex
	
	// -- retrieve public key of te user
	EVP_PKEY* client_pubk = retrieve_user_pubk((std::string)username);	
    
    // -- verify signature, in message there will be ( nonce | username)
	ret = digsign_verify(client_pubk, buffer, msg_size, message);
	if(ret < 0)
	{
    	cerr << "Error in the connection establishment: invalid client signature.\n";
    	return NULL;       // ++++++++++++++++++++++ to modify for close connection  ++++++++++++++++++++++
	}
	
	// -- store received nonce
	unsigned char* received_nonce = (unsigned char*)malloc(NONCE_SIZE);
	if(!received_nonce)
    	error("Error in the connection establishment: received_nonce Malloc error.\n");
	memcpy(received_nonce, message, NONCE_SIZE);           // copy the client nonce in the buffer
    
    // 2.0) Send server certificate
    // -- create server nonce (SN)
	unsigned char* my_nonce = (unsigned char*)malloc(NONCE_SIZE);     
	if(!my_nonce) 
    	error("Error in the connection establishment: my_nonce Malloc error.\n");
	RAND_poll();                                                // seed random generator
	ret = RAND_bytes((unsigned char*)&my_nonce[0],NONCE_SIZE);  // create random bytes for nonce
	if(ret!=1)
    	error("Error in the connection establishment: RAND_bytes error.\n");

	uint32_t size;                              // server certificate size to be sent 
	X509* server_cert;                          // contain server certificate
	server_cert = get_server_certificate();     // take server certificate
	BIO* bio = BIO_new(BIO_s_mem());            // create new BIO
	if(!bio) 
    	error("Error in the connection establishment: failed to allocate BIO_s_mem.\n");
	if(!PEM_write_bio_X509(bio, server_cert))   // write a certificate in PEM format into the BIO.
    	error("Error in the connection establishment: PEM_write_bio_X509 returned NULL.\n");
	
	unsigned char* cert_buffer = NULL;
	long cert_size = BIO_get_mem_data(bio, &cert_buffer);  // take server certificate size
	size = htonl(cert_size);                               // convert server certificate size
	// -- send server certificate size
	ret = send(socket, &size, sizeof(uint32_t), 0);        // send
	if(ret <= 0)
    	error("Error in the connection establishment: failure to send the server certificate size.\n");
	// -- send server certificate
	ret = send(socket, cert_buffer, cert_size, 0);         // send
	if(ret <= 0)
    	error("Error in the connection establishment: failure to send the server certificate.\n");
	
	// 2.1) send signed message to client -> messages format is -> ( sign_size | sign(client nonce | server nonce | ECDH pub_k) | client nonce | server nonce | ECDH pub_k )
	// -- diffie helmann protocol to estabilish a shared secret (key)
    EVP_PKEY* DH_privk = dh_gen_key();              // create ECDH private key
    unsigned char* DH_pubk_buffer = NULL;           // buffer to ECDH pubk  
    BIO* key_bio = BIO_new(BIO_s_mem());            // create BIO for the DH key
    if(!key_bio) 
        error("Error in the connection establishment: failed to allocate BIO_s_mem.\n");
    if(!PEM_write_bio_PUBKEY(key_bio,DH_privk))     // extract DH public key and serialize in BIO
        error("Error in the connection establishment: failed to write_bio_PUBKEY.\n");
    
    long pubk_size = BIO_get_mem_data(key_bio, &DH_pubk_buffer);    // get size of server DH pubk
    if (pubk_size <= 0) 
        error("Error in the connection establishment: failed to BIO_get_mem_data.\n");
    
    msg_size = pubk_size + NONCE_SIZE + NONCE_SIZE;        // calculate the size of message
	
	memcpy(message, received_nonce, NONCE_SIZE);           // copy client nonce in message buffer
	memcpy(message + NONCE_SIZE, my_nonce, NONCE_SIZE);    // copy server nonce in message buffer
	memcpy(message + NONCE_SIZE + NONCE_SIZE, DH_pubk_buffer ,pubk_size);  // copy ECDH server public key in message buffer
	
	cout << "Retrieve server private key.\n";
	EVP_PKEY* s_privk = get_server_private_key();          // retrieve server private key
	
	unsigned int signed_size = digsign_sign(s_privk, message, msg_size, buffer);   // sign message
	
	send_msg(socket, signed_size, buffer);         // send signed message -> messages format is -> ( sign_size | sign(client nonce | server nonce | ECDH pub_k) | client nonce | server nonce | ECDH pub_k )
	
	// delete used parameters 
	free(received_nonce);          // delete client nonce (CN)
	BIO_free(bio);                 // delete BIO used for server certificate
	BIO_free(key_bio);             // delete BIO used for server ECDH public key
	EVP_PKEY_free(s_privk);        // free s_privk 
	
	// 4) verify server nonce received from the client
	signed_size = receive_msg(socket, buffer);     // receive sigend message -> format is -> ( sign_size | sign() | server nonce | ECDH client pubk )
	unsigned int signature_size =*(unsigned int*)buffer;
	signature_size += sizeof(unsigned int);
	// -- check if the nonce received is correct or not
	if(memcmp(buffer + signature_size, my_nonce, NONCE_SIZE) != 0)
	{
    	cerr << "Error in the connection establishment: nonce received is not valid.\n";
    	return NULL;       // ++++++++++++++++++++++ to modify for close connection  ++++++++++++++++++++++
    }
	
	// -- verify client signature in message there will be ( server nonce | ECDH client pubk)
	msg_size = digsign_verify(client_pubk, buffer, signed_size, message);
	if(msg_size <= 0)
	{
    	cerr << "Error in the connection establishment: invalid client signature.\n";
    	return NULL;       // ++++++++++++++++++++++ to modify for close connection  ++++++++++++++++++++++
	}
	
	// -- get ECDH client public key from client
	BIO* ecdh_c_bio = BIO_new(BIO_s_mem());    // create BIO for the DH client public key
	BIO_write(ecdh_c_bio, message + NONCE_SIZE, msg_size - NONCE_SIZE);                // write in BIO the ECDH client public key contained in buffer
	EVP_PKEY* ecdh_client_pubkey = PEM_read_bio_PUBKEY(ecdh_c_bio, NULL, NULL, NULL);  // read ECDH public key in PEM format from the BIO
	
	// -- compute the shared secret key
	size_t shared_secret_len;                  // size of the shared secret len               
	EVP_PKEY_CTX *derive_ctx;                  // create context to derive shared secret    
	derive_ctx = EVP_PKEY_CTX_new(DH_privk, NULL);     // allocate a context
	if (!derive_ctx) 
    	handleErrors();
    if (EVP_PKEY_derive_init(derive_ctx) <= 0)         // initialise the derivation context
        handleErrors();
    // use ECDH server public key for derive the shared secret
    if (EVP_PKEY_derive_set_peer(derive_ctx, ecdh_client_pubkey) <= 0) 
        handleErrors();
	
	// Determine buffer length, by performing a derivation but writing the result nowhere
	EVP_PKEY_derive(derive_ctx, NULL, &shared_secret_len);
	unsigned char* shared_secret = (unsigned char*)(malloc(int(shared_secret_len)));	
	if (!shared_secret)
    	error("Error in Malloc for the buffer for shared secret.\n");
	// Perform again the derivation and store it in shared_secret buffer
    if (EVP_PKEY_derive(derive_ctx, shared_secret, &shared_secret_len) <= 0)
        error("Error in the connection establishment: failed to derive ECDH shared secret.\n");
	
	// free everything involved with the exchange (excep shared secret)
	BIO_free(ecdh_c_bio);                  // free BIO for the DH client public key		
    EVP_PKEY_CTX_free(derive_ctx);         // free context
	EVP_PKEY_free(ecdh_client_pubkey);     // free ECDH client public key
	EVP_PKEY_free(DH_privk);               // free ECDH server private key
	
	// -- create session key from ECDH shared secret
	// don't use directly the shared secret as a key because it does not have the entropy necessary to be a good symmetric key
	unsigned char* session_key = (unsigned char*) malloc(EVP_MD_size(sign_alg));    // buffer to the session key , size = digest
	if (!session_key) 
    	error("Error in the connection establishment: failed session key malloc.\n");
	
	// create the session key (symmetric key)
	ret = dh_generate_session_key(shared_secret, (unsigned int)shared_secret_len , session_key);
	free(shared_secret);                   // free shared secret
	args->session_key = session_key;       // set session key in args
	
	// set nonce counters, at the beginning are equal to 0
	current_user->server_counter = 0;      // is the server nonce, is used for nonce in the messages sent by the server
	current_user->client_counter = 0;      // is the client nonce, is used to verify the nonce in the messages sent by the client
	
	short cmd_code;                        // code of the command
	unsigned int aad_len;                  // len of AAD
	
	// cout of the authenticated and protected connection message between client and server
	cout << mex_AE_conn_succ << "Client: " << current_user->username << "\n";
	
	// send the list of the file in the dedicated stored of user
	send_user_file_list(socket, current_user, session_key);
	
	unsigned int received_counter;         // variable to contain the received nonce from client
	// main cicle
	while(1)
	{
    	// receive request from the client
    	msg_size = receive_msg(socket,buffer);
    	
    	received_counter=*(unsigned int*)(buffer + MSG_AAD_OFFSET);   //take the received client nonce
    	// check if the nonce is correct
    	if(received_counter == current_user->client_counter)          // if is equal is correct otherwhise the message is not fresh
    	{
        	ret = decryptor(buffer, msg_size, session_key, cmd_code, aad, aad_len, message);  // decrypt the received message
        	inc_counter_nonce(current_user->client_counter);      // increment the client nonce		

    		if (ret >= 0)                         // check if correctly decrypted 
    		{
        		// switch to see the cmd_code received and to perform the necessary operations to execute it.
        		switch(cmd_code)
        		{
        		case -1:   //
            		{
                		break;
            		}
            	case 0:    // close connection request
                	{
                    	close_user_conn(socket, current_user, session_key, message, ret);     // close the user connection
                    	break;
                	}
                case 1:    // user file list request
                	{
                    	handle_user_file_list_req(socket, current_user, session_key, message, ret); // handle user file list request
                    	break;
                	}
                case 2:    // upload request
                	{
                    	break;
                	}
                case 3:    // download request
                	{
                    	break;
                	}
                case 4:    // rename request
                	{
                    	handle_rename_req(socket, current_user, session_key, buffer, message, ret);
                    	break;
                	}
                case 5:    // delate request
                	{
                    	handle_delete_req(socket, current_user, session_key, message, ret);
                    	break;
                	}
                default:    // cmd_code incorrect or unrecognised
                    {
                        // control print in the server
                        // send error mex to the client
                        break;
                    }
        		}
    		}
    	}
    	else                       // nonce is not correct
    	{
    		cerr << err_rec_nonce;         // print mex error
    	}
	}
}
// ------------------------------- end: function to manage registered user -------------------------------

// ------------------------------- MAIN -------------------------------
// Argument of the main must be: <program_name> <server port>
int main(int argc, char *argv[])
{
    unsigned int counter=0;
	int ret, sock, server_port;
	socklen_t clilen;
	struct sockaddr_in addr_server, cli_addr;

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
        error("Error in listen.\n");
        
    // Server in listening
    while(1)
    {
        //Accept call creates a new socket and thread for the incoming connection
    	if(users.size() < MAX_CLIENTS)		// check if 
    	{
    	    int new_socket = accept(sock, (struct sockaddr *) &cli_addr, &clilen);
    	    if (new_socket < 0)
    	    { 
        		if (errno != EAGAIN || errno != EWOULDBLOCK)	
        		    error("ERROR on accept");
    	    }
    	    else
    	    {	
        	    cout << "Received connection from ip: " << inet_ntoa(cli_addr.sin_addr) << " and port number: " << ntohs(cli_addr.sin_port) << "\n\n";
    	    	
    	    	// create new args struct
    	    	Args *args=(Args *)malloc(sizeof(struct Args));
                if(!args)
                    error("Error in args Malloc.\n");
        	    args->socket = new_socket;

                // create new thread
                pthread_t thread;
            
        		// manage the client with the new thread
        		if(pthread_create(&thread, NULL, &client_handler, (void *)args)  != 0 )
            		cerr << "Failed to create thread\n";
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
