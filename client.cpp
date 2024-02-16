/*
    Created on Tue Jan 30 09:10:50 2024
    @author: Alessandro Diana
*/
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>       // for have size of the file > 2GBi
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <iostream> 
#include <stdio.h>                  // for fopen(), etc.
#include <limits.h>                 // for INT_MAX
#include <string.h>                 // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <arpa/inet.h>
// my library
#include "common.h"                 // Files containing functions and variables useful to both client and server

// ------------------------------- start: constant -------------------------------
// -- for reading commands from the command line, the maximum size prevents the entry of too many characters. The commands are few and fixed and with few arguments.
#define NUM_COMMAND 7               // number of avaible commands
#define MAX_DIM_COMMAND 10          // maximum length for a command name
#define MAX_DIM_PAR 100             // maximum length for a command parameter. The arguments are always file_names, a size of 100 each is more than sufficient for most legitimate cases.
#define MAX_NUM_PAR 2			    // maximum number of parameters that a command can have

// -- for help command -- various define containing explanations to be printed for the help command
#define HELP "\nThe following commands are available: \n !help <command> --> show details of a command.\n !list --> asks the server for the list of saved files and prints it in the terminal.\n !download <file_name> --> Download the file specified as an argument by name from the cloud server. The file will be saved on the client with the same name it had on the server, the name passed as argument. If a file with the same name already exists on the client, the download will fail and the file will not be downloaded from the server.\n !upload <file_name> --> Uploads the file specified as an argument by name to the cloud server. The file will be saved on the server with the same name it had on the client, the name passed as an argument. If a file with the same name already exists on the server, the upload will fail and the file will not be sent from the server.\n !rename <old_file_name> <new_file_name> --> Changes the name of a file on the server to the new name passed as a parameter. If a file with the same name as the new name specified already exists in the cloud server, the name change will fail.\n !delete <file_name> --> Deletes the file specified by name passed as a parameter from the cloud server.\n !logout --> disconnects from the server and closes the program.\n"
#define HELP_HELP "!help <command> --> Show details of the specified command.\n"
#define HELP_LIST "!list --> Asks the server for the list of saved files and prints it in the terminal.\n"
#define HELP_DOWNLOAD "!download <file_name> --> Download the file specified as an argument by name from the cloud server. The file will be saved on the client with the same name it had on the server, the name passed as argument. If a file with the same name already exists on the client, the download will fail and the file will not be downloaded from the server.\n"
#define HELP_UPLOAD "!upload <file_name> --> Uploads the file specified as an argument by name to the cloud server. The file will be saved on the server with the same name it had on the client, the name passed as an argument. If a file with the same name already exists on the server, the upload will fail and the file will not be sent from the server.\n"
#define HELP_RENAME "!rename <old_file_name> <new_file_name> --> Changes the name of a file on the server to the new name passed as a parameter. If a file with the same name as the new name specified already exists in the cloud server, the name change will fail.\n"
#define HELP_DELETE "!delete <file_name> --> Deletes the file specified by name passed as a parameter from the cloud server.\n"
#define HELP_LOGOUT "!logout --> disconnects from the server and closes the program.\n"
// ------------------------------- end: constant -------------------------------

// ------------------------------- start: struct and global variables -------------------------------
int socket_server;	                   // variable to contain the server socket fd
unsigned int server_counter = 0;       // is the server nonce, is used to verify the nonce in the messages sent by the server
unsigned int client_counter = 0;       // is the client nonce, is used for nonce in the messages sent by the client

// matrix containing all the commands recognised by the client, sorted by their respective cmd_code.
char commands[][ MAX_DIM_COMMAND ]={"!logout",
                                    "!list",
                   					"!upload",
                   					"!download",
                   					"!rename",
                   					"!delete",
                   					"!help"};
                   					
// ------------------------------- end: struct and global variables -------------------------------

// ------------------------------- start: path -------------------------------
string keys_path = "ClientFiles/Keys/";                     // path to users keys folder
string cert_path = "ClientFiles/Certificates/";             // path to certificates folder
string CA_cert_path = "ClientFiles/Certificates/FoC_Proj_CA_cert.pem";      // path to CA certificate
string CA_CRL_path = "ClientFiles/Certificates/FoC_Proj_CA_CRL.pem";        // path to CRL
string ded_store_path = "ClientFiles/Dedicated_Storage/";   // path to dedicated storage folder

// ------------------------------- end: path -------------------------------

// ------------------------------- start: messages -------------------------------
// message to be shown to the user after the first connection to the server but before authentication and the session is established.
string mex_after_server_conn = "Server authentication in progress...\n"; 
string mex_ready_command = "Please enter the command you want.\n";              // message to be displayed to notify the user that he/she can enter commands 
string aut_encr_conn_succ = "\nAuthenticated and encrypted connection with the server successfully established.\n";   // message that is displayed once the authenticated and encrypted connection with the server is successfully established
// -- errors
string err_open_file = "Error: cannot open file.\n";                            // error that occurs when a file cannot be opened
string err_command = "Error: command entered incorrect, please try again.\n";   // error that occurs when an entered command is incorrect
string err_wrong_num_par = "Error in the number of parameters passed.\n";       // error that occurs when the number of parameter is incorrect
string err_dim_par = "Error in the dimension of parameters passed.\n";          // error that occurs when the dimension of parameter is too big

string rename_failed = "Error: rename operation failed.\n";                     // error that occurs when the rename operation failed
string delete_failed = "Error: delete operation failed.\n";                     // error that occurs when the delete operation failed
string upload_failed = "Error: delete operation failed.\n";                     // error that occurs when the upload operation failed

// ------------------------------- end: messages -------------------------------

// ------------------------------- start: general function -------------------------------
//   Description: function to print the legend of the command for the user
void print_command_legend()
{
	cout << "\n-----------------------------------------------------------\n";
	cout << HELP_LIST;
	cout << HELP_DOWNLOAD;
	cout << HELP_UPLOAD;
	cout << HELP_RENAME;
	cout << HELP_DELETE;
	cout << HELP_LOGOUT;
	cout << HELP_HELP;
	cout << "-----------------------------------------------------------\n";
	cout << "------------------- USEFUL INFORMATION --------------------\n";
	cout << "File names may have a maximum size of " << MAX_DIM_FILE_NAME << " characters.\n";
    cout << "File names containing space are not allowed.\n";
    cout << "Files will be searched in the folder '/ClientFiles/Dedicated_Storage/username'.\n";
	cout << "-----------------------------------------------------------\n\n";
}
// ------------------------------- end: general function -------------------------------

// ------------------------------- start: functions to perform user commands -------------------------------
/*
    Description:  
        function to print the list of the files stored in the server, for the user logged in this client.
    Parameters:
        - buffer: buffer conatining the list of the file stored on the server
        - buffer_size: the size of the buffer 
*/
void print_files_list(unsigned char* buffer, unsigned int buffer_size)
{
	cout << "--------------------------------------------------\n";
	cout << "Files stored on the server: \n";
	memcpy(buffer + buffer_size - 1, "\0", 1);	  // for secure
	cout << buffer << "\n";                       // print the list of file
	cout << "--------------------------------------------------\n\n";
}

//    Description:  function to close connection and quite the program
void quit_program()
{
    close(socket_server);  // close socket
    exit(0);               // close program
}

/*
    Description:  
        function to send the request to close the connection with the server
    Parameters:
        - username: username of the user that uses the client
        - session_key: buffer to contain the symmetric session key	
*/
void send_close_conn_request(char* username, unsigned char* session_key)
{
    unsigned char* message = 0;        // contain the message to be sent
    unsigned int msg_len = 0;      // the len of the message to encrypt
    short cmd_code;                // code of the command
	unsigned int aad_len;          // len of AAD
    int ret;

	cout << "Send request to close the server connection...\n";
	
	// 1) set packet to send, the packet format is -> ( 0 | tag | IV | aad_len | client_nonce | username )
	// -- set the message to ecnrypt
	msg_len = strlen(username) + 1;			       // update msg_len
	message = (unsigned char*)malloc(msg_len);     // allocate       
	if(!message)
      	error("Error in send_close_conn_request: message Malloc error.\n");
	memcpy(message, username, msg_len);            // copy in message
	
	// -- set aad (client nonce)
	unsigned char* aad = (unsigned char*)malloc(sizeof(unsigned int));  // in this case aad is only the client nonce
	if(!aad)
    	error("Error in send_close_conn_request: aad Malloc error.\n");
	memcpy(aad,(unsigned char*)&client_counter,sizeof(unsigned int));   // copy client nonce in aad
	
	// -- buffer 
	unsigned char* buffer = (unsigned char*)malloc(MAX_SIZE);      // temp buffer for message 
	if(!buffer)
    	error("Error in send_close_conn_request: buffer Malloc error.\n");
	
	// -- encrypt the message, cmd_code for the operation to close connection is 0
	ret = encryptor(0,aad, sizeof(unsigned int), message, msg_len , session_key, buffer);
	if (ret >= 0)      // successfully encrypted
	{
    	// send the close connection request to the server
		send_msg(socket_server, ret, buffer);     // send user file list to client
		inc_counter_nonce(client_counter);        // update client counter
	}
	
	// 2) wait the response of the server, format is -> ( cmd_code | tag | IV | aad_len | nonce | ciphertext)
	free(message);     // free the buffer containing the cleartext message (user file list)
	message = (unsigned char*)malloc(MAX_SIZE);
	
	msg_len = receive_msg(socket_server, buffer);           // receive confirmation or not
	unsigned int received_counter=*(unsigned int*)(buffer + MSG_AAD_OFFSET);   //take the received server nonce
	
	if(received_counter == server_counter)    // if is equal is correct otherwhise the message is not fresh
	{
		ret = decryptor(buffer, msg_len, session_key, cmd_code, aad, aad_len, message);  // decrypt the received message
		inc_counter_nonce(server_counter);    // increment the server nonce
		
		if (ret >= 0)                         // correctly decrypted 
		{
    		// check the cmd_code received
    		if ((cmd_code != -1) && (cmd_code == 0))  // all is ok
    		{
        		memcpy(message + ret - 1, "\0", 1);   // for secure
            	cout << message <<"\n";               // print the error message
    		}
    		else if (cmd_code == -1)                  // error message
    		{
    			memcpy(message + ret - 1, "\0", 1);   // for secure
            	cerr << message <<"\n";               // print the error message
    		}
    		else
        		cerr << err_rec_cmd_code;             // error message
		}
	}
	else
		cerr << err_rec_nonce;
	
	// free all
	free(buffer);      // free buffer containing the encrypted message
	free(message);     // free the buffer containing the cleartext message (user file list)
	free(aad);         // free aad 8in this case the server nonce	
	
	quit_program();    // close connection and program
}

/*
    Description:  
        function to send the request to close the connection with the server
    Parameters:
        - username: username of the user that uses the client
        - session_key: buffer to contain the symmetric session key	
*/
void send_list_request(char* username, unsigned char* session_key)
{
    unsigned char* message;        // contain the message to be sent
    unsigned int msg_len = 0;      // the len of the message to encrypt
    short cmd_code = 1;            // code of the command
	unsigned int aad_len;          // len of AAD
    int ret;

	cout << "Send request for the list of the user's file on the server...\n";

	// 1) create and send packet to send, the packet format is -> ( 1 | tag | IV | aad_len | client_nonce | username )
	// -- set the message to ecnrypt
	msg_len = strlen(username) + 1;			       // update msg_len
	message = (unsigned char*)malloc(msg_len);     // allocate       
	if(!message)
      	error("Error in send_list_request: message Malloc error.\n");
	memcpy(message, username, msg_len);            // copy in message
	
	// -- set aad (client nonce)
	unsigned char* aad = (unsigned char*)malloc(sizeof(unsigned int));  // in this case aad is only the client nonce
	if(!aad)
    	error("Error in send_list_request: aad Malloc error.\n");
	memcpy(aad,(unsigned char*)&client_counter,sizeof(unsigned int));   // copy client nonce in aad
	
	// -- buffer 
	unsigned char* buffer = (unsigned char*)malloc(MAX_SIZE);      // temp buffer for message 
	if(!buffer)
    	error("Error in send_list_request: buffer Malloc error.\n");
    	
    // -- encrypt the message, cmd_code for the list operation is 1
	ret = encryptor(cmd_code,aad, sizeof(unsigned int), message, msg_len , session_key, buffer);
	if (ret >= 0)      // successfully encrypted
	{
    	// send the list request to the server
		send_msg(socket_server, ret, buffer);     // send user file list to client
		inc_counter_nonce(client_counter);        // update client counter
	}
	
	// 2) wait the response of the server, format is -> ( cmd_code | tag | IV | aad_len | nonce | ciphertext)
	msg_len = receive_msg(socket_server, buffer);           // receive confirmation or not
	unsigned int received_counter=*(unsigned int*)(buffer + MSG_AAD_OFFSET);   //take the received server nonce
	
	free(message);     // free the buffer containing the cleartext message (user file list)
	message = (unsigned char*)malloc(MAX_SIZE);
	
	// 2) receive the response of the server
	if(received_counter == server_counter)    // if is equal is correct otherwhise the message is not fresh
	{
		ret = decryptor(buffer, msg_len, session_key, cmd_code, aad, aad_len, message);  // decrypt the received message
		inc_counter_nonce(server_counter);    // increment the server nonce
		
		if (ret >= 0)                         // correctly decrypted 
		{
    		// check the cmd_code received
    		if ((cmd_code != -1) && (cmd_code == 1))  // all is ok
    		{
        		print_files_list(message, ret);       // print the list of the user file stored in the server
    		}
    		else if (cmd_code == -1)                  // error message
    		{
    			memcpy(message + ret - 1, "\0", 1);   // for secure
            	cerr << message <<"\n";               // print the error message
    		}
    		else
        		cerr << err_rec_cmd_code;             // error message
		}
	}
	else
		cerr << err_rec_nonce;
	
	// free all
	free(buffer);      // free buffer containing the encrypted message
	free(message);     // free the buffer containing the cleartext message (user file list)
	free(aad);         // free aad 8in this case the server nonce	
}

/*
    Description:  
        function to send the rename request for a file stored on the server
    Parameters:
        - session_key: buffer to contain the symmetric session key
        - old_file_name: file name to be changed
        - new_file_name: new file name
*/
void send_rename_request(unsigned char* session_key, char* old_file_name, char* new_file_name)
{
    unsigned char* message = 0;     // contain the message to be sent
    unsigned int msg_len = 0;       // the len of the message to encrypt
    short cmd_code = 4;             // code of the command
	unsigned int aad_len;           // len of AAD
    int ret;
    
    cout << "Send rename request on the server...\n";
    // check the dimension fo a string
    if ((strlen(old_file_name) > MAX_DIM_PAR) || (strlen(new_file_name) > MAX_DIM_PAR) )
    {
        cerr << "File name too big.\n";
        return;     
    }
    
    string old_s = old_file_name;   // string to contain the old file name
    string new_s = new_file_name;   // string to contain the new file name
    
    // checking the correctness of strings, only the white list control
    if ( check_file_name(old_s, " ", false) && check_file_name(new_s, " ", false) )
    {
        // strings are correct
        // 1) create and send the request to the server -> format is -> ( cmd_code | tag | IV | aad_len | aad (nonce, old_n_len, new_n_len) | ciphertext (old_file_name, new_file_name) )
    
        // -- take string len
        unsigned int old_n_len = strlen(old_file_name) + 1;     // take old file name len
        unsigned int new_n_len = strlen(new_file_name) + 1;     // take new file name len
        
        // -- set the message to ecnrypt
    	msg_len = old_n_len + new_n_len;			            // update msg_len
    	message = (unsigned char*)malloc(msg_len);              // allocate       
    	if(!message)
          	error("Error in send_rename_request: message Malloc error.\n");
    	memcpy(message, old_file_name, old_n_len);              // copy old_file_name in message
    	memcpy(message + old_n_len, new_file_name, new_n_len);  // copy new_file_name in message
        
        // -- set aad (nonce, old_n_len, new_n_len)
    	unsigned char* aad = (unsigned char*)malloc(sizeof(unsigned int) + sizeof(unsigned int) + sizeof(unsigned int));  
    	if(!aad)
        	error("Error in send_rename_request: aad Malloc error.\n");
    	memcpy(aad,(unsigned char*)&client_counter,sizeof(unsigned int));  // copy client nonce in aad
    	memcpy(aad + sizeof(unsigned int),(unsigned char*)&old_n_len,sizeof(unsigned int));  // copy old file name len
    	memcpy(aad + sizeof(unsigned int)+ sizeof(unsigned int),(unsigned char*)&new_n_len,sizeof(unsigned int));  // copy new file name len
    	
    	// -- buffer 
    	unsigned char* buffer = (unsigned char*)malloc(MAX_SIZE);      // temp buffer for message 
    	if(!buffer)
        	error("Error in send_rename_request: buffer Malloc error.\n");
        	
        aad_len = sizeof(unsigned int)*3;
        
        // -- encrypt the message, cmd_code for the rename operation is 4
    	ret = encryptor(cmd_code,aad, aad_len, message, msg_len, session_key, buffer);
    	if (ret >= 0)      // successfully encrypted
    	{
        	// send the rename request to the server
    		send_msg(socket_server, ret, buffer);     // send user file list to client
    		inc_counter_nonce(client_counter);        // update client counter
    	}
        
        // free message and reallocate with a different dimension
        free(message);     // free the buffer containing the cleartext message (user file list)
       	message = (unsigned char*)malloc(MAX_SIZE);
       	if(!message)
             	error("Error in send_rename_request: message Malloc error.\n");
    	
    	// 2) receive the response of the server
    	msg_len = receive_msg(socket_server, buffer);           // receive confirmation or not
    	unsigned int received_counter=*(unsigned int*)(buffer + MSG_AAD_OFFSET);   //take the received server nonce
    	
    	if(received_counter == server_counter)    // if is equal is correct otherwhise the message is not fresh
    	{
    		ret = decryptor(buffer, msg_len, session_key, cmd_code, aad, aad_len, message);  // decrypt the received message
    		inc_counter_nonce(server_counter);    // increment the server nonce
    		
    		if (ret >= 0)                         // correctly decrypted 
    		{
        		// check the cmd_code received
        		if ((cmd_code != -1) && (cmd_code == 4))  // all is ok
        		{
            		memcpy(message + ret - 1, "\0", 1);   // for secure
                	cout << message <<"\n";               // print the message
        		}
        		else if (cmd_code == -1)                  // error message
        		{
        			memcpy(message + ret - 1, "\0", 1);   // for secure
                	cerr << message <<"\n";               // print the error message
        		}
        		else
            		cerr << err_rec_cmd_code;             // error message
    		}
    	}
    	else
    		cerr << err_rec_nonce;
    	
    	// free all
    	free(buffer);      // free buffer containing the encrypted message
    	free(message);     // free the buffer containing the cleartext message (user file list)
    	free(aad);         // free aad 8in this case the server nonce	
    }
    else
        cerr << rename_failed;
}

/*
    Description:  
        function to send the rename request for a file stored on the server
    Parameters:
        - session_key: buffer to contain the symmetric session key
        - old_file_name: file name of the file  to be deleted
*/
void send_delete_request(unsigned char* session_key, char* file_name)
{
    unsigned char* message;         // contain the message to be sent
    unsigned int msg_len = 0;       // the len of the message to encrypt
    short cmd_code = 5;             // code of the command
	unsigned int aad_len;           // len of AAD
    int ret;
    char choice;           			// contain the choice of the user 'y' or 'n'
    
    // check the dimension fo a string
    if (strlen(file_name) > MAX_DIM_PAR)
    {
        cerr << "File name too big.\n";
        return;     
    }
    
    string temp_f_n = file_name;   // string to contain the file name
    
    // checking the correctness of strings, only white list check
    if ( check_file_name(temp_f_n, " ", false) )
    {
        // strings is correct, remove first part of the path
        //int pre_path_len = strlen(ded_store_path.c_str());
        //string f_n = temp_f_n.substr(pre_path_len,MAX_DIM_FILE_NAME);
        
        // 1) create and send the request to the server -> format is -> ( cmd_code | tag | IV | aad_len | nonce | file_name )
        // -- set the message to ecnrypt
    	msg_len = strlen(file_name) + 1;			   // update msg_len
    	message = (unsigned char*)malloc(msg_len);     // allocate       
    	if(!message)
          	error("Error in send_delete_request: message Malloc error.\n");
    	memcpy(message, file_name, msg_len);            // copy in message
    	
    	// -- set aad (client nonce)
    	unsigned char* aad = (unsigned char*)malloc(sizeof(unsigned int));  // in this case aad is only the client nonce
    	if(!aad)
        	error("Error in send_delete_request: aad Malloc error.\n");
    	memcpy(aad,(unsigned char*)&client_counter,sizeof(unsigned int));   // copy client nonce in aad
    	
    	// -- buffer 
    	unsigned char* buffer = (unsigned char*)malloc(MAX_SIZE);      // temp buffer for message 
    	if(!buffer)
        	error("Error in send_delete_request: buffer Malloc error.\n");
        	
        // -- encrypt the message, cmd_code for the list operation is 1
    	ret = encryptor(cmd_code,aad, sizeof(unsigned int), message, msg_len , session_key, buffer);
    	if (ret >= 0)      // successfully encrypted
    	{
        	// send the list request to the server
    		send_msg(socket_server, ret, buffer);     // send user file list to client
    		inc_counter_nonce(client_counter);        // update client counter
    	}
        
        // free message and reallocate with a different dimension
        free(message);     // free the buffer containing the cleartext message (file_name)
       	message = (unsigned char*)malloc(MAX_SIZE);
       	if(!message)
             	error("Error in send_delete_request: message Malloc error.\n");
    	
        // 2) receive the confirmation request from the server
        msg_len = receive_msg(socket_server, buffer);           // receive confirmation or not
    	unsigned int received_counter =*(unsigned int*)(buffer + MSG_AAD_OFFSET);   //take the received server nonce
    	
    	if(received_counter == server_counter)    // if is equal is correct otherwhise the message is not fresh
    	{
    		ret = decryptor(buffer, msg_len, session_key, cmd_code, aad, aad_len, message);  // decrypt the received message
    		inc_counter_nonce(server_counter);    // increment the server nonce
    		
    		if (ret >= 0)                         // correctly decrypted 
    		{
        		// check the cmd_code received
        		if ((cmd_code != -1) && (cmd_code == 5))  // all is ok
        		{
            		memcpy(message + ret - 1, "\0", 1);   // for secure
                	cout << message;                      // print the message
                	
                	bool get_choice = false;
                	string c;
                	// take the choice of the user, 'y' if wants to delete or 'n' if wants to stop
                	while (!get_choice)
                	{
                    	getline(std::cin, c);		// get user choice
                    	if(!std::cin)
                    	{
                    		cerr << "error in std::cin.\n";
                    		continue;
                    	}
                    	choice = c[0];		// get the first char
                    	//cin >> choice;
                    	if ( (choice == 'y') || (choice == 'Y') || (choice == 'n') || (choice == 'N'))     // correct choices
                        	get_choice = true;     // set variable to end the while
                	}		
        		}
        		else if (cmd_code == -1)                  // error message
        		{
        			memcpy(message + ret - 1, "\0", 1);   // for secure
                	cerr << message <<"\n";                      // print the error message
                	return;            // delete operation failed
        		}
        		else
        		{
        			cerr << err_rec_cmd_code;             // error message
            		return;            // delete operation failed
        		}
    		}
    		else
        	{
            	cerr << "Error in send_delete_request: decrypt error.\n";
        	}
        	
        	// free message and reallocate with a different dimension
            free(message);     // free the buffer containing the cleartext message (user file list)
        	free(buffer);      // free buffer containing the encrypted message
        	free(aad);         // free aad 8in this case the server nonce	
        	
        	// 3) send confirmation or rejection
        	// -- set the message to ecnrypt
        	msg_len = 1;			                       // update msg_len
        	message = (unsigned char*)malloc(msg_len);     // allocate       
        	if(!message)
              	error("Error in send_delete_request: message Malloc error.\n");
        	memcpy(message, &choice, msg_len);            // copy in message
        	
        	// -- set aad (client nonce)
        	unsigned char* aad = (unsigned char*)malloc(sizeof(unsigned int));  // in this case aad is only the client nonce
        	if(!aad)
            	error("Error in send_delete_request: aad Malloc error.\n");
        	memcpy(aad,(unsigned char*)&client_counter,sizeof(unsigned int));   // copy client nonce in aad
        	
        	// -- buffer 
        	unsigned char* buffer = (unsigned char*)malloc(MAX_SIZE);      // temp buffer for message 
        	if(!buffer)
            	error("Error in send_delete_request: buffer Malloc error.\n");
            	
            // -- encrypt the message, cmd_code for the list operation is 1
        	ret = encryptor(cmd_code,aad, sizeof(unsigned int), message, msg_len , session_key, buffer);
        	if (ret >= 0)      // successfully encrypted
        	{
            	// send the list request to the server
        		send_msg(socket_server, ret, buffer);     // send user file list to client
        		inc_counter_nonce(client_counter);        // update client counter
        	}
        	
        	// free message and reallocate with a different dimension
            free(message);     // free the buffer containing the cleartext message (user file list)
        	message = (unsigned char*)malloc(MAX_SIZE);
        	if(!message)
              	error("Error in send_delete_request: message Malloc error.\n");
              	
        	// 4) receive the final response of the operation
        	msg_len = receive_msg(socket_server, buffer);           // receive confirmation or not
        	unsigned int received_counter =*(unsigned int*)(buffer + MSG_AAD_OFFSET);   //take the received server nonce
        	
        	if(received_counter == server_counter)    // if is equal is correct otherwhise the message is not fresh
        	{
        		ret = decryptor(buffer, msg_len, session_key, cmd_code, aad, aad_len, message);  // decrypt the received message
        		inc_counter_nonce(server_counter);    // increment the server nonce
        		
        		if (ret >= 0)                         // correctly decrypted 
        		{
            		// check the cmd_code received
            		if ((cmd_code != -1) && (cmd_code == 5))  // all is ok
            		{
                		memcpy(message + ret - 1, "\0", 1);   // for secure
                    	cout << message <<"\n";               // print the message
            		}
            		else if (cmd_code == -1)                  // error message
            		{
            			memcpy(message + ret - 1, "\0", 1);   // for secure
                    	cerr << message <<"\n";               // print the error message
                    	return;            // delete operation failed
            		}
            		else
                		cerr << err_rec_cmd_code;             // error message
                		return;            // delete operation failed
        		}
        		else
            	{
                	cerr << "Error in send_delete_request: decrypt error.\n";
            	}
        	}
        	else           // else of the first control of nonce
            	cerr << err_rec_nonce;	
            	
            // free message and reallocate with a different dimension
            free(message);     // free the buffer containing the cleartext message (user file list)
        	free(buffer);      // free buffer containing the encrypted message
        	free(aad);         // free aad 8in this case the server nonce	
    	}
    	else           // else of the first control of nonce
    		cerr << err_rec_nonce;
    }
    else        // else of the control of file name
        cerr << delete_failed;
}

/*
    Description:  
        function to send the upload request for a file stored on the client
    Parameters:
        - session_key: buffer to contain the symmetric session key
        - old_file_name: file name of the file  to be deleted
        - username: username of the user that uses the client
*/
void send_upload_request(unsigned char* session_key, char* file_name, char* username)
{
    unsigned char* message = 0;     // contain the message to be sent
    long long msg_len = 0;          // the len of the message to encrypt
    short cmd_code = 2;             // code of the command
	unsigned int aad_len;           // len of AAD
    string f_n = file_name;    		// string for file name
    string path;                    // string for complete path of the specified file
    long long file_size = 0;	    // contain the size of the file to be uploaded
    FILE* file_up = 0;				// file to be uploaded
    bool ov_size = false;           // in case of big size to upload
    string prefix = ded_store_path + username + "/";				// the correct prefix that must have file paths
    long long ret;
    
    // check the dimension fo a string
    if (strlen(file_name) > MAX_DIM_PAR)
    {
        cerr << "File name too big.\n";
        return;     
    }
    
    //string temp_f_n = file_name;   // string to contain the file name
    path = ded_store_path + username + "/" + f_n;	// take the path
    
    // checking the correctness of strings
    if ( check_file_name(path, prefix) && (get_can_str(path, prefix) != " "))
    {
    	// 0) control check of the file to be uploaded on the server
    	// -- check if the file exist
        path = get_can_str(path, prefix);
		f_n = path.substr(prefix.length());		// ge the clear file name
        
        if(access(path.c_str(), F_OK ) != 0)         // if exist return 0 otherwhise return -1
        {
        	cerr << "The specified file" << f_n << " is not present, upload finished before sending the request to the server.\n";
        	return;		// return to main loop
        }
        // -- check file dimension
		file_up = fopen (path.c_str(),"rb");		// open the file
  		if (!file_up) 				
  			error ("Error in send_upload_request: opening file failed.\n");
  		else                    // file successfully opened
  		{
    		file_size = get_file_size(path);        // get the file size
    		cout << "The specified file '" << f_n << "' is large " << file_size << "Bytes.\n";   // print the files 
    		if ( file_size > MAX_FILE_SIZE )
        	{
            	cerr << upload_failed << "File too big.\n";
            	return;        // return to main loop
        	}
    	}
    	// all control passed, this first message is alway small, only have to send the name of the file to have the server do the checks. 
    	// The subsequent message (sending the file) may have to be handled differently if the file is large.
    	
    	// 1) create and send the request to the server -> format is -> ( cmd_code | tag | IV | aad_len | nonce | file_size | file_name )
    	// -- set the message to ecnrypt
    	msg_len = strlen(f_n.c_str()) + 1;			   // update msg_len
    	message = (unsigned char*)malloc(sizeof(long long) + msg_len);     // allocate       
    	if(!message)
          	error("Error in send_upload_request: message Malloc error.\n");
        memcpy(message, (unsigned char*)&file_size, sizeof(long long));           // copy the file size in message
    	memcpy(message + sizeof(long long), f_n.c_str(), msg_len);           // copy the file name in message
    	msg_len += sizeof(long long);		// update msg_len (now include the dimension of the file_size and the dimension of the file_name)
    	
    	// -- set aad (client nonce)
    	unsigned char* aad = (unsigned char*)malloc(sizeof(unsigned int));  // in this case aad is only the client nonce
    	if(!aad)
        	error("Error in send_upload_request: aad Malloc error.\n");
    	memcpy(aad,(unsigned char*)&client_counter,sizeof(unsigned int));   // copy client nonce in aad
    	
    	// -- buffer 
    	unsigned char* buffer = (unsigned char*)malloc(MAX_SIZE);      // temp buffer for message 
    	if(!buffer)
        	error("Error in send_upload_request: buffer Malloc error.\n");
    	
    	// -- encrypt the message, cmd_code for the list operation is 2
    	ret = encryptor(cmd_code,aad, sizeof(unsigned int), message, msg_len , session_key, buffer);
    	if (ret >= 0)      // successfully encrypted
    	{
        	// send the list request to the server
    		send_msg(socket_server, ret, buffer);     // send user file list to client
    		inc_counter_nonce(client_counter);        // update client counter
    	}
    	
    	// free message and reallocate with a different dimension
        free(message);     // free the buffer containing the cleartext message (file_name)
       	message = (unsigned char*)malloc(MAX_SIZE);
       	if(!message)
             	error("Error in send_upload_request: message Malloc error.\n");
    	
    	// 2) receive mex from the server
    	msg_len = receive_msg(socket_server, buffer);           // receive confirmation or not
    	unsigned int received_counter =*(unsigned int*)(buffer + MSG_AAD_OFFSET);   //take the received server nonce
    	
    	// start: if for nonce check of the first message received from server 
    	if(received_counter == server_counter)    // if is equal is correct otherwhise the message is not fresh
    	{
    		ret = decryptor(buffer, msg_len, session_key, cmd_code, aad, aad_len, message);  // decrypt the received message
    		inc_counter_nonce(server_counter);    // increment the server nonce
    		
    		if (ret >= 0)                         // correctly decrypted 
    		{     // end: if for decryptor ret check of the first message received from server 
        		// check the cmd_code received
        		if ((cmd_code != -1) && (cmd_code == 2))  // all is ok
        		{
            		memcpy(message + ret - 1, "\0", 1);   // for secure
                	cout << message << "\n";              // print the message
        		}
        		else if (cmd_code == -1)                  // error message
        		{
        			memcpy(message + ret - 1, "\0", 1);   // for secure
                	cerr << message << "\n";              // print the error message
                	return;            // delete operation failed
        		}
        		else
        		{
        			cerr << err_rec_cmd_code;             // error message
            		return;            // delete operation failed
        		}        		
    		}      // end: if for decryptor ret check of the first message received from server 
    		else
        	{      // start: else for decryptor ret check of the first message received from server 
            	cerr << "Error in send_upload_request: decrypt error.\n";
            	cerr << upload_failed;
            	return;    // return to manin loop
        	}      // end: else for decryptor ret check of the first message received from server 

            // free message and reallocate with a different dimension
            free(message);     // free the buffer containing the cleartext message (user file list)
            free(buffer);      // free buffer containing the encrypted message
            free(aad);         // free aad 8in this case the server nonce	
            
            // 3) send the file to be uploaded to the server
            // -- set aad (client nonce). It does not change depending on the size of the file.
        	unsigned char* aad = (unsigned char*)malloc(sizeof(unsigned int));  // in this case aad is only the client nonce
        	if(!aad)
            	error("Error in send_upload_request: aad Malloc error.\n");
        	memcpy(aad,(unsigned char*)&client_counter,sizeof(unsigned int));   // copy client nonce in aad
        	
        	// -- buffer: will contain the whole packet to be sent, it's size depends on file size
        	// -- message: it's the buffer to contain the cleartext to encrypt. If the file is too big for only 1 encrypt cycle the cleartext
        	// will be read directly from the file on disk to save memory and not have to allocate another buffer as large as the file.
        	//  - must be buffer, - message can be avoided
        	
        	// -- check if is a small file or a oversize file -- start: if (big file)
        	if (file_size + sizeof(unsigned int) > MAX_SIZE - AE_block_size - sizeof(unsigned int) - AE_iv_len - AE_tag_len - sizeof(short))
        	{
            	// large file (oversize), 
            	ov_size = true;                // set ov_size
            	
            	// buffer will be very large
            	buffer = (unsigned char*)malloc(file_size + sizeof(unsigned int)*2 + AE_block_size + AE_iv_len + AE_tag_len + sizeof(short) + 16);      // temp buffer for message 
            	if(!buffer)
                	error("Error in send_upload_request: buffer Malloc error.\n");
                	
                // check the size of the file to understand whether the encryption will be done in one loop (you have to put the contents of the file in message) 
                // or in several loops (message will not be used and will be read directly from the file)
                if ( (file_size + AE_block_size) <= FRAGMENT_SIZE )
                {
                    // -- one cycle -- set the message to ecnrypt
                    message = (unsigned char*)malloc(file_size);     // allocate       
                	if(!message)
                      	error("Error in send_upload_request: message Malloc error.\n");
                     
                    file_up = fopen (path.c_str(),"rb");		// open the file
              		if (!file_up) 				
              			error ("Error in send_upload_request: opening file failed.\n"); 	
                     
                    // read from the file and put into message buffer
                    ret = fread(message, 1, file_size, file_up);
                    if(ret < file_size) 
                    {
                        cerr << "Error while reading file '" << file_name << "'\n"; 
                        fclose(file_up);
                        return;                 //return to main loop
                    }
                    fclose(file_up);
                }
                else    // more cycle
                {
                    // message buffer will not be used
                    message = (unsigned char*)malloc(1);     // allocate       
                	if(!message)
                      	error("Error in send_upload_request: message Malloc error.\n");
                      	
                    file_up = fopen (path.c_str(),"rb");		// open the file
              		if (!file_up) 				
              			error ("Error in send_upload_request: opening file failed.\n"); 
                }                
        	}      //  end: if (big file)
        	else           // small file -- start: else (small file)
        	{
            	// -- buffer: all in one cycle and with small buffer
            	buffer = (unsigned char*)malloc(MAX_SIZE);      // temp buffer for message 
            	if(!buffer)
                	error("Error in send_upload_request: buffer Malloc error.\n");
                
                // -- set the message to ecnrypt
                message = (unsigned char*)malloc(MAX_SIZE);     // allocate       
            	if(!message)
                  	error("Error in send_upload_request: message Malloc error.\n");
                  	
                file_up = fopen (path.c_str(),"rb");		// open the file
          		if (!file_up) 				
          			error ("Error in send_upload_request: opening file failed.\n");
                  	
                // read from the file and put into message buffer
                ret = fread(message, 1, file_size, file_up);
                if(ret < file_size) 
                {
                    cerr << "Error while reading file '" << file_name << "'\n"; 
                    fclose(file_up);
                    return;                 //return to main loop
                }
                fclose(file_up);
        	}      // -- end: else (small file)
        	
        	// -- encrypt the message, cmd_code for the list operation is 2. In this call are specified also ov_size and file descriptor 
        	ret = encryptor(cmd_code,aad, sizeof(unsigned int), message, file_size , session_key, buffer, ov_size, file_up);
        	if ( (file_size + AE_block_size) > FRAGMENT_SIZE )
            	fclose (file_up);						// close the file
        	if (ret >= 0)      // successfully encrypted
        	{
            	// send the list request to the server
        		send_msg(socket_server, ret, buffer,ov_size);     // send user file list to client
        		inc_counter_nonce(client_counter);        // update client counter
        	}
        	
        	// free message and buffer and reallocate with a different dimension
            free(message);     // free the buffer containing the cleartext message
        	message = (unsigned char*)malloc(MAX_SIZE);
        	if(!message)
              	error("Error in send_upload_request: message Malloc error.\n");
              	
            // VERY IMPORTANT free buffer, it can be very large
        	free(buffer);      // free buffer containing the encrypted message
        	unsigned char* buffer = (unsigned char*)malloc(MAX_SIZE);      // temp buffer for message 
        	if(!buffer)
            	error("Error in send_upload_request: buffer Malloc error.\n");
              	
            // 4) receive response from the server
            msg_len = receive_msg(socket_server, buffer);           // receive confirmation or not
         	unsigned int received_counter =*(unsigned int*)(buffer + MSG_AAD_OFFSET);   //take the received server nonce
             
            if(received_counter == server_counter)    // if is equal is correct otherwhise the message is not fresh
        	{
        		ret = decryptor(buffer, msg_len, session_key, cmd_code, aad, aad_len, message);  // decrypt the received message
        		inc_counter_nonce(server_counter);    // increment the server nonce
        		
        		if (ret >= 0)                         // correctly decrypted 
        		{
            		// check the cmd_code received
            		if ((cmd_code != -1) && (cmd_code == 2))  // all is ok
            		{
                		memcpy(message + ret - 1, "\0", 1);   // for secure
                    	cout << message <<"\n";               // print the message
            		}
            		else if (cmd_code == -1)                  // error message
            		{
            			memcpy(message + ret - 1, "\0", 1);   // for secure
                    	cerr << message <<"\n";               // print the error message
                    	return;            // delete operation failed
            		}
            		else
                		cerr << err_rec_cmd_code;             // error message
                		return;            // upload operation failed
        		}
        		else
            	{
                	cerr << "Error in send_delete_request: decrypt error.\n";
            	}
        	}
        	else           // else of the first control of nonce
            	cerr << err_rec_nonce;	
            	
            // free all
            free(message);     // free the buffer containing the cleartext message (user file list)
        	free(buffer);      // free buffer containing the encrypted message
        	free(aad);         // free aad in this case the server nonce	
        	
        }       // end: if for nonce check of the first message received from server 
        else    // start: else for nonce check of the first message received from server 
            cerr << err_rec_nonce;
                // end: else for nonce check of the first message received from server 
    }
    else        // else of the control of file name
    {
    	if(access(path.c_str(), F_OK ) != 0)         // if exist return 0 otherwhise return -1
        {
        	cerr << "Because the specified file" << path << " is not present, upload finished before sending the request to the server.\n";
        }
        else
        	cerr << delete_failed;
    }
        
}


/*
    Description:  
        function to send the download request for a file stored on the server
    Parameters:
        - session_key: buffer to contain the symmetric session key
        - old_file_name: file name of the file to be downloaded
        - username: username of the user that uses the client
*/
void send_download_request(unsigned char* session_key, char* file_name, char* username)
{
    unsigned char* message = 0;     // contain the message to be sent
    long long msg_len = 0;          // the len of the message to encrypt
    short cmd_code = 3;             // code of the command
	unsigned int aad_len;           // len of AAD
    string f_n = file_name;    		// string for file name
    string path;                    // string for complete path of the specified file
    long long file_size = 0;	    // contain the size of the file to be uploaded
    FILE* file_dw = 0;				// file to be downloaded
    bool ov_size = false;           // in case of big size to 
    long long ret;
    
    // check the dimension fo a string
    if (strlen(file_name) > MAX_DIM_PAR)
    {
        cerr << "File name too big.\n";
        return;     
    }
    
    string temp_f_n = file_name;   // string to contain the file name
    
    // checking the correctness of strings
    if ( check_file_name(temp_f_n, " ", false) )
    {       // start: if 1.0 (white list check)
        // 0) control check of the file to be downloaded from the server
        // -- check if the file exist
        path = ded_store_path + username + "/" + f_n;	// take the path
        if(access(path.c_str(), F_OK ) == 0)         // if exist return 0 otherwhise return -1  (if 1.1)
        {   
            cerr << "The specified file" << path << " is already present, dowload finished before sending the request to the server.\n";
        	return;		// return to main loop
        }
        
        // Control passed, this first message is alway small, only have to send the name of the file to have the server do the checks. 
    	// The subsequent message (receiving the file) may have to be handled differently if the file is large.
        
        // 1) create and send the request to the server -> format is -> ( cmd_code | tag | IV | aad_len | nonce | file_name )
        // -- set the message to ecnrypt
        msg_len = strlen(file_name) + 1;			   // update msg_len
    	message = (unsigned char*)malloc(msg_len);     // allocate       
    	if(!message)
          	error("Error in send_download_request: message Malloc error.\n");
    	memcpy(message, file_name, msg_len);           // copy the file name in message
        
        // -- set aad (client nonce)
    	unsigned char* aad = (unsigned char*)malloc(sizeof(unsigned int));  // in this case aad is only the client nonce
    	if(!aad)
        	error("Error in send_download_request: aad Malloc error.\n");
    	memcpy(aad,(unsigned char*)&client_counter,sizeof(unsigned int));   // copy client nonce in aad
        
        // -- buffer 
    	unsigned char* buffer = (unsigned char*)malloc(MAX_SIZE);      // temp buffer for message 
    	if(!buffer)
        	error("Error in send_download_request: buffer Malloc error.\n");
        
        // -- encrypt the message, cmd_code for the list operation is 2
    	ret = encryptor(cmd_code,aad, sizeof(unsigned int), message, msg_len , session_key, buffer);
    	if (ret >= 0)      // successfully encrypted   (if 1.2)
    	{
        	// send the list request to the server
    		send_msg(socket_server, ret, buffer);     // send user file list to client
    		inc_counter_nonce(client_counter);        // update client counter
    	}
    	
    	// free message and reallocate with a different dimension
        free(message);     // free the buffer containing the cleartext message (file_name)
       	message = (unsigned char*)malloc(MAX_SIZE);
       	if(!message)
             	error("Error in send_download_request: message Malloc error.\n");
        
        // 2) receive mex from the server that indicates the dimension of the file or an error
    	msg_len = receive_msg(socket_server, buffer);           // receive confirmation or not
    	unsigned int received_counter =*(unsigned int*)(buffer + MSG_AAD_OFFSET);   //take the received server nonce
        
        // start: if for nonce check of the first message received from server 
    	if(received_counter == server_counter)    // if is equal is correct otherwhise the message is not fresh
    	{          // start: if 1.3 (first nounce control)
        	
        	ret = decryptor(buffer, msg_len, session_key, cmd_code, aad, aad_len, message);  // decrypt the received message
    		inc_counter_nonce(server_counter);    // increment the server nonce
    		
        	if (ret >= 0)         // correctly decrypted       start: if 1.3.1  
    		{      
        		// check the cmd_code received
        		if ((cmd_code != -1) && (cmd_code == 3))  // all is ok
        		{
            		file_size =*(unsigned long*)(message);       // take the received size of the file
        		}
        		else if (cmd_code == -1)                  // error message
        		{
        			memcpy(message + ret - 1, "\0", 1);   // for secure
                	cerr << message << "\n";              // print the error message
                	return;            // delete operation failed
        		}
        		else
        		{
        			cerr << err_rec_cmd_code;             // error message
            		return;            // delete operation failed
        		}        		
    		}      // end: if 1.3.1
    		else   // start: else 1.3.1
        	{      
            	cerr << "Error in send_download_request: decrypt error.\n";
            	cerr << upload_failed;
            	return;    // return to manin loop
        	}      // end: else 1.3.1 
        	
        	// free message and reallocate with a different dimension
            free(message);     // free the buffer containing the cleartext message (user file list)
            free(buffer);      // free buffer containing the encrypted message
            free(aad);         // free aad 8in this case the server nonce	
            
            // 3) receive the file and store on the disk
            // -- set aad 
            aad = (unsigned char*)malloc(sizeof(unsigned int));  // in this case aad is only the server nonce
        	if(!aad)
                error("Error in send_download_request: aad Malloc error.\n");
                
        	// -- buffer: will contain the whole packet to be sent, it's size depends on file size
        	// -- message: it's the buffer to contain the cleartext decrypted from the ciphertext received. If the file is too big for only 1 decrypt cycle 
        	// the cleartext will be write directly in the file on disk to save memory and not have to allocate another buffer as large as the file.
        	//  - must be buffer, - message can be avoided
        	
        	// -- check if is a small file or a oversize file -- start: if 1.3.2 (big file)
        	if (file_size + sizeof(unsigned int) > MAX_SIZE - AE_block_size - sizeof(unsigned int) - AE_iv_len - AE_tag_len - sizeof(short))
        	{
            	// large file (oversize), 
            	ov_size = true;                // set ov_size
            	
            	// -- set buffer to contain all the packet, if the file is big buffer wil be big
            	buffer = (unsigned char*)malloc(file_size + sizeof(unsigned int)*2 + AE_block_size + AE_iv_len + AE_tag_len + sizeof(short) + 16);      // temp buffer for message 
            	if(!buffer)
                	error("Error in send_download_request: buffer Malloc error.\n");
                	
                // check the size of the file to understand whether the decryption will be done in one loop (you have to put the contents of the file in message) 
                // or in several loops (message will not be used and will be read directly from the file)
                if ( (file_size + AE_block_size) <= FRAGMENT_SIZE )     // start: if 1.3.2.1
                {
                    // -- one cycle -- set the buffer for the decrypted message
                    message = (unsigned char*)malloc(file_size);     // allocate       
                	if(!message)
                      	error("Error in send_download_request: message Malloc error.\n");      	
                }                           // end: if 1.3.2.1
                else    // more cycle
                {                           // start: else 1.3.2.1
                    file_dw = fopen (path.c_str(),"wb+");		// open the file
              		if (!file_dw) 				
              			error ("Error in send_download_request: opening file failed.\n");
                    
                    // message buffer will not be used
                    message = (unsigned char*)malloc(1);     // allocate       
                	if(!message)
                      	error("Error in send_download_request: message Malloc error.\n");
                }                           // end: else 1.3.2.1
        	}          // end: if 1.3.2 (big file)
        	else       // small file -- start: else 1.3.2 (small file)
        	{
            	// -- buffer: all in one cycle and with small buffer
            	buffer = (unsigned char*)malloc(MAX_SIZE);      // temp buffer for message 
            	if(!buffer)
                	error("Error in send_download_request: buffer Malloc error.\n");
                
                // -- set the buffer for contain the decrypted message
                message = (unsigned char*)malloc(MAX_SIZE);     // allocate       
            	if(!message)
                  	error("Error in send_download_request: message Malloc error.\n");
        	}      // -- end: else 1.3.2 (small file)
        	
        	unsigned char* send_mex;                // for contain the mex to be sent
            unsigned int received_counter;          // for contain the received nonce
        	
        	msg_len = receive_msg(socket_server, buffer, ov_size);     // take the len of the response mex from user
        	
        	received_counter =*(unsigned int*)(buffer + MSG_AAD_OFFSET);  //take the received client nonce
        	// check if the nonce is correct
        	if(received_counter == server_counter)          // if is equal is correct otherwhise the message is not fresh
        	{      // start: if 1.3.3
            	ret = decryptor(buffer, msg_len, session_key, cmd_code, aad, aad_len, message, ov_size, file_dw);  // decrypt the received message
            	inc_counter_nonce(server_counter);          // increment the client nonce		
            	// free buffer that could be very big
            	free(buffer);
            	
            	if (ret >= 0)                         // correctly decrypted 
        		{                 // start: if 1.3.3.1 (check decrypt)
            		// check the cmd_code received
            		if ((cmd_code != -1) && (cmd_code == 3))  // all is ok -- start: if 1.3.3.1.1
            		{
                		// more cycle, the decrypted file is has already been written on disk
                    	if ( (file_size + AE_block_size) > FRAGMENT_SIZE )     
                        	fclose (file_dw);						// close the file
                        else    // 1 cycle, write the decrypted file on the disk
                        {
                            file_dw = fopen (path.c_str(),"wb+");		// open the file
                      		if (!file_dw) 				
                      			error ("Error in handle_upload_req: opening file failed.\n");
                      		
                            fwrite(message, 1, file_size, file_dw);     // write
                            
                            fclose (file_dw);						    // close the file
                        }
                        
                        cout << "Download operation successfully done.\n";
                        cout << "Downloaded " << file_name << " (" << file_size <<" Bytes).\n";
            		}         // end: if 1.3.3.1.1
            		else if (cmd_code == -1)                  // error message
            		{
            			memcpy(message + ret - 1, "\0", 1);   // for secure
                    	cerr << message <<"\n";               // print the error message
                    	return;            // delete operation failed
            		}         
            		else
            		{
                		cerr << err_rec_cmd_code;             // error message
                		cerr << "Download operation failed.\n";
            		}
        		}                 // end: if 1.3.3.1 (check decrypt)
        		else      // start: else (decryption incorrect)
        		{
            		cerr << "Error in send_upload_req: decrypt error. Download operation failed.\n";
        		}         // end: else (decryption incorrect)
        	
        	}      // end: if 1.3.3
        	else   // start: else 1.3.3
        	{
        		free(buffer);         // free buffer containing the encrypted message 
            	cerr << err_rec_nonce;         // print mex error
                cerr << "Error in receiving the file from server, download operation failed.\n";
        	}      // end: else 1.3.3
        
            // free all
        	free(message);      // free the buffer containing the cleartext message (user file list)
        	free(aad);          // free aad in this case the server nonce  	
    	}          // end: if 1.3 (first nounce control)
    	else       // else 1.3 (first nounce control)
            cerr << err_rec_nonce;
            
    }       // end: if 1.0 (white list check)
    else        // else 1.0 (white list check)
        cerr << delete_failed;
}
// ------------------------------- end: functions to perform user commands -------------------------------

// ------------------------------- start: functions to manage user entering of commands -------------------------------
/*
    Description:  
        function to identify the command inserted by the user
    Parameters:
        - s: string containing the entered command by user
    Return:
        - int that rapresent the position that the command has in the commands matrix 
*/
int identify_command(char *s)		
{
     int i;
     for (i=0; i < NUM_COMMAND ; i++)
          if (!strcmp(commands[i], s))
             return i;                      // command identified, return its position in the matrix, which corresponds to its cmd_code
     return -1;							    // comand not identified, return -1
}

/*
    Description:  
        function to print out the correct help string, based on the command passed as a parameter in the help
    Parameters:
        - command: string containing the command passed as parameter in the help
*/
void help(char* command)
{
    // switch for paremeter recognition
	switch (identify_command(command))			
    {
    	case 0:    // exit/logout -> no parameters
            {
                cout << HELP_LOGOUT;
                break;
            }
        case 1:    // list -> no parameters
            {
                cout << HELP_LIST;
                break;
            }
        case 2:    // upload -> 1 parameter
            {
            	cout << HELP_UPLOAD;
                break;
            }
        case 3:    // download -> 1 parameter
            {
                cout << HELP_DOWNLOAD;
                break;
            }
        case 4:    // rename -> 2 parameters
            {
                cout << HELP_RENAME;
                break;
            }
        case 5:    // delete -> 1 parameter
            {
                cout << HELP_DELETE;
                break;
            }
        case 6:    // help -> 0/1 parameter
            {
                cout << HELP_HELP;
                break;
            }
        default:
            {
                cerr << err_command;       // print error mex
            }
	}
}	

/*
    Description:  
        function that reads the keyboard command, identifies it and performs the necessary operations to fulfil it if the command is recognised
    Parameters:
        - username: username of the user that uses the client
        - session_key: buffer to contain the symmetric session key
*/
void read_command(char* username, unsigned char* session_key)				
{
    int command_code = 0;
    char buf [ MAX_DIM_COMMAND + (MAX_DIM_PAR * MAX_NUM_PAR) ];    // buffer to contain the line inserted by user
    char command [ MAX_DIM_COMMAND ];                              // char to contain the command inserted
    char parameters [ MAX_NUM_PAR ][ MAX_DIM_PAR ];		        // contains the arguments of the command
    // tells how many strings have been typed spaced with a space, it is used to know how many arguments have been entered
    int num_string_readed;				
     
    // get the command and the arguments
    char *res = fgets(buf, MAX_DIM_COMMAND + (MAX_DIM_PAR * MAX_NUM_PAR), stdin); // reads at most the specified number of characters (including \n)
    if (res == 0)  // error while reading or read zero bytes (i.e. pressed ctrl+d as first character)
	{
        cerr << "stdin read error.\n";
    	return;                      // return to main loop to perform again the fgets 
	}
	 
	// take the command and the parameters and counts them
	// reads the commands and any parameters, the number of %s are equal to MAX_NUM_PAR + 1 (command)
	num_string_readed = sscanf(buf, "%s %s %s", command, parameters[0],parameters[1]);    
     
    command_code = identify_command(command);       // call function to identify the entered command. 
    // Switch which, depending on the parameter entered by the user, will perform the necessary operations to execute it.
    switch(command_code)
    {
        case 0:    // exit/logout -> no parameters
             {
                 send_close_conn_request(username, session_key);    // send message to close the connection
                 break;
             }
        case 1:    // list -> no parameters
             {
                 send_list_request(username, session_key);          // send message to request the user file list on the server
                 break;
             }
        case 2:    // upload -> 1 parameter
             {
             	 char file_name [MAX_DIM_PAR];       // contain the file name
               	
               	 if (num_string_readed == 2)         // correct number of parameter
               	 {
                     if (strlen(parameters[0]) > MAX_DIM_PAR)        // other dimension check of the parameters
                    {
                       	cerr << err_dim_par;        // print error mex
                   	}
                   	else
                   	{
                       	sscanf(parameters[0], "%s", file_name);     // take file name
       					
       					send_upload_request(session_key, file_name, username);	// start the upload operation
                   	}
               	}
               	else
                   	cerr << err_wrong_num_par;      // return error mex
                break;
             }
        case 3:    // download -> 1 parameter
             {
                 char file_name [MAX_DIM_PAR];       // contain the file name
                 
                 if (num_string_readed == 2)
                 {
                     if (strlen(parameters[0]) > MAX_DIM_PAR)
                     {
                         cerr << err_dim_par;        // print error mex
                     }
                     else
                     {
                         sscanf(parameters[0], "%s", file_name);     // take file name
                         send_download_request(session_key, file_name, username);	// start the download operation
                     }
                 }
                 else
                     cerr << err_wrong_num_par;      // return error mex
                 
                 break;
             }
        case 4:    // rename -> 2 parameters
             {
                char old_file_name [MAX_DIM_PAR] , new_file_name [MAX_DIM_PAR];         // contain the file names 
               	
               	if (num_string_readed == 3)
               	{
                   	if ((strlen(parameters[0]) > MAX_DIM_PAR) || (strlen(parameters[1]) > MAX_DIM_PAR))     // other dimension check of the parameters
                   	{
                       	cerr << err_dim_par;        // print error mex
                   	}
                   	else
                   	{
                       	sscanf(parameters[0], "%s", old_file_name);  // take old file name
       					sscanf(parameters[1], "%s", new_file_name);  // take new file name
       					
       					send_rename_request(session_key, old_file_name, new_file_name);// checking the correctness of strings
                   	}
               	}
               	else
                   	cerr << err_wrong_num_par;      // return error mex
       	
                break;
             }
        case 5:    // delete -> 1 parameter
             {
                char file_name [MAX_DIM_PAR];       // contain the file name
               	
               	if (num_string_readed == 2)         // correct number of parameter
               	{
                   	if (strlen(parameters[0]) > MAX_DIM_PAR)        // other dimension check of the parameters
                   	{
                       	cerr << err_dim_par;        // print error mex
                   	}
                   	else
                   	{
                       	sscanf(parameters[0], "%s", file_name);     // take file name
       					
       					send_delete_request(session_key, file_name);// send delete request
                   	}
               	}
               	else
                   	cerr << err_wrong_num_par;      // return error mex
                break;
             }
        case 6:    // help -> 0/1 parameter
             {
                if (num_string_readed == 2)		   // read command and parameter
      			    help(parameters[0]);		   // call the help function with one parameter
          		else if (num_string_readed == 1)   // entered only the command
      			    cout << HELP;                  // call the help function without parameter
          		else
              		cerr << err_wrong_num_par;
                break;
             }
        default:
             {
                 cerr << err_command;       // print error mex
             }
    }
}
// ------------------------------- start: functions to manage user entering of commands -------------------------------

// ------------------------------- start: connection function -------------------------------
/*
    Description:  
        function to authenticate the server (through the control of its certifier and the authentication of its public key)
    Parameters:
        - buffer: buffer conatining 
        - buffer_size: the size of the buffer 
    Return:
        - public key of the server
*/
EVP_PKEY* verify_server_cert( unsigned char* buffer, long buffer_size )
{
	int ret;                               // used for return values
	
	// load the CA's certificate    
    FILE* cacert_file = fopen(CA_cert_path.c_str(), "r");           // open CA certificate
    if(!cacert_file)                                                // CA cert file control check
    {
        cerr << "Error: cannot open file '" << CA_cert_path << "' (missing?)\n"; 
        exit(1); 
    }
    X509* cacert = PEM_read_X509(cacert_file, NULL, NULL, NULL);    // read X509
    fclose(cacert_file);                                            // close CA certificate file
    if(!cacert)                                                     // CA cert read X509 control check
    { 
        cerr << "Error: PEM_read_X509 returned NULL\n"; 
        exit(1); 
    }
    
    // load the CRL
    FILE* crl_file = fopen(CA_CRL_path.c_str(), "r");               // open CRL
    if(!crl_file)                                                   // CRL file control check
    { 
        cerr << "Error: cannot open file '" << CA_CRL_path << "' (missing?)\n"; 
        exit(1); 
    }
    X509_CRL* crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);  // read X509
    fclose(crl_file);                                               // close CRL file
    if(!crl)                                                        // CRL read X509 control check
    { 
        cerr << "Error: PEM_read_X509_CRL returned NULL\n";
        exit(1); 
    }
    
    // build a store with the CA's certificate and the CRL:
    X509_STORE* store = X509_STORE_new();                           //create new X509 store
    if(!store)                          
    { 
        cerr << "Error: X509_STORE_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; 
        exit(1); 
    }
    ret = X509_STORE_add_cert(store, cacert);                       // add CA cert into store
    if(ret != 1) 
    { 
        cerr << "Error: X509_STORE_add_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; 
        exit(1); 
    }
    ret = X509_STORE_add_crl(store, crl);                           // add CRL into store
    if(ret != 1) 
    { 
        cerr << "Error: X509_STORE_add_crl returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; 
        exit(1); 
    }
    ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);       // configure the store to check with CRl any certificate
    if(ret != 1) 
    { 
        cerr << "Error: X509_STORE_set_flags returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; 
        exit(1); 
    }
    
    // load the server's certificate: deserialize it from buffer (from BIO struct)
    BIO* bio = BIO_new(BIO_s_mem());                // create new BIO
	if(!bio) 
    	error("Error in verify_server_certificate: failed to allocate BIO_s_mem.\n");
	
	if(!BIO_write(bio, buffer, buffer_size ))              // write in BIO the server certificate contained in buffer
    	error("Error in verify_server_certificate: BIO_write failure.\n");
	
	X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL); //read a certificate in PEM format from the BIO.
    if(!cert)
        error("Error in verify_server_certificate: PEM_read_bio_X509 returned NULL.\n");
	BIO_free(bio);                                 // deallocate BIO

    // verify the certificate:
    X509_STORE_CTX* certvfy_ctx = X509_STORE_CTX_new();             // create new context to verify the certificate
    if(!certvfy_ctx) 
    { 
        cerr << "Error: X509_STORE_CTX_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; 
        exit(1); 
    }
    ret = X509_STORE_CTX_init(certvfy_ctx, store, cert, NULL);      // initialise the verification context
    if(ret != 1) 
    { 
        cerr << "Error: X509_STORE_CTX_init returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; 
        exit(1); 
    }
    ret = X509_verify_cert(certvfy_ctx);                            // verify the certificate
    // returns: 1 if the certificate has been verified, 0 if it cannot be verified, and <0 if there was an error
    if(ret != 1)                                // there is an error in the verification 
    { 
        cerr << "Error: X509_verify_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; 
        exit(1); 
    }
    
    // print the successful verification to screen
    char* tmp = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);    // obtain the name of the owner of the certificate
    char* tmp2 = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);    // obtain CA name
    cout << "Certificate of \"" << tmp << "\" (released by \"" << tmp2 << "\") verified successfully\n";
    free(tmp);                                                              
    free(tmp2);
    
    // obtan server public key from certificate
    EVP_PKEY* server_pubkey = X509_get_pubkey(cert);
    
    // deallocate data:   
    X509_free(cert);
    X509_STORE_free(store);
    X509_STORE_CTX_free(certvfy_ctx);

    return  server_pubkey; 
}

/*
    Description:  
        function to authenticate the client and server to establish a secure, authenticated connection 
        between client and server. (First communication after connecting the sockets)
    Parameters:
        - buffer: utility buffer to contain the message
        - mex_buffer: buffer to contain the message to send
        - username: username of the user that uses the client
        - user_key: the private key of the user
        - aad: buffer to allocate aad
        - session_key: buffer to contain the symmetric session key
*/
void start_authenticated_conn(unsigned char* buffer, unsigned char* mex_buffer, char* username, EVP_PKEY* user_key, unsigned char* aad, unsigned char* session_key)
{
    int message_size;               // size of the message to send or received 
    int ret;
    uint32_t network_number;
    
    // create client nonce (CN)
    unsigned char* mynonce=(unsigned char*)malloc(NONCE_SIZE);  // nonce created by client
	if(!mynonce) 
    	error("Error in mynonce Malloc.\n");
	RAND_poll();                                               // seed random generator
	ret = RAND_bytes((unsigned char*)&mynonce[0],NONCE_SIZE);  // create random bytes for nonce
	if(ret!=1)
    	error("Error in RAND_bytes.\n");
    
    // Add nonce and username to buffer
    memcpy(buffer,mynonce,NONCE_SIZE);
	memcpy(buffer+NONCE_SIZE,username,strlen(username));

    // 1) Send nonce and username -> messages format is -> ( size_sign | sign | nonce | username )
    unsigned int signed_size = digsign_sign(user_key, buffer, NONCE_SIZE+strlen(username),mex_buffer);
	send_msg(socket_server, signed_size, mex_buffer);        // send the messages
    
    // 2.0) Receive server certificate	(sended by the server)	
    ret = recv(socket_server, &network_number, sizeof(uint32_t), 0);    // receive size of message
	if(ret <= 0)
    	error("Error in socket receive.\n");
	
	long certsize = ntohl(network_number);                 // take size of the server certificate
	cout<<"\nServer certificate Size: "<< certsize <<"\n";   // show dimension of certificate
	
	unsigned char* certbuffer = (unsigned char*) malloc(certsize); // allocate the buffer to receive the server certificate
	if(!certbuffer)
    	error("Error in Malloc for the buffer for server certificate.\n");
	
	unsigned int received = 0;             // set the quantity received to 0
	while(received < certsize)             // while to read the whole server certificate
	{
		ret = recv(socket_server, certbuffer+received, certsize-received, 0);	// receive server certificate
		if(ret < 0)
    		error("Error in server certificate receive.\n");
		received += ret;                  // update received
	}
	
	// -- Verify server certificate and retrieve the server public key
	EVP_PKEY* server_pub_k = verify_server_cert( certbuffer, certsize );
    
    // 2.1) Receive signed message from server, format -> ( sign_size | sign(client nonce | server nonce | ECDH pub_k) | client nonce | server nonce | ECDH pub_k )
    
    signed_size = receive_msg(socket_server, buffer);     // receive signed message
	if(signed_size <= 0)               // verify the size of signed message received
    	error("Error in receiving server signature.\n");
	
	// -- verify client nonce received from the server
	unsigned int signature_size =*(unsigned int*)buffer;
	signature_size += sizeof(unsigned int);                        // set pointer to nonce in the message
	if(memcmp(buffer + signature_size, mynonce, NONCE_SIZE) != 0)    // verify the nonce sended by server
    	error("Error: the nonce received by server is not valid!\n");
	free(mynonce);             // delete nonce
	
	// -- Verify signature and take server nonce
	message_size = digsign_verify(server_pub_k, buffer, signed_size, mex_buffer);
	if(message_size <= 0)                      // check if signature is valid or not
    	error("Error: signature received is invalid!\n");
	
	unsigned char* server_nonce = (unsigned char*) malloc(NONCE_SIZE);  // allocate buffer for server nonce
	if(!server_nonce)
    	error("Error in Malloc for server nonce");
	
	memcpy(server_nonce,mex_buffer + NONCE_SIZE,NONCE_SIZE);       // copy the nonce received from server in server nonce buffer
    
    // 3) Extract ECDH server public key
    
    BIO* ecdh_s_bio= BIO_new(BIO_s_mem());      // create BIO for the DH server public key
    BIO_write(ecdh_s_bio, mex_buffer + NONCE_SIZE + NONCE_SIZE, message_size - NONCE_SIZE - NONCE_SIZE);   // write in BIO the ECDH server public key contained in buffer
	EVP_PKEY* ecdh_server_pubkey = PEM_read_bio_PUBKEY(ecdh_s_bio, NULL, NULL, NULL);   //read ECDH public key in PEM format from the BIO.
	BIO_free(ecdh_s_bio);                       // free BIO for the DH server public key
	
	// -- create ECDH private key
	EVP_PKEY* DH_privk = dh_gen_key();     // create ECDH private key
	unsigned char* DH_pubk_buffer = NULL;       // buffer to ECDH pubk    
	BIO* key_bio = BIO_new(BIO_s_mem());            // create BIO for the DH key
    if(!key_bio) 
        error("Error in the connection establishment: failed to allocate BIO_s_mem..\n");
    
    if(!PEM_write_bio_PUBKEY(key_bio, DH_privk))    // extract DH public key and serialize in BIO
        error("Error in the connection establishment: failed to write_bio_PUBKEY.\n");
	
	long pubk_size = BIO_get_mem_data(key_bio, &DH_pubk_buffer);    // get size of server DH pubk
    if (pubk_size <= 0) 
        error("Error in the connection establishment: failed to BIO_get_mem_data.\n");
	
	message_size = 0;                              // reset message size to 0
	memcpy(mex_buffer, server_nonce, NONCE_SIZE);     // copy in message il server nonce
	message_size += NONCE_SIZE;                    
	memcpy(mex_buffer + message_size, DH_pubk_buffer, pubk_size);	           // copy in message the ECDH client public key
	message_size += pubk_size;
	signed_size = digsign_sign(user_key, mex_buffer, message_size, buffer);   // sign (server_nonce | ECDH client pubk)
	
	// -- send signed ECDH client public key
	send_msg(socket_server, signed_size, buffer);    // send message -> format is -> ( sign_size | sign() | server nonce | ECDH client pubk )
	free(server_nonce);                            // free server nonce
	
	// -- compute the shared secret key
	size_t shared_secret_len;                  // size of the shared secret len               
	EVP_PKEY_CTX *derive_ctx;                  // create context to derive shared secret    
	derive_ctx = EVP_PKEY_CTX_new(DH_privk, NULL);     // allocate a context
	if (!derive_ctx) 
    	handleErrors();
    if (EVP_PKEY_derive_init(derive_ctx) <= 0)         // initialise the derivation context
        handleErrors();
    // use ECDH server public key for derive the shared secret
    if (EVP_PKEY_derive_set_peer(derive_ctx, ecdh_server_pubkey) <= 0) 
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
	EVP_PKEY_CTX_free(derive_ctx);         // free context
	EVP_PKEY_free(ecdh_server_pubkey);     // free ECDH server public key
	EVP_PKEY_free(DH_privk);               // free ECDH client private key
	
	// don't use directly the shared secret as a key because it does not have the entropy necessary to be a good symmetric key
	// create the session key (symmetric key)
	ret = dh_generate_session_key(shared_secret, (unsigned int)shared_secret_len , session_key);
	free(shared_secret);                   // free shared secret
	
	// 5 - receiving confirmation of successfully established session
	// set nonce counters, at the beginning are equal to 0
	server_counter = 0;            // is the server nonce, is used to verify the nonce in the messages sent by the server
	client_counter = 0;            // is the client nonce, is used for nonce in the messages sent by the client
	short cmd_code;                // code of the command
	unsigned int aad_len;          // len of AAD
	
	// -- receive the message -> format is -> ( cmd_code | tag | IV | nonce_len | nonce | ciphertext)
	message_size = receive_msg(socket_server, buffer);           // receive confirmation or not
	unsigned int received_counter=*(unsigned int*)(buffer + MSG_AAD_OFFSET);   //take the received server nonce
	if(received_counter == server_counter)    // if is equal is correct otherwhise the message is not fresh
	{
		ret = decryptor(buffer, message_size, session_key, cmd_code, aad, aad_len, mex_buffer);  // decrypt the received message
		inc_counter_nonce(server_counter);            // increment the server nonce
		if (ret >= 0)                         // correctly decrypted 
		{
    		// check the cmd_code received
    		if ((cmd_code != -1) && (cmd_code == 1))   // all is ok
    		{
        		cout << aut_encr_conn_succ;            // print for user, message of successful authenticated and protected connection between client and server
        		print_command_legend();                // cout all avaible command and their explanations
        		print_files_list(mex_buffer, ret);     // print the list of the user file stored in the server 
    		}
    		else if (cmd_code == -1)                   // error message
    		{
    			memcpy(mex_buffer + ret - 1, "\0", 1); // for secure
            	cerr << mex_buffer;                    // print the error message
            	quit_program();                        // close connection
    		}
		}
	}
	else
		cerr << err_rec_nonce;
	
}
// ------------------------------- end: connection function -------------------------------

// ------------------------------- start: initial parameter control functions -------------------------------
/*
    Description:  
        function to connect the client to the server
    Parameters:
        - ip_server: server ip address
        - server_port: port for the connection
*/
void open_server_connection(char* ip_server, int server_port)
{
     unsigned short int p;              
     int ret;
     struct sockaddr_in addr_server;
     
     // check that the port value passed as a parameter is valid
     if ((server_port < 0) || (server_port > 65535))	
     {
     	cerr << "Invalid port number: " << server_port << ".\n";
     	exit(1);
     }				
        
     p = server_port;                       // the port is correct
     
     // create socket 
     if ((socket_server = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        error("Error in the \"socket()\": ");					
     
     memset((char*)&addr_server, 0, sizeof(addr_server));		//cleans, sets the memory zone to 0
     addr_server.sin_family = AF_INET;
     addr_server.sin_port = htons(p);
     //server address conversion from numeric address to Byte
     if (!inet_pton(AF_INET, ip_server , &addr_server.sin_addr.s_addr))		
        error("Invalid server address.\n");                     //segnalazione errore indirizzo server non valido
     
     // connection to the server indicated in the parameters
     ret = connect(socket_server, ( struct sockaddr *) &addr_server, sizeof(addr_server));
     if (ret<0)			
        error("Errore nella \"connect()\":");                  // connection error
}

/*
    Description: only for test purpose
    	function to enter the password for the client's private key automatically, used to speed up testing. 
    	In the delivered code the function will be commented out but not removed so that users can do testing faster. 
    	The password should be entered only when you want to initiate a secure connection with a client. 
*/
int pass_cb(char *buf, int size, int rwflag, void *u)
{
	int len;

    char tmp[] = "!UserA_Psw!";     // psw for the UserA
    //char tmp[] = "!UserB_Psw!";     // psw for the UserB
    //char tmp[] = "!UserC_Psw!";     // psw for the UserC
    len = strlen(tmp);

    if (len <= 0) 
    	return 0;
    if (len > size) 
    	len = size;
    memcpy(buf, tmp, len);
   	return len;
}

/*
    Description:  
        function which checks the correctness of the username passed as a parameter
    Parameters:
        - username: username to be checked
        - username_buffer: buffer which will contain the username
        - buffer_len: length of the buffer
    Return:
        - the private key of the user
*/
EVP_PKEY* check_username(char* username, char* username_buffer , int buffer_len)
{
    // check the the length of the username
    if(strlen(username) >= buffer_len)
        error("Username is too long (can be maximum 19 characters).\n");
    
    // check if the username is valid. SEE NOTE 0 at the bottom of the file.
    
	string filename = keys_path + string(username)+"_privk.pem";    // path to retrieve the privk of the user
	
	EVP_PKEY* user_key;
	FILE* file = fopen(filename.c_str(), "r");                 // open the file containing the privk   
	if(!file)                                              
	    error("User does not have a key file. The user is not signed or the username isn't correct.\n");

	user_key = PEM_read_PrivateKey(file, NULL, NULL, NULL);    // read the privk
	//user_key = PEM_read_PrivateKey(file, NULL, pass_cb, NULL);    // read the privk -- only for test purpose --
	if(!user_key) 
    	error("user_key Error\n");
	fclose(file);                                              // close the file containing the privk
	
	// user is valid, save the username in array
	int cx = snprintf(username_buffer,buffer_len ,"%s",username);
	if (cx < 0)
    	error("Error in username copy.\n");
	
	return user_key;                                   // username is correct, return privk of the user
}
// ------------------------------- end: initial parameter control functions -------------------------------

// ------------------------------- MAIN -------------------------------
// Argument of the main must be: <program_name> <server ip> <server port> <username>
int main(int argc, char *argv[])
{
    char username[USERNAME_SIZE];           // contain the username of the client user (passed as a parameter)
    EVP_PKEY* user_key;                     // contain the private key of the user that uses the client 
    int sockfd;                             // fd of the socket connected to the server

    unsigned char* buffer = (unsigned char*)malloc(MAX_SIZE);   // utility buffer for the operation
	if(!buffer)
    	error("Error in buffer Malloc.\n");
	
	unsigned char* message = (unsigned char*)malloc(MAX_SIZE);  // buffer to contain the messages to be sent and received
	if(!message)
    	error("Error in message Malloc.\n");
	
	unsigned char* aad = (unsigned char*)malloc(MAX_SIZE);     // buffer for aad
	if(!aad)
    	error("Error in aad Malloc.\n");
    	
    unsigned char* session_key = (unsigned char*) malloc(EVP_MD_size(sign_alg));    // buffer to the session key , size = digest
	if (!session_key) 
    	error("Error in session key malloc.\n");

    if (argc != 4)		//first control of the parameters, check that the correct number of parameters have been passed
    {
       printf("Wrong argument number.\nThe correct syntax is  %s <server ip> <server port> <username>.\n", argv[0]);
       exit(1);
    }
    
    user_key = check_username(argv[3],username,USERNAME_SIZE); // control for the username 
       
    open_server_connection(argv[1], atoi(argv[2]));		       // connection to the server
	
	//visualizza messaggio di connessione al server
    printf("Successful server connection, ip %s and port %s\n",argv[1],argv[2]);		
    cout << mex_after_server_conn;   
    
    // establish an authenticated and secure connection
    start_authenticated_conn(buffer, message, username, user_key, aad, session_key);
    
    cout << mex_ready_command;              // show to user that the command line is ready to take commands
        
    // main while, 
    while(1)
    {
        read_command(username, session_key);         // take the command
    }
}

/*
    NOTE 0:
        The signin phase is not considered in this project to simplify the work and because it is not the focus of the course. 
        The login is done by entering a valid username (of an already registered user) as a parameter when the client is run on
        command line. In order to consider a username valid (i.e. able to talk to the server), it is checked whether the 
        private key for that username is present. If no private key is present for that username (with the name 'username_privk.pem') 
        the username will be considered invalid. In this project, for testing purposes, there are 3 valid usernames "UserA", "UserB" 
        and "UserC".
*/
