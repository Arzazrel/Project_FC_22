/*
    Created on Tue Jan 30 09:10:50 2024
    @author: Alessandro Diana
*/
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
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
#include "common.h"                 // 

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
string err_rec_nonce = "Received nonce is not fresh.\n";                        // error that occurs when the received nonce is not correct

string rename_failed = "Error: rename operation failed.\n";                     // error that occurs when the rename operation failed

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
    unsigned char* message;        // contain the message to be sent
    unsigned int msg_len = 0;      // the len of the message to encrypt
    short cmd_code;                // code of the command
	unsigned int aad_len;          // len of AAD
    int ret;

	cout << "Send request to close the server connection...\n";
	
	// set packet to send, the packet format is -> ( 0 | tag | IV | aad_len | client_nonce | username )
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
	
	// wait the response of the server, format is -> ( cmd_code | tag | IV | nonce_len | nonce | ciphertext)
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
            	cout << message;                      // print the error message
    		}
    		else if (cmd_code == -1)                  // error message
    		{
    			memcpy(message + ret - 1, "\0", 1);   // for secure
            	cerr << message;                      // print the error message
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
	
	// wait the response of the server, format is -> ( cmd_code | tag | IV | nonce_len | nonce | ciphertext)
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
            	cerr << message;                      // print the error message
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
        function to send the request to close the connection with the server
    Parameters:
        - username: username of the user that uses the client
        - session_key: buffer to contain the symmetric session key
        - old_file_name: file name to be changed
        - new_file_name: new file name
*/
void send_rename_request(char* username, unsigned char* session_key, char* old_file_name, char* new_file_name)
{
    unsigned char* message;         // contain the message to be sent
    unsigned int msg_len = 0;       // the len of the message to encrypt
    short cmd_code = 4;             // code of the command
	unsigned int aad_len;           // len of AAD
    int ret;
    
    // check the dimension fo a string
    if ((strlen(old_file_name) > MAX_DIM_PAR) || (strlen(new_file_name) > MAX_DIM_PAR) )
    {
        cerr << "File name too big.\n";
        return;     
    }
    
    string old_s = old_file_name;   // string to contain the old file name
    string new_s = new_file_name;   // string to contain the new file name
    
    // checking the correctness of strings
    if ( check_file_name(old_s) && check_file_name(new_file_name))
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
    	memcpy(aad + sizeof(unsigned int),(unsigned char*)&new_n_len,sizeof(unsigned int));  // copy new file name len
    	
    	// -- buffer 
    	unsigned char* buffer = (unsigned char*)malloc(MAX_SIZE);      // temp buffer for message 
    	if(!buffer)
        	error("Error in send_rename_request: buffer Malloc error.\n");
        
        // -- encrypt the message, cmd_code for the rename operation is 4
    	ret = encryptor(cmd_code,aad, sizeof(unsigned int), message, msg_len, session_key, buffer);
    	if (ret >= 0)      // successfully encrypted
    	{
        	// send the rename request to the server
    		send_msg(socket_server, ret, buffer);     // send user file list to client
    		inc_counter_nonce(client_counter);        // update client counter
    	}
        
        // free message and reallocate with a different dimension
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
        		if ((cmd_code != -1) && (cmd_code == 4))  // all is ok
        		{
            		memcpy(message + ret - 1, "\0", 1);   // for secure
                	cout << message;                      // print the message
        		}
        		else if (cmd_code == -1)                  // error message
        		{
        			memcpy(message + ret - 1, "\0", 1);   // for secure
                	cerr << message;                      // print the error message
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
                 break;
             }
        case 3:    // download -> 1 parameter
             {
                 break;
             }
        case 4:    // rename -> 2 parameters
             {
                char old_file_name [MAX_DIM_PAR] , new_file_name [MAX_DIM_PAR];         //conterranno l'username e psw digitati da tastiera
               	
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
       					
       					send_rename_request(username, session_key, old_file_name, new_file_name);// checking the correctness of strings
                   	}
               	}
               	else
                   	cerr << err_wrong_num_par;      // return error mex
       	
                break;
             }
        case 5:    // delete -> 1 parameter
             {
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
    		if ((cmd_code != -1) && (cmd_code == 1))      // all is ok
    		{
        		cout << aut_encr_conn_succ;          // print for user, message of successful authenticated and protected connection between client and server
        		print_command_legend();              // cout all avaible command and their explanations
        		print_files_list(mex_buffer, ret);   // print the list of the user file stored in the server 
    		}
    		else if (cmd_code == -1)                      // error message
    		{
    			memcpy(mex_buffer + ret - 1, "\0", 1);	// for secure
            	cerr << mex_buffer;                  // print the error message
            	// +++++++++++++++++++++++++++ close connection +++++++++++++++++++
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
    
    int i = 1;                  // take the cmd_code of the command entered by user
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
