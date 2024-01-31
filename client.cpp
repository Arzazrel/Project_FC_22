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
#include <stdio.h>  // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include "common.h"
#include <arpa/inet.h>

// ------------------------------- start: struct and global variables -------------------------------
int socket_server, fdmax, stato;	//variabili per contenere una il fd del socket del server e l'altra per contenere l'fd maggiore nella lista della select,
									//stato conterrà il numero che identificherà qual è stato l'ultimo comando fatto dal client da cui si aspetta una risposta dal server
									//il valore di stato identifica il comando di posizione comandi[stato]
// message to be shown to the user after the first connection to the server but before authentication and the session is established.
string mex_after_server_conn = "Server authentication in progress...\n";  
// ------------------------------- end: struct and global variables -------------------------------

// ------------------------------- start: path -------------------------------
string keys_path = "ClientFiles/Keys/";                     // path to users keys folder
string cert_path = "ClientFiles/Certificates/";             // path to certificates folder
string CA_cert_path = "ClientFiles/Certificates/FoC_Proj_CA_cert.pem";      // path to CA certificate
string CA_CRL_path = "ClientFiles/Certificates/FoC_Proj_CA_CRL.pem";        // path to CRL

// ------------------------------- end: path -------------------------------

// ------------------------------- start: error messages -------------------------------
string err_open_file = "Error: cannot open file";       // error that occurs when a file cannot be opened

// ------------------------------- end: error messages -------------------------------

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


//   Description: function to print the legend of the command for the user
void print_command_legend()
{
	cout<<"-----------------------------------------------------------\n";
	cout<<"Available Operation:"<<"\n";
	cout<<"--ex: exit program"<<"\n";
	cout<<"--up <client_filename> <server_filename>: exit program"<<"\n";
	cout<<"--dw <filename>: download a specified file stored on the server"<<"\n";
	cout<<"--del <filename>: delete a specified file stored on the server"<<"\n";
	cout<<"--l: print the list of the file stored on the server"<<"\n";
	cout<<"--r <old_filename> <new_filename>: rename a file stored on the server"<<"\n";
	cout<<"--help: print avaiable operation list"<<"\n";
}

/*
    Description:  
        function to print the list of the files stored in the server, for the user logged in this client.
    Parameters:
        - buffer: buffer conatining the list of the file stored on the server
        - buffer_size: the size of the buffer 
*/
void  print_files_list(unsigned char* buffer, unsigned int buffer_size)
{
	cout<<"--------------------------------------------------"<<"\n";
	cout<<"Files stored on the server: "<<"\n";
	unsigned int read=0;
	/*
	char nickname[USERNAME_SIZE];
	while(read<buffer_size){
	read+=snprintf(nickname,sizeof(nickname),"%s",buffer+read);
	printf("%s \n",nickname);
	read++;
	*/
}

// ------------------------------- end: general function -------------------------------

// ------------------------------- start: connection function -------------------------------

/*
    Description:  
        function to authenticate the server and to do login
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
    
    // load the server's certificate: deserialize it from buffer
    BIO* bio = BIO_new(BIO_s_mem());
	if(!bio) { cerr<<"verify_server_certificate: Failed to allocate BIO_s_mem";exit(1); }
	if(!BIO_write(bio, buffer, buffer_size )) { cerr<<"verify_server_certificate: BIO_write  error";exit(1); }
	X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if(!cert){ cerr << "Error: PEM_read_bio_X509 returned NULL\n"; exit(1); }
	BIO_free(bio);

    // verify the certificate:
    X509_STORE_CTX* certvfy_ctx = X509_STORE_CTX_new();             // create new context to verify the certificate
    if(!certvfy_ctx) 
    { 
        cerr << "Error: X509_STORE_CTX_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); 
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
        error("Invalid port number: " + server_port + ".\n");
        
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

	user_key= PEM_read_PrivateKey(file, NULL, NULL, NULL);     // read the privk
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
    char username[USERNAME_SIZE];           // will contain the username of the client user (passed as a parameter)
    EVP_PKEY* user_key;                     // contain the private key of the user that uses the client 

    if (argc != 4)		//first control of the parameters, check that the correct number of parameters have been passed
    {
       printf("Wrong argument number.\nThe correct syntax is  %s <server ip> <server port> <username>.\n", argv[0]);
       exit(1);
    }
    
    user_key = check_username(argv[3],username,USERNAME_SIZE);  // control for the username 
       
    open_server_connection(argv[1], atoi(argv[2]));		  // connection to the server
	
	//visualizza messaggio di connessione al server
    printf("Successful server connection, ip %s and port %s\n",argv[1],argv[2]);		
    cout << mex_after_server_conn;                                   
    
    //Send nonce and username	
    
    //Verify server certificate		
    
    //receive signedmessage
    
    //verify signature and take server nonce	
    
    //extract ecdh_server_pubkey
    
    //generate ecdh_privkey												//visualizza il messaggio iniziale di descrizione dei comandi
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
