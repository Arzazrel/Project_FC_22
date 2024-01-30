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

// ------------------------------- start: struct and global variables -------------------------------

// ------------------------------- end: struct and global variables -------------------------------


// ------------------------------- start: error error messages -------------------------------
string err_open_file = "Error: cannot open file";       // error that occurs when a file cannot be opened

// ------------------------------- end: error messages -------------------------------

// ------------------------------- start: general function -------------------------------

/*
    Description: 
        
    Parameters:
        - 
*/
void error(const char *msg)
{
    perror(msg);
    exit(1);
}

/*
    Description: function to print the legend of the command for the user
*/
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

    /*
    // load the CA's certificate:
    string cacert_file_name="clientFiles/CA_cert.pem";
    FILE* cacert_file = fopen(cacert_file_name.c_str(), "r");
   if(!cacert_file){ cerr << "Error: cannot open file '" << cacert_file_name << "' (missing?)\n"; exit(1); }
   X509* cacert = PEM_read_X509(cacert_file, NULL, NULL, NULL);
   fclose(cacert_file);
   if(!cacert){ cerr << "Error: PEM_read_X509 returned NULL\n"; exit(1); }

   // load the CRL:
   string crl_file_name="clientFiles/CA_crl.pem";
   FILE* crl_file = fopen(crl_file_name.c_str(), "r");
   if(!crl_file){ cerr << "Error: cannot open file '" << crl_file_name << "' (missing?)\n"; exit(1); }
   X509_CRL* crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
   fclose(crl_file);
   if(!crl){ cerr << "Error: PEM_read_X509_CRL returned NULL\n"; exit(1); }

   // build a store with the CA's certificate and the CRL:
   X509_STORE* store = X509_STORE_new();
   if(!store) { cerr << "Error: X509_STORE_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
   ret = X509_STORE_add_cert(store, cacert);
   if(ret != 1) { cerr << "Error: X509_STORE_add_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
   ret = X509_STORE_add_crl(store, crl);
   if(ret != 1) { cerr << "Error: X509_STORE_add_crl returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
   ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
   if(ret != 1) { cerr << "Error: X509_STORE_set_flags returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }

   // load the server's certificate: deserialize it from buffer
    BIO* bio = BIO_new(BIO_s_mem());
	if(!bio) { cerr<<"verify_server_certificate: Failed to allocate BIO_s_mem";exit(1); }
	if(!BIO_write(bio, buffer, buffer_size )) { cerr<<"verify_server_certificate: BIO_write  error";exit(1); }
	X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if(!cert){ cerr << "Error: PEM_read_bio_X509 returned NULL\n"; exit(1); }
	BIO_free(bio);
   
   // verify the certificate:
   X509_STORE_CTX* certvfy_ctx = X509_STORE_CTX_new();
   if(!certvfy_ctx) { cerr << "Error: X509_STORE_CTX_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
   ret = X509_STORE_CTX_init(certvfy_ctx, store, cert, NULL);
   if(ret != 1) { cerr << "Error: X509_STORE_CTX_init returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
   ret = X509_verify_cert(certvfy_ctx);
   if(ret != 1) { cerr << "Error: X509_verify_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }

   // print the successful verification to screen:
   char* tmp = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
   char* tmp2 = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
   cout << "Certificate of \"" << tmp << "\" (released by \"" << tmp2 << "\") verified successfully"<<endl;
   
   free(tmp);
   free(tmp2);
   
   EVP_PKEY* server_pubkey = X509_get_pubkey(cert);
   
   X509_free(cert);
   X509_STORE_free(store);
   X509_STORE_CTX_free(certvfy_ctx);

   return  server_pubkey; 
   */
}

// ------------------------------- end: connection function -------------------------------

// ------------------------------- MAIN -------------------------------
int main(int argc, char *argv[])
{
}
