/*
    Created on Tue Jan 30 09:10:50 2024
    @author: Alessandro Diana
    Description:
        file containing functions and variables that are common (are used) by both client and server.
*/
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <cmath>
#include <iostream> 
#include <fstream> 
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h> 
#include <sys/types.h> 
#include <sys/stat.h>       // for have size of the file > 2GBi

// ------------------------------- start: constant -------------------------------
#define USERNAME_SIZE 20            // maximum length for users' usernames
#define MAX_CLIENTS 20              // maximum number of clients connected to the server at the same time
// -- define for messages format -- GCM mex format is -> ( cmd_code | tag | IV | aad_len | aad | ciphertext)
// For further clarification on the maximum size of packages and file management in this project, SEE NOTE 0 at the end of the file or look at the documentation on github.
#define MAX_FILE_SIZE (long)pow(2,32)    	// maximum size of files that can be saved and received by the cloud server 4GBi = 2^32 Bytes
#define MAX_DIM_FILE_NAME 100       // maximum length for a file_names, a size of 100 each is more than sufficient for most legitimate cases.
#define MAX_SIZE_F_OS MAX_FILE_SIZE + 200   // maximum length for a packet with a big file (oversize)
#define FRAGMENT_SIZE 20*(long)pow(2,20)    // maximum size of files that can be encrypted or decrypted in a single update step (for further clarification SEE NOTE 1 or documentation) 20MBi = 20*2^20 Bytes <- for motivation of chosen value -> SEE NOTE 2
// Messages exchanged normally do not contain large files but keys, certificates, signatures or text (they do not need large buffers to be handled)
#define MAX_SIZE 100*(long)pow(2,10)        // the maximum length for normal message (100 KBi)
#define MSG_MAX MAX_SIZE - 200
#define NONCE_SIZE 4                // size of the nonce
#define MSG_AAD_OFFSET 34           // offset of the AAD(usually only nonce) in the message format (AAD is after cmd_code,tag,IV,aad_len)
#define MSG_AAD_LEN_OFFSET 30       // offset of the AAD_len in the message format (AAD_len is after cmd_code,tag,IV)

static char ok_chars[] = "abcdefghijklmnopqrstuvwxyz"
                         "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                         "1234567890_./";    // characters that are permitted by the white list
// ------------------------------- end: constant -------------------------------

using namespace std;

string err_rec_nonce = "Received nonce is not fresh.\n";        // error that occurs when a received nonce is not correct
string err_rec_cmd_code = "Received cmd_code is uncorrect.\n";  // error that occurs when a received cmd_code does not correspond to the one sent

// ------------------------------- start: parmaeter and utility variables for encrypt and digital sign -------------------------------
const EVP_CIPHER* AE_cipher = EVP_aes_128_gcm();        // for ecnryption using AES with 128 bit 
int AE_iv_len =  EVP_CIPHER_iv_length(AE_cipher);       // size of the IV for encryption and decryption
int AE_block_size = EVP_CIPHER_block_size(AE_cipher);   // size of the block for encryption and decryption
const int AE_tag_len = 16;                              // size (in Bytes) of the TAG in GCM with AES-128
const EVP_MD* sign_alg = EVP_sha256();                  // indicates algorithm to sign (hash), in this case SHA 256

// ------------------------------- end: parmaeter and utility variables for encrypt and digital sign -------------------------------

// ------------------------------- start: function to manage error message -------------------------------
/*
    Description:    function to show the error message using ERR_print_errors(), which is a utility function that prints
                    the error strings for all errors that OpenSSL has recorded in bp, thus emptying the error queue.
*/
void handleErrors()
{
	ERR_print_errors_fp(stderr);
	abort();
}

/*
    Description:    function to show the error message and terminate the programme
    Parameters:     error message
*/
void error(const char *msg)
{
    perror(msg);
    exit(1);
}
// ------------------------------- end: function to manage error message -------------------------------

// ------------------------------- start: general function -------------------------------

/*
    Description:    
        function to get the file size of a specified file. use stati64 and fstati64 for to have the file size on 64 bit and be able to handle files larger than 2 GBi
    Parameters:     file name
    Return:         size of the file or -1 if occurs some error
*/
long long get_file_size(string file_name)
{
	struct stat64 stat_buf;
	
	if(stat64(file_name.c_str(), &stat_buf) != 0)
    {
        perror("Erro in get file size.\n");
        return -1;                  // return error
    }

    if (stat_buf.st_size > 0)
        return stat_buf.st_size;        // return the dimension of the file, all correct
    else
    {
        // size of the file negative, error
        cerr << "Error in the size of the file, is <= 0\n";
        return -1;                  // return error
    }
}
// ------------------------------- end: general function -------------------------------

// ------------------------------- start: function to canonicalization and command injection -------------------------------
/*
    Description: 
        function to check filenames (or strings in general) passed as parameters. The function will use canonicalisation and 
        white listing to check that the string passed conforms to the security rules.
    Parameters:     
        - str: the string to be checked
        - prefix_path: after canonicalizing the passed path you must verify that it is in the area where you want the client 
        			   or server to operate at that time. The passed string 'prefix_path' must be present in the real path 
        			   otherwise it will mean that the specified file is not in a correct area.
        - both_control: indicates if you want to do both checks or just the check on the white list .default parameter = true
    Return:
        - true: if the string passes the control checks, false: if the string dosn't pass the control checks
*/
bool check_file_name(const string& str, string prefix_path, bool both_control = true)
{
    // white list control
    // -- first control, check if the string is empty
    if(str.empty()) 
    {
        cerr << "Error the string entered is empty.\n";
        return false;       // return false
    }
    // -- second control, searches in str for the first character that does not match any of the characters specified in ok_chars
    if(str.find_first_not_of(ok_chars) != string::npos)     // if no such characters are found, the function returns string::npos.
    {
        cerr << "There are non-conforming characters in the entered string.\n";
        cerr << "The list of accepted characters is: " << ok_chars << ".\n";
        return false;
    }
    
    if (both_control)
    {
    	// canonicalization
		// realpath() fucntion -> expands all symbolic links and resolves references to /./, /../ and extra '/' characters
		char* canon_str = realpath(str.c_str(), NULL);      // get the real path 
		if(!canon_str)          // error
		{
			cerr << "Canonicalization failed.\n";
			return false; 
		} 
		
		// check that first directory is "/home" (in some systems this should be: "/home/<username>")
		if(strncmp(canon_str, "/home/", strlen("/home/")) != 0) 
		{
			cerr << "ERROR: Invalid path. The specified path isn't in /home/.\n"; 
		    free(canon_str); 
		    return false; 
		} 
		
		string can_str = canon_str;
		// check if prefix_path is in canon string. prefix_path will be 'ServerFiles/Dedicated_Storage/username' or 'ClientFiles/Dedicated_Storage/'
		if(can_str.find(prefix_path) == string::npos)     // if no such characters are found, the function returns string::npos.
		{
			cerr << "ERROR: Invalid path. The specified path isn't in the correct user folder.\n"; 
		    cout << "Prefix: " << prefix_path << "\n";
		    cout << "can_str: " << can_str << "\n";
		    free(canon_str); 
		    return false; 
		}
		
		cout << "can_str: " << can_str << "\n";
		
		free(canon_str); 
    }
    
    return true;
}

/*
    Description: 
        function to check filenames (or strings in general) passed as parameters. The function will use canonicalisation and 
        white listing to check that the string passed conforms to the security rules.
    Parameters:     
        - str: the string to be checked
        - prefix_path: after canonicalizing the passed path you must verify that it is in the area where you want the client 
        			   or server to operate at that time. The passed string 'prefix_path' must be present in the real path 
        			   otherwise it will mean that the specified file is not in a correct area.
    Return:
        - the canonicalizated string
*/
string get_can_str (const string& str, string prefix_path)
{
	string canon_ret;
	
	// canonicalization
	char* canon_str = realpath(str.c_str(), NULL);      // get the real path 
	if(!canon_str)          // error
	{
		cerr << "Canonicalization failed.\n";
		canon_ret = " ";
		return canon_ret;  
	} 
		
	// check that first directory is "/home" (in some systems this should be: "/home/<username>")
	if(strncmp(canon_str, "/home/", strlen("/home/")) != 0) 
	{
		cerr << "ERROR: Invalid path. The specified path isn't in /home/.\n"; 
		free(canon_str); 
	    canon_ret = " ";
		return canon_ret; 
	} 
		
	string can_str = canon_str;
	
	// check if prefix_path is in canon string. prefix_path will be 'ServerFiles/Dedicated_Storage/username' or 'ClientFiles/Dedicated_Storage/'
	size_t found = can_str.find(prefix_path);
	if(found == string::npos)     // if no such characters are found, the function returns string::npos.
	{
		cerr << "ERROR: Invalid path. The specified path isn't in the correct user folder.\n"; 
		free(canon_str); 
		canon_ret = " ";
		return canon_ret; 
	}

  	canon_ret = can_str.substr(found);		// ge the clear file name
	free(canon_str); 
	return canon_ret;
}

// ------------------------------- end: function to canonicalization and command injection -------------------------------

// ------------------------------- start: function to to manage server and client nonce -------------------------------
/*
    Description:    function that increments the counter passed as parameter by 1 (module maximum value for unsigned int)
    Parameters:     counter nonce to be updated
*/
void inc_counter_nonce(unsigned int &counter)
{
	if(counter == UINT_MAX)    // check if the maximum value is reached
		counter = 0;              // reset to 0
	else
		counter++;                // increment of 1
}
// ------------------------------- end: function to to manage server and client nonce -------------------------------

// ------------------------------- start: function to send and receive messages via sockets -------------------------------
/*
    Description: 
        function to send a message via a specified socket 
    Parameters:     
        - socket: socket
        - msg_size: size of the message to send
        - message: message to send
        - ov_size: indicates if the package is to contain 'oversize' files, in which case the controls on the maximum possible size 
                   must be different. By default the parameter is set to 0.
*/
void send_msg(int socket, long long msg_size, unsigned char* message, bool ov_size = false)
{
	int ret;
	
	// check for the size of the message to send
	if( !ov_size && ( msg_size > MAX_SIZE) )   // check with small mex
	{
    	cerr<<"Error in send: message too big, will not be sent.\n";
    	return;
    }
    if( ov_size && ( msg_size > MAX_SIZE_F_OS) )   // check with big mex
    {
        cerr<<"Error in send: message too big, will not be sent.\n";
    	return;
    }
    
	uint32_t size = htonl(msg_size);                   // translate in Network format
	ret = send(socket, &size, sizeof(uint32_t), 0);    // send the message
	if(ret < 0)
    	error("Error in message size send.\n");
	
	ret = send(socket, message, msg_size, 0);
	if(ret <= 0)
    	error("Error in message send.\n");
}

/*
    Description: 
        function to receive a message via a specified socket 
    Parameters:     
        - socket: socket
        - message: buffer for store the received message
        - ov_size: indicates if the package is to contain 'oversize' files, in which case the controls on the maximum possible size 
                   must be different. By default the parameter is set to 0.
    Return:
        - size of the received message
*/
long long receive_msg(int socket, unsigned char* message, bool ov_size = false)
{
	int ret;
	uint32_t networknumber;    // contain the size of the message to receive
	long long recieved = 0; // how much I received

	ret = recv(socket, &networknumber, sizeof(uint32_t), 0);
	if(ret < 0)
    	error("Error in socket receive.\n");
	if(ret > 0)                // successfully received the message size
	{
		unsigned int msg_size = ntohl(networknumber); // translate message size 
		if(!ov_size && ( msg_size > MAX_SIZE))       // check if the message is too big, with small mex
		{
    		cerr<<"Error in receive: message too big.\n"; 
    		return 0;                 // return 0
    	}	
    	if( ov_size && ( msg_size > MAX_SIZE_F_OS) )   // check with big mex
        {
            cerr<<"Error in receive: message too big, will not be sent.\n";
        	return 0;
        }
    	// retrieve all received message
		while(recieved < msg_size)
		{
			ret = recv(socket,  message+recieved, msg_size-recieved, 0);	
			if(ret < 0)
    			error("Error in receive_msg.\n");
			recieved += ret;         // update received
		}
		
    	return msg_size;           // return the size of the received message
	}
	return 0;                  // return 0
}
// ------------------------------- end: function to send and receive messages via sockets -------------------------------

// ------------------------------- start: function to sign and verify sign -------------------------------
/*
    Description: 
        function to sign using a private key passed as parameter   
    Parameters:     
        - priv_k: the private key to sign
        - clear_buf: buffer that contain the clear message (to be encrypted)
        - clear_size: size of the clear message
        - output_buffer: buffer that contain the signed message -> format -> ( sign_size | sign(clear_text) | clear_text )
    Return:
        - size of the encrypted message. 
*/
unsigned int digsign_sign(EVP_PKEY* priv_k, unsigned char* clear_buf, unsigned int clear_size, unsigned char* output_buffer)
{
	int ret;
	
	// check for the size of the message to sign
	if( clear_size > MSG_MAX)
    	error("Error in digsign_sign: message too big.\n");
	
	// create the signature context:
	EVP_MD_CTX* sign_ctx = EVP_MD_CTX_new();
	if(!sign_ctx)
    	error("Error in digsign_sign: EVP_MD_CTX_new returned NULL.\n");
	
	ret = EVP_SignInit(sign_ctx, sign_alg);        // initialisation
	if(ret == 0)
    	error("Error in digsign_sign: EVP_SignInit returned 0.\n");
	
	ret = EVP_SignUpdate(sign_ctx, clear_buf, clear_size);   // update
	if(ret == 0)
    	error("Error in digsign_sign: EVP_SignUpdate returned 0.\n");
	
	unsigned int sign_size;                    // size of the sign received from final
	unsigned char* signature_buffer = (unsigned char*)malloc(EVP_PKEY_size(priv_k)); //buffer to contain priv_key
	if(!signature_buffer)
    	error("Error in malloc signature buffer in digsign_sign.\n");
	
	ret = EVP_SignFinal(sign_ctx, signature_buffer, &sign_size, priv_k);   //final
	if(ret == 0)
    	error("Error in digsign_sign: EVP_SignFinal returned 0.\n");
	
	unsigned int written=0;                    // size of the message written in the output buffer
	memcpy(output_buffer,  (unsigned char *)&sign_size, sizeof(unsigned int)); // write in output buffer 
	written += sizeof(unsigned int);           // update size of the written message
	memcpy(output_buffer + written, signature_buffer, sign_size);      // write the sign in output buffer 
	written += sign_size;                      // update size of the written message
	memcpy(output_buffer + written, clear_buf, clear_size);            // write the clear message
	written += clear_size;                     // update size of the written message
	EVP_MD_CTX_free(sign_ctx);                 // free the context
	
	return written;            // return the size of the written message 
}

/*
    Description: 
        function to verify the sign using a pub_key passed as parameter     
    Parameters:     
        - pub_k: the public key for decrypt and verify the signature
        - input_buffer: buffer containing the sign to verify ( sign_size | sign | clear_text )
        - input_size: size of the input_buffer
        - output_buffer: buffer to the clear text
    Return:
        - an integer that can be: -1 -> if the signature is invalid; >0 -> if the signature is valid
*/
int digsign_verify(EVP_PKEY* pub_k, unsigned char* input_buffer, unsigned int input_size, unsigned char* output_buffer)
{
	int ret;
	unsigned int sgnt_size=*(unsigned int*)input_buffer;   // 
	unsigned int read = sizeof(unsigned int);              // take the position of the beginning of the signature in the buffer
	
	// check that the signature to be verified is properly formatted, it must consist
	// of an unsigned integer (indicating the size of the signature) and the signature.
	if(input_size <= (sizeof(unsigned int) + sgnt_size))
    	error("Error in digsign_verify: empty or invalid message.\n");
	
	unsigned char* signature_buffer = (unsigned char*)malloc(sgnt_size);   // buffer for the sign
	if(!signature_buffer)
    	error("Error in digsign_verify: malloc error.\n");
    
	memcpy(signature_buffer,input_buffer + read,sgnt_size);        // copy the sign in signature_buffer
	read += sgnt_size;                                             // update read
	memcpy(output_buffer,input_buffer + read,input_size - read);   // copy the clear text in output_buffer
	
	// create the signature context:
	EVP_MD_CTX* sign_ctx = EVP_MD_CTX_new();
	if(!sign_ctx)
    	error("Error in digsign_verify: EVP_MD_CTX_new returned NULL.\n");

	// verify the plaintext: (perform a single update on the whole plaintext, assuming that the plaintext is not huge)
	ret = EVP_VerifyInit(sign_ctx, sign_alg);                                  // initialisation
	if(ret == 0)
    	error("Error in digsign_verify: EVP_VerifyInit returned 0.\n");
	
	ret = EVP_VerifyUpdate(sign_ctx, input_buffer + read, input_size-read);    // update, pass the clear text
	if(ret == 0)
    	error("Error in digsign_verify: EVP_VerifyUpdate returned 0.\n");
	
	ret = EVP_VerifyFinal(sign_ctx, signature_buffer, sgnt_size, pub_k);       //final, pass the sign
	// ret is: 0 -> if invalid signature, -1 -> if some other error, 1 -> if success.
	if(ret == -1)
	{ 
    	cerr << "Error: EVP_VerifyFinal returned " << ret << " (invalid signature?)\n";
    	ERR_error_string_n(ERR_get_error(),(char *)output_buffer,MAX_SIZE);    
    	cerr<< output_buffer <<"\n";
    	exit(1);
	}
	else if(ret == 0)
	{      
    	cerr << "Error: Invalid signature!\n"; 
    	return -1;                                 //return -1
	}

	EVP_MD_CTX_free(sign_ctx);         // free context

	return input_size - read;          // return dimension of clear text, all is correct then is greater then 0
}
// ------------------------------- end: initial parameter control functions -------------------------------

// ------------------------------- start: functions for using the ECDH protocol for creating a shared secret key -------------------------------
/*
    Description:    function to create a Diffie-Hellman key pair  
    Return:         DH private key
*/
EVP_PKEY* dh_gen_key()
{
	EVP_PKEY *params = NULL;       // use default Diffie-Hellmann parameters

	EVP_PKEY_CTX* PDH_ctx;          // Create context for the key generation
	
	if(NULL == (PDH_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) // allocate context to ECDH
    	handleErrors();
	if(1 != (EVP_PKEY_paramgen_init(PDH_ctx)))                      // generate key parameters, return 1 for success, 0 or <0 for failure
    	handleErrors();
    //  sets the EC curve for EC parameter generation to nid. For EC parameter generation this macro must be called or an error occurs because there is no default curve. 
	if(1 != (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(PDH_ctx, NID_X9_62_prime256v1))) 
    	handleErrors();
	if(!EVP_PKEY_paramgen(PDH_ctx, &params)) 
    	handleErrors();
	EVP_PKEY_CTX_free(PDH_ctx);    // delete context
	
    // generate a new key
	EVP_PKEY_CTX* DH_ctx;          // create context for key generation
	if(NULL == (DH_ctx = EVP_PKEY_CTX_new(params, NULL))) 
    	handleErrors();
	EVP_PKEY* DH_key = NULL;       // create DH private key
	if(1 != EVP_PKEY_keygen_init(DH_ctx)) 
    	handleErrors();
	if(1 != EVP_PKEY_keygen(DH_ctx, &DH_key)) 
    	handleErrors();
	EVP_PKEY_CTX_free(DH_ctx);      // delete context
	
	EVP_PKEY_free(params);
	
	return DH_key;               // return DH key
} 

/*
    Description: 
        function to create the session key from the shared secret obtained via ECDH   
    Parameters:     
        - shared_secret: ECDH shared secret
        - shared_secret_len: size of the ECDH shared secret
        - sessionkey: output buffer to the session key
    Return:
        - unsigned int that rapresent the size of session key
*/
unsigned int dh_generate_session_key(unsigned char* shared_secret, unsigned int shared_secret_len, unsigned char* session_key)
{
	unsigned int session_key_len;      // contain the len of the key
	int ret;
	
	EVP_MD_CTX* hash_ctx;              // create context for hash
	hash_ctx = EVP_MD_CTX_new();       // context allocation
	if(!hash_ctx) 
    	error("Error in dh_generate_session_key: EVP_MD_CTX_new Error.\n");
	// Hashing (initialization + single update + finalization
	ret = EVP_DigestInit(hash_ctx, sign_alg);      // sign init
	if(ret != 1)
    	error("Error in dh_generate_session_key: EVP_DigestInit error.\n");
	ret = EVP_DigestUpdate(hash_ctx, shared_secret, shared_secret_len);     // sign update
	if(ret != 1)
    	error("Error in dh_generate_session_key: EVP_DigestUpdate Error.\n");
	ret = EVP_DigestFinal(hash_ctx, session_key, &session_key_len);          // sign final
	if(ret != 1)
    	error("Error in dh_generate_session_key: EVP_DigestFinal Error.\n");
	EVP_MD_CTX_free(hash_ctx);         // free context
	
	return session_key_len;            // return the len of the session key
}

// ------------------------------- end: functions for using the ECDH protocol for creating a shared secret key -------------------------------

// ------------------------------- start: functions for encryption and decryption with GCM with AES_128  -------------------------------
/*
    Description: 
        function for GCM encryption with AES_128
    Parameters:     
        - cmd_code: code to identify the operation between client and server  
        - aad: the rest of aad (in addition to cmd_code, it is usually the nonce that is counter to ensure the freshness of the message)
        - aad_len: the size of the aad
        - input_buffer: buffer thath contain the clear text to be encrypted
        - input_len: the size of the clear text in input
        - shared_key: the shared key for symmetric encryption (derived from ECDH between client and server)
        - output_buffer: buffer to contain the encrypted message in this format -> ( cmd_code | tag | IV | aad_len | aad | ciphertext)
        - ov_size: indicates if the package is to contain 'oversize' files, in which case the controls on the maximum possible size 
                   must be different. By default the parameter is set to 0.
        - file_name: pointer to the file to be encrypted, it will be necessary to read at each update cycle from the file to the maximum fragment size
    Return:
        - int that rapresent: the total length of the message (success) or '-1' if encryption has failed
*/
long long encryptor(short cmd_code, unsigned char* aad, unsigned int aad_len, unsigned char* input_buffer, long long input_len, unsigned char* shared_key, unsigned char *output_buffer, bool ov_size = false, FILE* file_name = 0)
{
	
	//FILE* file_name;
    int ret;
    unsigned int cmd_code_size = sizeof(short);     // take size of cmd_code
    
    // 1) dimension check
    // -- dimension check 1, checks if at least one of the two input buffers is larger than the maximum allowed size.
    // ---- for small file
    if ( !ov_size && (input_len > MAX_SIZE || aad_len > MAX_SIZE) )
    {
        cerr << "Error in GCM (AES_128) encryptor function: AAD or plaintext too big.\n";
        cerr << "AAD dimension is: " << aad_len << "B , plaintext dimension is: " << input_len << "B, max possible dimension is: " << MAX_SIZE << "B.\n";
        return -1;                  // failed return value
    }
    // ---- for large file
    if ( ov_size && (input_len > MAX_SIZE_F_OS || aad_len > MAX_SIZE_F_OS) )
    {
        cerr << "Error in GCM (AES_128) encryptor function: AAD or plaintext too big.\n";
        cerr << "AAD dimension is: " << aad_len << "B , plaintext dimension is: " << input_len << "B, max possible dimension is: " << MAX_SIZE_F_OS << "B.\n";
        return -1;                  // failed return value
    }
    // -- dimension check 2, checks if together the two input buffers are larger than the maximum space they can have available (maximum allowed size - the size of the other fields in the packet in the format of this application)
    // ---- for small file
    if( !ov_size && (input_len + aad_len > MAX_SIZE - AE_block_size - sizeof(unsigned int) - AE_iv_len - AE_tag_len - cmd_code_size) )
    {
        cerr << "Error in GCM (AES_128) encryptor function: AAD or plaintext too big.\n";
        return -1;                  // failed return value
    }
    // ---- for large file
    if( ov_size && (input_len + aad_len > MAX_SIZE_F_OS - AE_block_size - sizeof(unsigned int) - AE_iv_len - AE_tag_len - cmd_code_size) )
    {
        cerr << "Error in GCM (AES_128) encryptor function: AAD or plaintext too big.\n";
        return -1;                  // failed return value
    }
    
    // 2) encrypt
    // -- generate context, buffer and usefull variable
    EVP_CIPHER_CTX* ctx;               // create context for Authenticated Encryption
	int len = 0;
	long long ciphertext_len = 0;            // contain the size of the ciphertext
	
    // -- generate IV
    unsigned char *iv = (unsigned char *)malloc(AE_iv_len);     // allocate buffer to IV
    if(!iv) 
        error("Error in GCM (AES_128) encryptor: IV malloc error.\n");
    RAND_poll();                                                // seed random generator
	ret = RAND_bytes((unsigned char*)&iv[0], AE_iv_len);        // create random bytes for nonce
	
	unsigned char* tag = (unsigned char *)malloc(AE_tag_len);      // buffer to contain the TAG
	if(!tag) 
    	error("Error in GCM (AES_128) encryptor: TAG malloc error.\n");
	
	// -- buffer to contain the complete AAD = ( cmd_code | nounce )
	unsigned char* complete_aad=(unsigned char*)malloc(sizeof(short) + cmd_code_size); 
	if(!complete_aad) 
    	error("Error in GCM (AES_128) encryptor: AAD malloc error.\n");
	memcpy(complete_aad, &cmd_code, cmd_code_size);            // copy in complete_aad the cmd_code
	memcpy(complete_aad + cmd_code_size, aad, aad_len);        // copy in complete_aad the nonce
	
	// -- buffer for the ciphertext
	unsigned char* ciphertext;
	
	if ( (input_len + AE_block_size) <= FRAGMENT_SIZE )
    	ciphertext = (unsigned char *)malloc(input_len + AE_block_size);    // buffer to contain the ciphertext, maximum size is plaintext_size + block_size
	else
    	ciphertext = (unsigned char *)malloc(FRAGMENT_SIZE + AE_block_size);// buffer to contain the ciphertext, maximum size is plaintext_size + block_size
	if(!ciphertext) 
    	error("Error in GCM (AES_128) encryptor: ciphertext malloc error.\n");
	
    // -- Authenticated encryption
    if(!(ctx = EVP_CIPHER_CTX_new()))       // context allocation
        handleErrors();

	if(1 != EVP_EncryptInit(ctx, AE_cipher, shared_key, iv))   // Initialise the encryption operation.
    	handleErrors();
	
	// -- update: provide any AAD data. This can be called zero or more times as required
	if(1 != EVP_EncryptUpdate(ctx, NULL, &len, complete_aad, aad_len + cmd_code_size))
    	handleErrors();
    
    // -- start update cycles: one cycle if input size is less than FRAGMENT_SIZE, more cycles if input size is bigger than FRAGMENT_SIZE
    if ( (input_len + AE_block_size) <= FRAGMENT_SIZE )   // only one cicle
    {
        // -- update : provide the message to be encrypted, and obtain the ciphertext output.
    	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, input_buffer, input_len))
        	handleErrors();
    	ciphertext_len = len;          // update ciphertext len
    	
    	// -- final
    	if(1 != EVP_EncryptFinal(ctx, ciphertext + ciphertext_len, &len))  // finalize Encryption
        	handleErrors();
    	ciphertext_len += len;         // update ciphertext len
    }
    else        // more cicle
    {
        // -- set utilities
        // the offset to the beginning of the cipher text in the output buffer
        unsigned int msg_header = AE_tag_len + AE_iv_len + aad_len + sizeof(unsigned int) + cmd_code_size;   
        unsigned char* inbuf =(unsigned char*)malloc(FRAGMENT_SIZE);
     
        long inlen;              // how was read from the file in the current cycle
		
        // -- encrypt cycle
        for (;;) 
        {
            inlen = fread(inbuf, 1, FRAGMENT_SIZE, file_name);     // read from file max FRAGMENT_SIZE Bytes
            
            if (inlen <= 0)         // check if th end of the file
                break;
            
            if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, inbuf, inlen))     // encrypt update
                handleErrors();             // error
            
            // write encrypt part into output_buffer
            memcpy(output_buffer + msg_header + ciphertext_len, ciphertext, len);
            
            ciphertext_len += len;         // update ciphertext len
        }
        
        // -- final
        if (1 != EVP_EncryptFinal(ctx, output_buffer + len, &len))  
            handleErrors();                 // error
        ciphertext_len += len;         // update ciphertext len
    }
    
	// get the TAG and put it in tag buffer
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, AE_tag_len, tag))
    	handleErrors();
	
	// 3) write the packet with the ciphertext in the output_buffer
	long long written = 0;  // counter of written Byte
	
	// copy in the output_buffer, in the format -> ( cmd_code | tag | IV | nonce_len | nonce | ciphertext)
	// -- write cmd_code in output buffer
	memcpy(output_buffer, (unsigned char *)&cmd_code, cmd_code_size);      
	written += cmd_code_size;    
	// -- write the tag in output buffer
	memcpy(output_buffer + written, tag, AE_tag_len);
	written += AE_tag_len;                     // update written offset
	// -- write the IV in output buffer
	memcpy(output_buffer + written, iv, AE_iv_len);
	written += AE_iv_len;                      // update written offset
	// -- write the nonce_len in output buffer
	memcpy(output_buffer + written, (unsigned char *)&aad_len, sizeof(unsigned int));
	written += sizeof(unsigned int);           // update written offset
	// -- write the nonce in output buffer
	memcpy(output_buffer + written, aad, aad_len);
	written += aad_len;                      // update written offset
	
	// -- write the ciphertext in output buffer
	if(input_len <= FRAGMENT_SIZE)             // made a single encryption cycle, the encrypted message must be copied.
    	memcpy(output_buffer + written, ciphertext, ciphertext_len);
	written += ciphertext_len;                 // update written offset
	
	// free all 
	EVP_CIPHER_CTX_free(ctx);  // free context
	free(tag);                 // free TAG buffer
	free(iv);                  // free IV buffer
	free(ciphertext);          // free ciphertext buffer
	
	return written;            // return the dimension of the encrypted message in the specified format
}

/*
    Description: 
        function for GCM decryption with AES_128
    Parameters:     
        - input_buffer: buffer thath contain the ciphertext to be decrypted, in this format -> ( cmd_code | tag | IV | aad_len | aad | ciphertext)
        - input_len: the size of the clear text in input
        - shared_key: the shared key for symmetric encryption (derived from ECDH between client and server)
        - cmd_code: buffer in which to insert the received code (that identify the operation between client and server)  
        - output_aad: buffer in which to insert the received aad (in addition to cmd_code, it is usually the nonce that is counter to ensure the freshness of the message)
        - aad_len: the size of the output_aad
        - output_buffer: buffer to contain the decrypted message
        - ov_size: indicates if the package is to contain 'oversize' files, in which case the controls on the maximum possible size 
                   must be different. By default the parameter is set to 0.
        - file_name: pointer to the file, it will be necessary to write at each update cycle to the file (maximum fragment size)
    Return:
        - int that rapresent: the length of the output_buffer containing the decrypted message or '-1' if decryption has failed
*/
long long decryptor(unsigned char* input_buffer, long long input_len, unsigned char* shared_key, short &cmd_code, unsigned char* output_aad, unsigned int &aad_len, unsigned char* output_buffer, bool ov_size = false, FILE* file_name = 0)
{
    int ret;
    unsigned int cmd_code_size = sizeof(short);     // take size of cmd_code
    
    // 1) dimension check
    // -- dimension check 1, checks if input buffer is larger than the maximum allowed size.
    // ---- for small file
    if ( !ov_size && (input_len > MAX_SIZE) )
    {
        cerr << "Error in GCM (AES_128) decryptor function: packet too big.\n";
        cerr << "Packet dimension is: " << input_len << "B, max possible dimension is: " << MAX_SIZE << "B.\n";
        return -1;                  // failed return value
    }
    // ---- for large file
    if ( ov_size && (input_len > MAX_SIZE_F_OS) )
    {
        cerr << "Error in GCM (AES_128) decryptor function: packet too big.\n";
        cerr << "Packet dimension is: " << input_len << "B, max possible dimension is: " << MAX_SIZE_F_OS << "B.\n";
        return -1;                  // failed return value
    }
    // -- dimension check 2, checks if the message is smaller than the minimum size for a well formatted mex
    if(input_len <= AE_iv_len + AE_tag_len + cmd_code_size)
    {
        cerr << "Error in GCM (AES_128) decryptor function: malformed or empty message.\n";
        return -1;                  // failed return value
    }
    
    // 2) decrypt
    // -- generate context, buffer and usefull variable
    EVP_CIPHER_CTX *ctx;                // create context for Authenticated Decryption
	unsigned int read = 0;
	long long output_len = 0;
	int len;
	
	// -- generate IV
    unsigned char *iv = (unsigned char *)malloc(AE_iv_len);     // allocate buffer to IV
    if(!iv) 
        error("Error in GCM (AES_128) decryptor: IV malloc error.\n");
    unsigned char* tag = (unsigned char *)malloc(AE_tag_len);   // buffer to contain the TAG
	if(!tag) 
    	error("Error in GCM (AES_128) decryptor: TAG malloc error.\n");
    // read the Packet, the format is -> ( cmd_code | tag | IV | aad_len | aad | ciphertext)
    // -- read cmd_code received
    cmd_code =*(short*)(input_buffer);
	read += cmd_code_size;             // update read offset
    // -- read tag received
    memcpy(tag, input_buffer + read, AE_tag_len);
	read += AE_tag_len;                // update read offset
	// -- read IV received
	memcpy(iv, input_buffer + read, AE_iv_len);
	read += AE_iv_len;                 // update read offset
	// -- read aad_len received
	aad_len=*(unsigned int*)(input_buffer + read);
	read += sizeof(unsigned int);      // update read offset
	// dimension check 3
	if(input_len < read + aad_len) 
	{
    	cerr << "Error in GCM (AES_128) decryptor function: invalid aad_len.\n";
        return -1;                  // failed return value
	}
	// dimension check 4
	if(aad_len > MSG_MAX)
	{
        cerr << "Error in GCM (AES_128) decryptor function: aad too big.\n";
        return -1;                  // failed return value
    }
	// -- read aad received (usually the nonce)
	memcpy(output_aad, input_buffer + read, aad_len);
	read += aad_len;               // failed return value
	// -- read complete aad
	unsigned char* complete_aad=(unsigned char*)malloc(aad_len + cmd_code_size); // buffer to contain the complete AAD = ( cmd_code | nounce )
	if(!complete_aad) 
    	error("Error in GCM (AES_128) decryptor: AAD malloc error.\n");
	memcpy(complete_aad, &cmd_code,cmd_code_size);             // copy cmd_code
	memcpy(complete_aad + cmd_code_size, output_aad, aad_len); // copy aad

	// -- read ciphertext
	long long ciphertext_len = input_len - read;            // take ciphertext len
	// dimension check 5
	// -- small file
	if(!ov_size && (ciphertext_len > MSG_MAX))
	{
    	cerr << "Error in GCM (AES_128) decryptor function: ciphertext too big.\n";
        return -1; 
	}
	// -- big file
	if(ov_size && (input_len > MAX_SIZE_F_OS))
	{
    	cerr << "Error in GCM (AES_128) decryptor function: ciphertext too big.\n";
        return -1; 
	}
	
	// -- buffer for the ciphertext
	unsigned char* ciphertext;
	if ( input_len <= FRAGMENT_SIZE )      // small file
    	ciphertext = (unsigned char *)malloc(ciphertext_len);   // buffer to contain the ciphertext, maximum size is plaintext_size + block_size
	else                                   // big file
    	ciphertext = (unsigned char *)malloc(FRAGMENT_SIZE);    // buffer to contain the ciphertext, maximum size is plaintext_size + block_size
	if(!ciphertext)
    	error("Error in GCM (AES_128) decryptor: ciphertext Malloc Error.\n");
    
    if ( input_len <= FRAGMENT_SIZE )       // small file
    	memcpy(ciphertext, input_buffer + read, ciphertext_len);   // copy all ciphertext in the buffer, decryption in 1 cycle
	else                                    // big file
    	memcpy(ciphertext, input_buffer + read, FRAGMENT_SIZE);    // copy the fist FRAGMENT_SIZE Bytes of the ciphertext in the buffer, decryption in more cycle
	
	// -- Authenticated decryption
    if(!(ctx = EVP_CIPHER_CTX_new()))       // context allocation
        handleErrors();

	if(1 != EVP_DecryptInit(ctx, AE_cipher, shared_key, iv))   // Initialise the encryption operation.
    	handleErrors();
	
	//Provide any AAD data.
	if(1 != EVP_DecryptUpdate(ctx, NULL, &len, complete_aad, aad_len + cmd_code_size))
    	handleErrors();
    	
    // -- start update cycles: one cycle if input size is less than FRAGMENT_SIZE, more cycles if input size is bigger than FRAGMENT_SIZE
    if ( input_len <= FRAGMENT_SIZE )   // only one cicle
    {
        // -- update : provide the message to be decrypted, and obtain the plaintext output.
    	if(1 != EVP_DecryptUpdate(ctx, output_buffer, &len, ciphertext, ciphertext_len))
        	handleErrors();
    	output_len = len;              // update output_len len
    	
    	// Set expected tag value. Works in OpenSSL 1.0.1d and later
    	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, AE_tag_len, tag))
        	handleErrors();
    	
    	// Finalise the decryption. A positive return value indicates success, anything else is a failure - the plaintext is not trustworthy.
    	ret = EVP_DecryptFinal(ctx, output_buffer + output_len, &len);
    }
    else        // more cicle, does not write the decrypted fragments into a buffer in memory but directly into the file passed as a parameter.
    {
        // -- set utilities  
        unsigned char* out_buf = (unsigned char*)malloc(FRAGMENT_SIZE + AE_block_size);   // buffer to contain the fragment of cleartext
        long long to_read = ciphertext_len - FRAGMENT_SIZE;     // how many bytes are missing to complete the decryption
        long long curr_ciphert_len = FRAGMENT_SIZE;             // size of the current fragment to be decrypted

        // -- decrypt cycle
        for (;;) 
        {
            if (1 != EVP_DecryptUpdate(ctx, out_buf, &len, ciphertext, curr_ciphert_len))     // encrypt update
                handleErrors();             // error
            output_len += len;         // update ciphertext len
            
            // write decrypt part into file
            fwrite(out_buf, 1, len, file_name);
            
            if (to_read == 0)         // check if th end of the file
            {
                break;
            }
            // update to_read
            if (to_read >= FRAGMENT_SIZE)   // next cycle will not be the last
            {
                to_read -= FRAGMENT_SIZE;       // update
                memcpy(ciphertext, input_buffer + read + output_len, FRAGMENT_SIZE);    // copy for next cycle
            }
            else                            // next cycle will be the last
            {
                curr_ciphert_len = to_read;     // update current diphertext len
                memcpy(ciphertext, input_buffer + read + output_len, to_read);    // copy for next cycle
                to_read = 0;                     // set to 0 to_read
            }
        }
        
        // Set expected tag value. Works in OpenSSL 1.0.1d and later
    	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, AE_tag_len, tag))
        	handleErrors();
    	
    	// Finalise the decryption. A positive return value indicates success, anything else is a failure - the plaintext is not trustworthy.
    	ret = EVP_DecryptFinal(ctx, out_buf, &len);
    	// write decrypt part into file
        fwrite(out_buf, 1, len, file_name);
    }
    	
	// free all 
	EVP_CIPHER_CTX_free(ctx);  // free context
	free(tag);                 // free TAG buffer
	free(iv);                  // free IV buffer
	free(ciphertext);          // free ciphertext buffer
	
	// check if decryption was succesfull or not
	if(ret > 0)        // success
	{
    	output_len += len;         // update output_len len
    	return output_len;         // return output_len
	} 
	else               // verify failed
	{
    	cerr<<"Error in GCM (AES_128) decryptor: Verification failed!\n";
    	return -1;
	}
}
// ------------------------------- end: functions for encryption and decryption with GCM with AES_128  -------------------------------

/*
    NOTE 0:
        In the protocol thought most packets are small, the cipher text that is exchanged is always represented by a small string 
        (it may contain username, message to report an error, server questions for the user, etc.). For this reason, most messages 
        can be allocated in buffers of a standard size (200 KBi), and checks are made on the maximum size to prevent too large 
        transmission (which would be due to an application malfunction or a malicious thrust).
        The only case in which transmissions can be larger is during downloading and uploading files (which can be up to 4GBi in size).
    NOTE 1:
        In cases of downloading and uploading files larger than the maximum size of the standard packet, the maximum size of the 
        'oversize' packet (packet in which there is a large file) must be adopted. In this case, encryption and decryption cannot be 
        done on the entire file at once, as this would occupy a lot of memory. For this reason, a constant (FRAGMENT_SIZE) is defined 
        which sets the maximum size of a fragment for encryption and decryption; if the file exceeds this size, it will be divided 
        into fragments of this maximum size and passed to the encryption or decryption update each time. 
        Then the entire encrypted file will be sent in the packet.
    NOTE 2:
    	This value is at the discretion of the programmer or requirement. it is a value to save RAM by avoiding allocating too large buffers 
    	(for encrypting and decrypting at once) by going to allocate large buffers maximum this size (for encrypting and decrypting with 
     	multiple cycles and reading or writing directly from/to the file).
    	For devices with lots of RAM available it may not be a problem to allocate 2 buffers as large as the file to be transferred; 
    	therefore the fragment size can be put equal to the maximum file size.
    	In the project you have 4GBi file size limit, it is not a wise choice to want to take up twice as much RAM to encrypt and decrypt the file at once.
		Test files for transfer are also provided in this project. The two largest files are one of 39.6MBi and one of 79MBi. 
		In the program the fragment size is set 20MBi because this way various scenarios can be tested while staying within the limits of github 
		which does not allow files larger than 100MBi. With 20MBi as the fragment size, text files (which are small) will be encrypted and 
		decrypted in one cycle while larger .tar files will need multiple cycles of encryption and decryption (each will run a different number of cycles).
*/
