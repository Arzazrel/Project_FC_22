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
#include <iostream> 
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h> 

// ------------------------------- start: constant -------------------------------
#define USERNAME_SIZE 20        // maximum length for users' usernames
#define MAX_CLIENTS 20          // maximum number of clients connected to the server at the same time
#define MAX_SIZE 15000
#define MSG_MAX 10000
#define NONCE_SIZE 4            // size of the nonce
// ------------------------------- end: constant -------------------------------

using namespace std;

// ------------------------------- start: parmaeter and utility variables for encrypt and digital sign -------------------------------
const EVP_CIPHER* AE_cipher = EVP_aes_128_gcm();        // for ecnryption using AES with 128 bit 
int AE_iv_len =  EVP_CIPHER_iv_length(AE_cipher);       // size of the IV for encryption and decryption
int AE_block_size = EVP_CIPHER_block_size(AE_cipher);   // size of the block for encryption and decryption
const int AE_tag_len = 16;                              // size of the TAG
const EVP_MD* sign_alg = EVP_sha256();                  // indicates algorithm to sign (hash), in this case SHA 256

// ------------------------------- end: parmaeter and utility variables for encrypt and digital sign -------------------------------

// ------------------------------- start: function to manage error message -------------------------------
/*
    Description:    function to show the error message using ERR_print_errors(), which is a utility function that prints
                    the error strings for all errors that OpenSSL has recorded in bp, thus emptying the error queue.
*/
void handleErrors(void)
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

// ------------------------------- start: function to send and receive messages via sockets -------------------------------
/*
    Description: 
        function to send a message via a specified socket 
    Parameters:     
        - socket: socket
        - msg_size: size of the message to send
        - message: message to send
*/
void send_msg(int socket, unsigned int msg_size, unsigned char* message)
{
	int ret;
	
	// check for the size of the message to send
	if( msg_size > MAX_SIZE)
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
    Return:
        - size of the received message
*/
unsigned int receive_msg(int socket, unsigned char* message)
{
	int ret;
	uint32_t networknumber;    // contain the size of the message to receive
	unsigned int recieved = 0; // how much I received

	ret = recv(socket, &networknumber, sizeof(uint32_t), 0);
	if(ret < 0)
    	error("Error in socket receive.\n");
	if(ret > 0)                // successfully received the message size
	{
		unsigned int msg_size = ntohl(networknumber); // translate message size 
		if(msg_size > MAX_SIZE)       // check if the message is too big
		{
    		cerr<<"Error in receive: message too big.\n"; 
    		return 0;                 // return 0
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
	if(!ctx)
    	error("Error in digsign_sign: EVP_MD_CTX_new returned NULL.\n);
	
	ret = EVP_SignInit(sign_ctx, sign_alg);        // initialisation
	if(ret == 0)
    	error("Error in digsign_sign: EVP_SignInit returned 0.\n");
	
	ret = EVP_SignUpdate(sign_ctx, clear_buf, clear_size);   // update
	if(ret == 0)
    	error("Error in digsign_sign: EVP_SignUpdate returned 0.\n");
	
	unsigned int sign_size;                    // size of the sign received from final
	unsigned char* signature_buffer = (unsigned char*)malloc(EVP_PKEY_size(prvkey)); //buffer to contain priv_key
	if(!signature_buffer)
    	error("Error in malloc signature buffer in digsign_sign.\n");
	
	ret = EVP_SignFinal(sign_ctx, signature_buffer, &sgnt_size, prvkey);   //final
	if(ret == 0)
    	error("Error in digsign_sign: EVP_SignFinal returned 0.\n");
	
	unsigned int written=0;                    // size of the message written in the output buffer
	memcpy(output_buffer,  (unsigned char *)&sgnt_size, sizeof(unsigned int)); // write in output buffer 
	written += sizeof(unsigned int);           // update size of the written message
	memcpy(output_buffer + written, signature_buffer, sgnt_size);      // write the sign in output buffer 
	written += sgnt_size;                      // update size of the written message
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
	if(!md_ctx)
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
	if(1 != (EVP_PKEY_paramgen_init(PDHctx)))                      // generate key parameters, return 1 for success, 0 or <0 for failure
    	handleErrors();
    //  sets the EC curve for EC parameter generation to nid. For EC parameter generation this macro must be called or an error occurs because there is no default curve. 
	if(1!=(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(PDHctx, NID_X9_62_prime256v1))) 
    	handleErrors();
	if(!EVP_PKEY_paramgen(PDHctx, &params)) 
    	handleErrors();
	EVP_PKEY_CTX_free(PDHctx);     // delete context
	
    // generate a new key
	EVP_PKEY_CTX* DH_ctx;          // create context for key generation
	if(NULL == (DH_ctx = EVP_PKEY_CTX_new(params, NULL))) 
    	handleErrors();
	EVP_PKEY* DH_key = NULL;       // create DH private key
	if(1 != EVP_PKEY_keygen_init(DHctx)) 
    	handleErrors();
	if(1 != EVP_PKEY_keygen(DHctx, &my_dhkey)) 
    	handleErrors();
	EVP_PKEY_CTX_free(DHctx);      // delete context
	
	EVP_PKEY_free(params);
	
	return my_dhkey;               // return DH key
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
	
	return sessionkey_len;             // return the len of the session key
}

// ------------------------------- end: functions for using the ECDH protocol for creating a shared secret key -------------------------------

