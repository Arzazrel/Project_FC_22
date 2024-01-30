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
#define USERNAME_SIZE 20
#define MAX_CLIENTS 20
// ------------------------------- end: constant -------------------------------

using namespace std;
