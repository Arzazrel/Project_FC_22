DESCRIPTION
	Folder of the Client-Server application that resembles a Cloud Storage built in C++ (using OpenSSL) for the Foundations of Cybersecurity project at the University of Pisa.
	This application, created for university purposes (realised during a Master's degree in AIDE), is focused on cybersecurity. 
	For this reason, some aspects will not be complete or will be simplified compared to a real commercial cloud storage.
	In this application: each user has a “dedicated storage” on the server, and any user cannot access the “dedicated storage” of any other user. 
	Users can Upload, Download, Rename, or Delete data to/from the Cloud Storage in a safe manner.

The folder contains:
	This cpp files:
	- Server.cpp: contains the code relating to the server; 
    	- Client.cpp: contains the code relating to the client;
    	- Common.h: contains variables and functions useful for both the server and the client.
	
	This document:
	- Password.txt: The passwords for the private keys of the server and the three pre-registered users are stored in this file. 
 			The passwords are required to initiate the authenticated and secure connection between the client and the server.
	- FoC_Documentation.pdf: the documentation of the project that explain protocol, the format of the packets and so on...

	This folder:
	- ClientFiles: containing all files (keys, certificates, files) concerning the client;
    	- ServerFiles: containing all files (keys, certificates, saved user files) concerning the server;
    	- test files: a folder containing the files provided for testing the application. there are small .txt files and two larger .tar files. 
		      These files can be copied to the individual users' folders and then used to test the application.

Commands used to compile and run:
	- to compile (The project folder also contains the two executables of the server and client compiled with these commands)
		-- with debug
		g++ server.cpp -lssl -lcrypto -pthread -g -o server
		g++ client.cpp -lssl -lcrypto -g -o client
		-- without debug
		g++ server.cpp -lssl -lcrypto -pthread -o server
		g++ client.cpp -lssl -lcrypto -o client

	- run (with example arguments)
		./server 5000
		./client 127.0.0.1 5000 UserA

Developer's notes:
	The work related to the university examination is finished and the project is completed. 
	There may be updates or improvements to the project in the future, but nothing is planned for now.

Developers:
	- Alessandro Diana