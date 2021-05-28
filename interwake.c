// Client side C/C++ program to demonstrate Socket programming
#include <sys/socket.h>
#include <arpa/inet.h>
#include<netdb.h>	//hostent

#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "Hacl_SHA3.h"

#define NONCELENGTH 32
#define DIGEST_SIZE 64
#define KEY_LENGTH 512

int read_keyfile(unsigned char *keyBuffer){
	/*
	Reads the key from keyfile to the buffer provided.
	*/
	
	char *homeDir = getenv("HOME");
	const char *keyDirEnd = "/.config/interwakeKeyfile";
	char *keyDir = malloc(strlen(homeDir)+strlen(keyDirEnd)+1);
	strcpy(keyDir, homeDir);
	strcat(keyDir, keyDirEnd);
	
	int retval;

	FILE *keyHandle;
	keyHandle = fopen(keyDir, "rb");
	if(keyHandle == NULL){
		perror("fopen");
		fprintf(stderr, "Could not open keyfile at %s, does it exist?\n", keyDir);
		exit(EXIT_FAILURE);
	}

	retval = fread(keyBuffer, 1, KEY_LENGTH, keyHandle);
	if(retval<KEY_LENGTH){
		fprintf(stderr, "Keyfile too short. Exiting.\n");
		exit(EXIT_FAILURE);
	}

	retval = fclose(keyHandle);
	if(retval != 0){
		fprintf(stderr, "Error closing keyfile. Exiting. \n");
		exit(EXIT_FAILURE);
	}

	return 0;
}

int main(int argc, char const *argv[])
{

	if(argc<3)
	{
		fprintf(stderr, "Usage interwake address port\n");
		exit(EXIT_FAILURE);
	}

	const char *serverHostname = argv[1];
	unsigned short port;
	sscanf(argv[2], "%hu", &port);
		
	int sock, numBytes, retval;
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;		/* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; 	/* Stream socket */
	hints.ai_flags = 0;
	hints.ai_protocol = 0;				/* Any protocol */
	retval = getaddrinfo(argv[1], argv[2], &hints, &result);
	if (retval != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(retval));
		exit(EXIT_FAILURE);
	}
	
	// Connect to first working result
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sock == -1)
			continue;

		if (connect(sock, rp->ai_addr, rp->ai_addrlen) != -1)
			break;                  /* Success */

		close(sock);
	}
	
	freeaddrinfo(result);
	
	//Read the keyfile
	unsigned char key[KEY_LENGTH];
	read_keyfile(key);

	//allocate buffer for the nonce
	unsigned char nonceBuf[NONCELENGTH] = {'\0'};
	//read the nonce
	numBytes = read( sock , nonceBuf, NONCELENGTH);
	if(numBytes == -1){
		perror("read");
		exit(EXIT_FAILURE);
	}

	//print the nonce
	printf("Nonce: ");
	for(unsigned int i=0; i<NONCELENGTH; i++){
		printf("%02x", nonceBuf[i]);
	}
	printf("\n");

	//allocate preHash buffer and copy password and nonce into it
	unsigned char preHash[KEY_LENGTH+NONCELENGTH];
	memcpy(preHash, key, KEY_LENGTH);
	memcpy(preHash+KEY_LENGTH, nonceBuf, NONCELENGTH);

	unsigned char hash[DIGEST_SIZE];
	Hacl_SHA3_sha3_512(KEY_LENGTH+NONCELENGTH, preHash, hash);

	//print hash
	printf("hash: ");
	for (unsigned int i = 0; i < DIGEST_SIZE; i++){
		printf("%02x", hash[i]);
	}
	printf("\n");

	//sleep before sending hash
	sleep(1);

	//send the hash
	numBytes = send(sock , hash , DIGEST_SIZE , 0 );
	if(numBytes == -1){
		perror("send");
		exit(EXIT_FAILURE);
	}

	printf("%d bytes of hash sent\n", numBytes);

	char serverMessage[255] = {'\0'};
	numBytes = read(sock, serverMessage, 255);
	if(numBytes == -1){
		perror("send");
		exit(EXIT_FAILURE);
	}

	//force message to be null terminated
	serverMessage[254] = '\0';
	printf("Recieved from server: %s\n", serverMessage);

	close(sock);

	return 0;
}
