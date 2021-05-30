// Client side C/C++ program to demonstrate Socket programming
#include <sys/socket.h>
#include <arpa/inet.h>
#include<netdb.h>	//hostent

#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <sodium.h>

#define DIGEST_SIZE 64
#define KEY_LENGTH 512

int readKeyfile(unsigned char *keyBuffer)
{
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
	if(keyHandle == NULL)
	{
		perror("fopen");
		fprintf(stderr, "Could not open keyfile at %s, does it exist?\n", keyDir);
		exit(EXIT_FAILURE);
	}

	retval = fread(keyBuffer, 1, KEY_LENGTH, keyHandle);
	if(retval<KEY_LENGTH)
	{
		fprintf(stderr, "Keyfile too short. Exiting.\n");
		exit(EXIT_FAILURE);
	}

	retval = fclose(keyHandle);
	if(retval != 0)
	{
		fprintf(stderr, "Error closing keyfile. Exiting. \n");
		exit(EXIT_FAILURE);
	}

	return 0;
}

int main(int argc, char const *argv[])
{
	
	if (sodium_init() == -1)
	{
		fprintf(stderr, "Libsodium failed to initialise, exiting.\n");
		exit(EXIT_FAILURE);
	}
	
	if(argc<3)
	{
		fprintf(stderr, "Usage interwake address port\n");
		exit(EXIT_FAILURE);
	}

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
	if (retval != 0)
	{
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(retval));
		exit(EXIT_FAILURE);
	}
	
	// Connect to first working result
	for (rp = result; rp != NULL; rp = rp->ai_next)
	{
		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sock == -1)
			continue;

		if (connect(sock, rp->ai_addr, rp->ai_addrlen) != -1)
			break;		/* Success */

		close(sock);
	}
	
	freeaddrinfo(result);
	
	//Read the keyfile
	unsigned char key[KEY_LENGTH];
	readKeyfile(key);
	sodium_mlock(key, KEY_LENGTH);
	
	// Allocate room for keys and generate client keys
	unsigned char serverPK[crypto_kx_PUBLICKEYBYTES] = {'\0'};
	unsigned char clientPK[crypto_kx_PUBLICKEYBYTES];
	unsigned char clientSK[crypto_kx_SECRETKEYBYTES];
	unsigned char clientTX[crypto_kx_SESSIONKEYBYTES];
	crypto_kx_keypair(clientPK, clientSK);
	
	//read the server public key
	numBytes = read( sock , serverPK, crypto_kx_PUBLICKEYBYTES);
	if(numBytes == -1)
	{
		perror("read");
		exit(EXIT_FAILURE);
	}

	// print the server public key
	printf("Server public key: ");
	for(unsigned int i=0; i<crypto_kx_PUBLICKEYBYTES; i++)
	{
		printf("%02x", serverPK[i]);
	}
	printf("\n");
	
	if (crypto_kx_client_session_keys(NULL, clientTX, clientPK, clientSK, serverPK) != 0)
	{
		fprintf(stderr, "Suspicious server key, exiting.\n");
		exit(EXIT_FAILURE);
	}
	
	//allocate preHash buffer and copy derived key and auth key into it
	unsigned char preHash[crypto_kx_SESSIONKEYBYTES+KEY_LENGTH];
	memcpy(preHash, clientTX, crypto_kx_SESSIONKEYBYTES);
	memcpy(preHash+crypto_kx_SESSIONKEYBYTES, key, KEY_LENGTH);

	unsigned char hash[DIGEST_SIZE];
	crypto_generichash(hash, sizeof hash, preHash, sizeof preHash, NULL, 0);

	//print hash
	printf("hash: ");
	for (unsigned int i = 0; i < DIGEST_SIZE; i++)
	{
		printf("%02x", hash[i]);
	}
	printf("\n");

	//sleep before sending hash
	sleep(1);

	//send the client public key and hash
	unsigned char clientSend[crypto_kx_PUBLICKEYBYTES+DIGEST_SIZE];
	memcpy(clientSend, clientPK, crypto_kx_PUBLICKEYBYTES);
	memcpy(clientSend+crypto_kx_PUBLICKEYBYTES, hash, DIGEST_SIZE);
	numBytes = send(sock, clientSend, crypto_kx_PUBLICKEYBYTES+DIGEST_SIZE, 0);
	if(numBytes == -1)
	{
		perror("send");
		exit(EXIT_FAILURE);
	}

	printf("%d bytes of hash sent\n", numBytes);

	char serverMessage[255] = {'\0'};
	numBytes = read(sock, serverMessage, 255);
	if(numBytes == -1)
	{
		perror("send");
		exit(EXIT_FAILURE);
	}

	//force message to be null terminated
	serverMessage[254] = '\0';
	printf("Recieved from server: %s\n", serverMessage);

	close(sock);

	return 0;
}
