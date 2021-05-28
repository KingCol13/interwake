//Example code: A simple server side code, which echos back the received message.
//Handle multiple socket connections with select and fd_set on Linux
#include <stdio.h>
#include <string.h>   //strlen
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>   //close
#include <arpa/inet.h>    //close
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/epoll.h>

#include <sodium.h>

#define TRUE   1
#define FALSE  0
#define PORT 42304
#define MAX_EVENTS 500

#define BROADCAST_ADDRESS "192.168.1.255"
#define BROADCAST_PORT 9

#define NONCELENGTH 32
#define DIGEST_SIZE 64
#define KEY_LENGTH 512

//TODO: double check all buffer overflow stuff, especially on sent/received stuff
const char macAddress[] = "2c:f0:5d:26:46:76";

struct ep_ev_data
{
    int fd;
    unsigned char *nonce;
};

int read_keyfile(const char *keyfile, unsigned char *keyBuffer)
{
	/*
	Reads the key from keyfile to the buffer provided.
	*/

	int retval;

	FILE *keyHandle;
	keyHandle = fopen(keyfile, "rb");
	if(keyHandle == NULL)
	{
		perror("fopen");
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
		perror("Error closing keyfile. Exiting. \n");
		exit(EXIT_FAILURE);
	}

	fprintf(stdout, "Read keyfile.\n");
	fflush(stdout);

	return 0;
}

void makeMagicPacket(unsigned char packet[])
{
    unsigned int imac[6];
    unsigned char mac[6];

    sscanf(macAddress,"%x:%x:%x:%x:%x:%x", &(imac[0]), &(imac[1]), &(imac[2]), &(imac[3]), &(imac[4]), &(imac[5]));
    	// 6 x 0xFF on start of packet
	for(unsigned int i = 0; i < 6; i++)
	{
		packet[i] = 0xFF;
		mac[i] = (unsigned char) imac[i];
	}
	// Rest of the packet is MAC address of the pc
	for(unsigned int i = 1; i <= 16; i++)
	{
		memcpy(&packet[i * 6], &mac, 6 * sizeof(unsigned char));
	}
}

void sendWOLPacket(){
    int opt = 1;
    int broadcastSocket = socket(PF_INET, SOCK_DGRAM, 0);
    if(broadcastSocket<0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "broadcast socket: %d\n", broadcastSocket);

    //set to reuse address
    if(setsockopt(broadcastSocket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) == -1)
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    //set to allow broadcasts
    if(setsockopt(broadcastSocket, SOL_SOCKET, SO_BROADCAST, (char *)&opt, sizeof(opt)) == -1)
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in broadcastAddr;
    memset(&broadcastAddr, 0, sizeof(broadcastAddr));   /* Zero out structure */
    broadcastAddr.sin_family = AF_INET;                 /* Internet address family */
    broadcastAddr.sin_addr.s_addr = inet_addr("192.168.1.255");//BROADCAST_ADDRESS);/* Broadcast IP address */
    broadcastAddr.sin_port = htons(BROADCAST_PORT);         /* Broadcast port */

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));   /* Zero out structure */
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = 0;

    if(bind(broadcastSocket, (struct sockaddr*) &serverAddr, sizeof(serverAddr)) == -1)
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    unsigned char packet[102];
    makeMagicPacket(packet);

    int bytesSent = sendto(broadcastSocket, packet, sizeof(unsigned char) * 102, 0, (struct sockaddr*) &broadcastAddr, sizeof(broadcastAddr));
    if(bytesSent == -1)
    {
        perror("sendto");
        exit(EXIT_FAILURE);
    }
    close(broadcastSocket);
}

void disconnectClient(int epoll_fd, struct epoll_event ep_ev)
{
    int clientSocket = ( (struct ep_ev_data *) ep_ev.data.ptr)->fd;
    unsigned char *nonce = ( (struct ep_ev_data *) ep_ev.data.ptr)->nonce;
    //remove socket from polling table
    if(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, clientSocket, NULL) == -1)
    {
        perror("epoll_ctl");
        exit(EXIT_FAILURE);
    }
    //close socket
    close(clientSocket);
    //free data in epoll event
    free(nonce);
    free(ep_ev.data.ptr);
    fprintf(stdout, "Disconnected client with socket file descriptor: %d.\n", clientSocket);
    fflush(stdout);
}

int main()
{
	
	if (sodium_init() == -1)
	{
		fprintf(stderr, "Libsodium failed to initialise, exiting.\n");
		exit(EXIT_FAILURE);
	}
	
	//read key from file
	unsigned char key[KEY_LENGTH];
	sodium_mlock(key, KEY_LENGTH);
	read_keyfile("mykey", key);

    int opt = 1;

    //create epoll instance
    int epoll_fd = epoll_create1(0);

    //create master socket
    int master_fd;
    if ((master_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0){
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    //set to receive multiple clients
    if(setsockopt(master_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    //setup master address details
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    unsigned int addrlen = sizeof(address);

    //bind socket to address struct
    if( (bind(master_fd, (struct sockaddr *) &address, addrlen)) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    //listen for connections, max pending 3
    if( (listen(master_fd, 3)) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    struct ep_ev_data serverData;
    serverData.fd = master_fd;
    serverData.nonce = NULL;

    struct epoll_event ep_ev;
    //notify when ready for input or when connection closes
    ep_ev.events = EPOLLIN | EPOLLRDHUP;
    ep_ev.data.ptr = &serverData;
     //add master to epoll instance
    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, master_fd, &ep_ev) == -1)
    {
        perror("epoll_ctl");
        exit(EXIT_FAILURE);
    }

    while(1)
    {

        struct epoll_event ep_ret[MAX_EVENTS];
        int numEvents = epoll_wait(epoll_fd, ep_ret, MAX_EVENTS, -1);
        if(numEvents==-1)
        {
            perror("epoll_wait");
            exit(EXIT_FAILURE);
        }

        //loop through open files, taking actions
        for(int i=0; i<numEvents; i++)
        {
            //extract the socket file descriptor of the event that was triggered
            int event_socket_fd = ((struct ep_ev_data *) ep_ret[i].data.ptr)->fd;
            fprintf(stdout, "\nepoll returned file descriptor %d\n", event_socket_fd);

            //if the master socket descriptor changed,
            if(event_socket_fd == master_fd)
            {
                //accept a client socket
                int new_socket;
                if( (new_socket = accept(master_fd, (struct sockaddr *) &address, &addrlen)) < 0)
                {
                    perror("accept");
                    exit(EXIT_FAILURE);
                }

                fprintf(stdout, "New connection , socket fd is %d , ip is : %s , port : %d\n", new_socket, inet_ntoa(address.sin_addr), ntohs(address.sin_port));

                //malloc and configure new client data
                struct ep_ev_data *new_data = malloc(sizeof(struct ep_ev_data));
                new_data->fd = new_socket;
                new_data->nonce = malloc(NONCELENGTH);
                //malloc and configure new epoll event
                ep_ev.data.ptr = new_data;

                //add the new socket to polling
                if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, new_socket, &ep_ev) == -1)
                {
                    perror("epoll_ctl");
                    exit(EXIT_FAILURE);
                }

                unsigned char *nonceBuf = new_data->nonce;
                randombytes_buf(nonceBuf, NONCELENGTH);

                fprintf(stdout, "Nonce: ");
                for(unsigned int i=0; i<NONCELENGTH; i++)
                {
                    fprintf(stdout, "%02x", nonceBuf[i]);
                }
                fprintf(stdout, "\n");

                fprintf(stdout, "Sending nonce\n");
                if(send(new_socket, nonceBuf, NONCELENGTH, 0)==-1)
                {
                    perror("send");
                    exit(EXIT_FAILURE);
                }
            }//if its not the master socket, then a client has progressed
            else{
                fprintf(stdout, "Non master socket event: %x\n", ep_ret[i].events);
                //if the connection is broken
                if(ep_ret[i].events & EPOLLRDHUP)
                {
                    disconnectClient(epoll_fd, ep_ret[i]);
                }
                //if there is data to be read and the socket wasn't closed
                else if(ep_ret[i].events & EPOLLIN)
                {
                    fprintf(stdout, "Input available event.\n");
                    //allocate buffer for receiving hash
                    unsigned char hashBuf[DIGEST_SIZE] = {'\0'};
                    //read hash from socket
                    int numBytesRead = read(event_socket_fd, hashBuf, DIGEST_SIZE);
                    if(numBytesRead == -1)
                    {
                        perror("read");
                        exit(EXIT_FAILURE);
                    }
                    fprintf(stdout, "Read %d bytes\n", numBytesRead);
                    //TODO: close connection if incorrect number of bytes received
                    if(numBytesRead < DIGEST_SIZE)
                    {
                        fprintf(stderr, "Insufficient digest size, closing connection.\n");
                        disconnectClient(epoll_fd, ep_ret[i]);
                    }
                    else
                    {   //correct number of hash bites sent

                        //print the received hash
                        fprintf(stdout, "Hash from client on socket %d: ", event_socket_fd);
                        for(unsigned int i=0; i<DIGEST_SIZE; i++)
                        {
                            fprintf(stdout, "%02x", hashBuf[i]);
                        }
                        fprintf(stdout, "\n");

                        unsigned char *nonceBuf = ((struct ep_ev_data *) ep_ret[i].data.ptr)->nonce;

                        unsigned char preHash[KEY_LENGTH+NONCELENGTH];
                        memcpy(preHash, key, KEY_LENGTH);
                        memcpy(preHash+KEY_LENGTH, nonceBuf, NONCELENGTH);

                        unsigned char serverHash[DIGEST_SIZE];
                        crypto_generichash(serverHash, sizeof serverHash, preHash, sizeof preHash, NULL, 0);

                        //print hash
                        fprintf(stdout, "server hash: ");
                        for (unsigned int i = 0; i < DIGEST_SIZE; i++)
                        {
                            fprintf(stdout, "%02x", serverHash[i]);
                        }
                        fprintf(stdout, "\n");

                        //compare our hash to hash from client
                        int auth_val = memcmp(serverHash, hashBuf, DIGEST_SIZE);

                        if(auth_val==0){ //authentication succesful
                            fprintf(stdout, "Authentication successful. Sending wake packet.\n");
                            sendWOLPacket();
                            char msgSuccess[] = "Success.\n";
                            if(send(event_socket_fd, msgSuccess, strlen(msgSuccess), 0)==-1)
                            {
                                perror("send");
                                exit(EXIT_FAILURE);
                            }
                            disconnectClient(epoll_fd, ep_ret[i]);
                        }
                        else
                        { //authentication unsuccessful
                            fprintf(stdout, "Authentication unsuccessful. Closing connection.\n");
                            char msgFailure[] = "Failure.\n";
                            if(send(event_socket_fd, msgFailure, strlen(msgFailure), 0)==-1)
                            {
                                perror("send");
                                exit(EXIT_FAILURE);
                            }
                            disconnectClient(epoll_fd, ep_ret[i]);
                        } //authentication unsuccessful
                    } //correct number of hash bites sent
                } //data to read event
            } //not the master socket
            fflush(stdout);
        } //loop through epoll events
    } //main while loop
    return 0;
}
