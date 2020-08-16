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

#define TRUE   1
#define FALSE  0
#define PORT 42304
#define MAX_EVENTS 500

//TODO: fix all buffer overflow stuff, make sure all string are 0 terminated if they should be
#define BUFSIZE 1024

int main(){
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
    if(setsockopt(master_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt))){
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
    if( (bind(master_fd, (struct sockaddr *) &address, addrlen)) < 0){
        perror("listen");
        exit(EXIT_FAILURE);
    }

    //listen for connections, max pending 3
    if( (listen(master_fd, 3)) < 0){
        perror("listen");
        exit(EXIT_FAILURE);
    }

    struct epoll_event ep_ev;
    //notify when ready for input or when connection closes
    ep_ev.events = EPOLLIN | EPOLLRDHUP;
    ep_ev.data.fd = master_fd;
     //add master to epoll instance
    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, master_fd, &ep_ev) == -1){
        perror("epoll_ctl");
        exit(EXIT_FAILURE);
    }

    while(1){

        struct epoll_event ep_ret[MAX_EVENTS];
        int numEvents = epoll_wait(epoll_fd, ep_ret, MAX_EVENTS, -1);
        if(numEvents==-1){
            perror("epoll_wait");
            exit(EXIT_FAILURE);
        }
        printf("epoll returned file descriptor %d\n", ep_ret[0].data.fd);

        //loop through open files, taking actions
        for(int i=0; i<numEvents; i++){
            //if the master socket descriptor changed,
            if(ep_ret[i].data.fd == master_fd){
                //accept a client socket
                int new_socket;
                if( (new_socket = accept(master_fd, (struct sockaddr *) &address, &addrlen)) < 0){
                    perror("accept");
                    exit(EXIT_FAILURE);
                }

                printf("New connection , socket fd is %d , ip is : %s , port : %d\n", new_socket, inet_ntoa(address.sin_addr), ntohs(address.sin_port));

                //configure epoll struct
                ep_ev.data.fd = new_socket;
                //add the new socket to polling
                if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, new_socket, &ep_ev) == -1){
                    perror("epoll_ctl");
                    exit(EXIT_FAILURE);
                }

                //char buffer[1025] = {0};
                //read( new_socket , buffer, 1024);
                //printf("%s\n",buffer );
                char hello[] = "Hello from server!\n\0";

                if(send(new_socket, hello, strlen(hello), 0)==-1){
                    perror("send");
                    exit(EXIT_FAILURE);
                }
            }//if its not the master socket, then a client has progressed
            else{
                char buffer[BUFSIZE] = {'\0'};
                int numBytesRead = read(ep_ret[i].data.fd, buffer, BUFSIZE);
                if(numBytesRead == -1){
                    perror("read");
                    exit(EXIT_FAILURE);
                }
                printf("Message from client on socket %d: %s\n", ep_ret[i].data.fd, buffer);

                char hello[] = "I love you!\n\0";
                if(send(ep_ret[i].data.fd, hello, strlen(hello), 0)==-1){
                    perror("send");
                    exit(EXIT_FAILURE);
                }
            }
        }
    }
    return 0;
}
