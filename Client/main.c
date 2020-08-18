// Client side C/C++ program to demonstrate Socket programming
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <gcrypt.h>

#define PORT 42304
#define NONCELENGTH 32
#define DIGEST_SIZE 32

const unsigned char password[] = "TestingPassword12345";

int main(int argc, char const *argv[]){
    int sock = 0, numBytes;
    struct sockaddr_in serv_addr;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0)
    {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\nConnection Failed \n");
        return -1;
    }

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
    unsigned char preHash[sizeof(password)+NONCELENGTH];
    memcpy(preHash, password, sizeof(password));
    memcpy(preHash+sizeof(password), nonceBuf, NONCELENGTH);

    gcry_md_hd_t hash_context;
    //initialise hash context
    gcry_md_open(&hash_context, GCRY_MD_SHA3_256, GCRY_MD_FLAG_SECURE);
    //hash the preHash concatenation
    gcry_md_write(hash_context, preHash, sizeof(password)+NONCELENGTH);
    //get the result of hashing
    unsigned char *hash = gcry_md_read(hash_context, GCRY_MD_SHA3_256);

    //print hash
    printf("hash: ");
    for (unsigned int i = 0; i < DIGEST_SIZE; i++){
        printf("%02x", hash[i]);
    }
    printf("\n");

    //send the hash
    numBytes = send(sock , hash , DIGEST_SIZE , 0 );
    if(numBytes == -1){
        perror("send");
        exit(EXIT_FAILURE);
    }
    printf("Hello message sent\n");

    return 0;
}
