#include<stdio.h> //printf
#include<gcrypt.h>

//HACL libraries, compile with KRML_VERIFIED_UINT128 define
#include "hacl/Hacl_SHA3.h"
#include "hacl/Hacl_Curve25519_51.h"
#include "hacl/Lib_RandomBuffer_System.h"

void reverse_buffer(char *buffer, int size){
    char *temp = malloc(size);

    for(unsigned int i=0; i<size; i++){
        temp[i] = buffer[size-i-1];
    }

    memcpy(buffer, temp, size);

    free(temp);
}

void hashTest(){
    const unsigned char input[] = "Hello";

    unsigned char output[32] = {0};

    Hacl_SHA3_sha3_256(5, input, output);

    printf("Output hash of %s:\n", input);
    for(unsigned int i=0; i<32; i++){
        printf("%02x", output[i]);
    }
    printf("\n");

}

void ECDHTest(){

    u_int8_t clientSecret[32];
    u_int8_t serverSecret[32];

    //fill secrets with random bytes
    Lib_RandomBuffer_System_randombytes(clientSecret, 32);
    Lib_RandomBuffer_System_randombytes(serverSecret, 32);

    printf("Server secret: ");
    for(unsigned int i=0; i<32; i++){
        printf("%02x", clientSecret[i]);
    }
    printf("\nClient secret: ");
    for(unsigned int i=0; i<32; i++){
        printf("%02x", serverSecret[i]);
    }

    u_int8_t clientPub[32];
    u_int8_t serverPub[32];

    //get public keys using secrets
    Hacl_Curve25519_51_secret_to_public(clientPub, clientSecret);
    Hacl_Curve25519_51_secret_to_public(serverPub, serverSecret);

    printf("\n\nServer public: ");
    for(unsigned int i=0; i<32; i++){
        printf("%02x", serverPub[i]);
    }
    printf("\nClient public: ");
    for(unsigned int i=0; i<32; i++){
        printf("%02x", clientPub[i]);
    }

    u_int8_t clientShared[32];
    u_int8_t serverShared[32];

    //derive shared key from other's public key, and own secret
    Hacl_Curve25519_51_ecdh(clientShared, clientSecret, serverPub);
    Hacl_Curve25519_51_ecdh(serverShared, serverSecret, clientPub);

    printf("\n\nClient shared: ");
    for(unsigned int i=0; i<32; i++){
        printf("%02x", clientShared[i]);
    }
    printf("\nServer shared: ");
    for(unsigned int i=0; i<32; i++){
        printf("%02x", serverShared[i]);
    }
}

int main(){

    ECDHTest();

    return 0;
}
