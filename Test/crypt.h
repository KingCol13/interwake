#ifndef HASH_H
#define HASH_H

#include <stdio.h>
#include <gcrypt.h>

void hashTest(){
    char *s = "some text";
    unsigned char *x;
    unsigned i;
    unsigned int l = gcry_md_get_algo_dlen(GCRY_MD_SHA3_256); /* get digest length (used later to print the result) */

    gcry_md_hd_t h;
    gcry_md_open(&h, GCRY_MD_SHA3_256, GCRY_MD_FLAG_SECURE); /* initialise the hash context */
    gcry_md_write(h, s, strlen(s)); /* hash some text */
    x = gcry_md_read(h, GCRY_MD_SHA3_256); /* get the result */

    printf("Digest length: %d\n", l);
    printf("hash: ");

    for (i = 0; i < l; i++){
        printf("%02x", x[i]); /* print the result */
    }
    printf("\n");
}

void nonceTest(){
    unsigned int nonceLength = 32;
    unsigned char nonceBuffer[nonceLength];
    gcry_create_nonce(nonceBuffer, nonceLength);
    printf("Nonce: ");
    for (unsigned int i = 0; i < nonceLength; i++){
        printf("%02x", nonceBuffer[i]); /* print the result */
    }
    printf("\n");
}

#endif //HASH_H
