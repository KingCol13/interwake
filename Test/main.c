#include<stdio.h> //printf
#include<gcrypt.h>

void reverse_buffer(char *buffer, int size){
    char *temp = malloc(size);

    for(unsigned int i=0; i<size; i++){
        temp[i] = buffer[size-i-1];
    }

    memcpy(buffer, temp, size);

    free(temp);
}

void checkECC(){
    gcry_sexp_t sexp_genkey_params;
    gcry_mpi_t mpi_Curve_pub = gcry_mpi_new( 0 );
    gcry_mpi_t mpi_Curve_priv;

    gcry_sexp_build( &sexp_genkey_params, NULL,
                     "(genkey"
                     "    (ecc"
                     "        (curve \"Curve25519\")"
                     "        (flags djb-tweak comp)"
                     "    )"
                     ")" );

    gcry_sexp_t sexp_Curve25519_pair_server;
    gcry_sexp_t sexp_Curve25519_pair_client;
    gcry_pk_genkey( &sexp_Curve25519_pair_server, sexp_genkey_params );
    gcry_pk_genkey( &sexp_Curve25519_pair_client, sexp_genkey_params );

    // the public key is a point stored compressed (determined by the 0x40 prefix)
    // in an mpi and it will need to be decompressed
    gcry_mpi_t mpi_Curve_pub_compressed;
    gcry_sexp_extract_param( sexp_Curve25519_pair_server, NULL, "qd",
                             &mpi_Curve_pub_compressed, &mpi_Curve_priv, NULL );

    // to decompress, we decode it into a point
    // then extract the X and discard the rest
    gcry_mpi_point_t point_Curve_pub = gcry_mpi_point_new( 0 );
    gcry_ctx_t ctx_curve;
    gcry_mpi_ec_new( &ctx_curve, NULL, "Curve25519" );
    gcry_mpi_ec_decode_point( point_Curve_pub, mpi_Curve_pub_compressed, ctx_curve );

    // we extract x, y and z but only need x because
    // curve only uses the x coordinate. y and z are discarded.
    gcry_mpi_t mpi_Curve_pub_y = gcry_mpi_new( 0 );
    gcry_mpi_t mpi_Curve_pub_z = gcry_mpi_new( 0 );

    gcry_mpi_point_snatch_get( mpi_Curve_pub, mpi_Curve_pub_y, mpi_Curve_pub_z, point_Curve_pub );

    gcry_sexp_release( sexp_genkey_params );
    gcry_sexp_release( sexp_Curve25519_pair_server );
    gcry_mpi_release( mpi_Curve_pub_y );
    gcry_mpi_release( mpi_Curve_pub_z );
    gcry_mpi_release( mpi_Curve_pub_compressed );

    u_int8_t p_bytes_Curve[32];

    int error = gcry_mpi_print( GCRYMPI_FMT_USG, p_bytes_Curve, 32, NULL, mpi_Curve_pub );
    // Curve25519 is little-endian
    reverse_buffer( p_bytes_Curve, 32 );

    printf("p_bytes_Curve: ");
    for(unsigned int i=0; i<32; i++){
        printf("%02x", p_bytes_Curve[i]);
    }
    printf("\n");

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
