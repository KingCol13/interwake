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

#endif //HASH_H
