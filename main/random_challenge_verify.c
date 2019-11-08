/*
 * random_challenge_verify.c
 *
 *  VA IMPLEMENTATO SU ANDROID
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else


#include <stdio.h>
#include <stdlib.h>

#define mbedtls_snprintf        snprintf
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_MD_C) || \
    !defined(MBEDTLS_SHA256_C) || !defined(MBEDTLS_PK_PARSE_C) ||   \
    !defined(MBEDTLS_FS_IO)
int main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_MD_C and/or "
           "MBEDTLS_SHA256_C and/or MBEDTLS_PK_PARSE_C and/or "
           "MBEDTLS_FS_IO not defined.\n");
    return( 0 );
}
#else

#include "random_challenge_verify.h"
#include <stdio.h>
#include <string.h>
extern mbedtls_x509_crt slave_certificate;
extern char rand_challenge_str;
extern unsigned char rand_challenge_firmato[1024];

#if defined(MBEDTLS_CHECK_PARAMS)
#include "mbedtls/platform_util.h"
void mbedtls_param_failed( const char *failure_condition, const char *file, int line )
{
    mbedtls_printf( "%s:%i: Input param failed - %s\n", file, line, failure_condition );
    mbedtls_exit( MBEDTLS_EXIT_FAILURE );
}
#endif

int random_challenge_verify()
{
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_pk_context *pk=&slave_certificate.pk;
    unsigned char hash[32];
    //unsigned char buf[MBEDTLS_MPI_MAX_SIZE];

    //mbedtls_pk_init( &pk );

    //DEBUG
    int rett;
    unsigned char output_buf[4000];
    memset(output_buf, 0, 4000);
	if( ( rett = mbedtls_pk_write_pubkey_pem( pk, output_buf, 4000 ) ) != 0 )
		printf("\nPROBLEMONEE");
	printf("\n La chiave pubblica: %s",output_buf);
	// Print the signature
	printf("\n    . Il testo firmato: [%u]", (unsigned)rand_challenge_firmato);
    //DEBUG


    /*
     * Compute the SHA-256 hash of the input file and
     * verify the signature
     */
    mbedtls_printf( "\n    . Verifying the SHA-256 signature" );
    fflush( stdout );

    if( ( ret = mbedtls_md(mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ),(const unsigned char *)&rand_challenge_str, sizeof(rand_challenge_str), hash ) ) != 0 )
    {
    	mbedtls_printf( "\nfailed! Could not open or read %s\n\n", &rand_challenge_str);
        goto exit;
    }

    if( ( ret = mbedtls_pk_verify( pk, MBEDTLS_MD_SHA256, hash, 0, rand_challenge_firmato, 256 ) ) != 0 )
    {
        mbedtls_printf( "\nfailed! mbedtls_pk_verify returned -0x%04x\n", -ret );
        goto exit;
    }

    mbedtls_printf( "\n    . OK (the signature is valid)\n\n" );

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
    //mbedtls_pk_free( &pk );

#if defined(MBEDTLS_ERROR_C)
    if( exit_code != MBEDTLS_EXIT_SUCCESS )
    {
        //mbedtls_strerror( ret, (char *) buf, sizeof(buf) );
    	mbedtls_printf( "  !  Last error was: %u\n", (unsigned)rand_challenge_firmato );
    }
#endif

    return( exit_code );
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_SHA256_C &&
          MBEDTLS_PK_PARSE_C && MBEDTLS_FS_IO */
