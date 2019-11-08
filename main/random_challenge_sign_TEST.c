/*
 * random_challenge_sign_TEST.c
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

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_ENTROPY_C) ||  \
    !defined(MBEDTLS_SHA256_C) || !defined(MBEDTLS_MD_C) || \
    !defined(MBEDTLS_PK_PARSE_C) || !defined(MBEDTLS_FS_IO) ||    \
    !defined(MBEDTLS_CTR_DRBG_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_ENTROPY_C and/or "
           "MBEDTLS_SHA256_C and/or MBEDTLS_MD_C and/or "
           "MBEDTLS_PK_PARSE_C and/or MBEDTLS_FS_IO and/or "
           "MBEDTLS_CTR_DRBG_C not defined.\n");
    return( 0 );
}
#else


#include "random_challenge_sign_TEST.h"
#include <stdio.h>
#include <string.h>

extern mbedtls_pk_context slave_priv_key;
extern char rand_challenge_str;
extern unsigned char rand_challenge_firmato[1024];

#if defined(MBEDTLS_CHECK_PARAMS)
#include "mbedtls/platform_util.h"
void mbedtls_param_failed( const char *failure_condition,
                           const char *file,
                           int line )
{
    mbedtls_printf( "%s:%i: Input param failed - %s\n",
                    file, line, failure_condition );
    mbedtls_exit( MBEDTLS_EXIT_FAILURE );
}
#endif

int random_challenge_sign()
{
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_pk_context *pk=&slave_priv_key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char hash[32];
    //unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    const char *pers = "mbedtls_pk_sign";
    size_t olen = 0;
    memset(hash, 0, 32);
    memset(rand_challenge_firmato, 0, 1024);
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    //mbedtls_pk_init( &pk );

    mbedtls_printf( "\n    . Seeding the random number generator..." );
    fflush( stdout );

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret );
        goto exit;
    }

    /*
     * Compute the SHA-256 hash of the input file,
     * then calculate the signature of the hash.
     */
    mbedtls_printf( "\n    . Generating the SHA-256 signature" );
    printf( "\n    . Using the string: [%s]", &rand_challenge_str);
    fflush( stdout );

    if( ( ret = mbedtls_md(mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ),(const unsigned char *)&rand_challenge_str, sizeof(rand_challenge_str), hash ) ) != 0 )
    {
        mbedtls_printf( "\nfailed! Could not open or read %s\n\n", &rand_challenge_str);
        goto exit;
    }
    printf("\n    . l'hash vale: [%u]", (unsigned)hash);

    if( ( ret = mbedtls_pk_sign( pk, MBEDTLS_MD_SHA256, (const unsigned char *)hash, 0,
    		rand_challenge_firmato, &olen, mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        mbedtls_printf( "\nfailed! mbedtls_pk_sign returned -0x%04x\n", -ret );
        goto exit;
    }

    // Print the signature
    printf("\n    . lunghezza testo firmato: [%d]", olen);
    printf("\n    . Il testo firmato: [%u]", (unsigned)rand_challenge_firmato);


    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
    //mbedtls_pk_free( &pk );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

#if defined(MBEDTLS_ERROR_C)
    if( exit_code != MBEDTLS_EXIT_SUCCESS )
    {
        //mbedtls_strerror( ret, (unsigned char *) rand_challenge_firmato, sizeof(rand_challenge_firmato) );
        mbedtls_printf( "  !  Last error was: %u\n", (unsigned)rand_challenge_firmato );
    }
#endif


    return( exit_code );
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C &&
          MBEDTLS_SHA256_C && MBEDTLS_PK_PARSE_C && MBEDTLS_FS_IO &&
          MBEDTLS_CTR_DRBG_C */
