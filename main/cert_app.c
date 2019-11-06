/*
 * cert_app.c
 *
 *  Certificate reading application
 *
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
#define mbedtls_time            time
#define mbedtls_time_t          time_t
#define mbedtls_fprintf         fprintf
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_ENTROPY_C) ||  \
    !defined(MBEDTLS_SSL_TLS_C) || !defined(MBEDTLS_SSL_CLI_C) || \
     !defined(MBEDTLS_RSA_C) ||         \
    !defined(MBEDTLS_X509_CRT_PARSE_C) || !defined(MBEDTLS_FS_IO) ||  \
    !defined(MBEDTLS_CTR_DRBG_C)
void main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_ENTROPY_C and/or "
           "MBEDTLS_SSL_TLS_C and/or MBEDTLS_SSL_CLI_C and/or "
           "MBEDTLS_NET_C and/or MBEDTLS_RSA_C and/or "
           "MBEDTLS_X509_CRT_PARSE_C and/or MBEDTLS_FS_IO and/or "
           "MBEDTLS_CTR_DRBG_C not defined.\n");
    printf("EXIT CERT APP: 00");
    //wait_cert_app=false;
    //vTaskDelete(NULL);
}
#else

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "nvs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cert_app.h"
bool wait_cert_app;

 //prototipi statici
static void my_debug( void *ctx, int level, const char *file, int line, const char *str );
static int my_verify( void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags );


#define MODE_NONE               0
#define MODE_FILE               1
#define MODE_SSL                2

#define DFL_MODE                MODE_NONE
#define DFL_FILENAME            "cert.crt"
#define DFL_CA_FILE             ""
#define DFL_CRL_FILE            ""
#define DFL_CA_PATH             ""
#define DFL_SERVER_NAME         "localhost"
#define DFL_SERVER_PORT         "4433"
#define DFL_DEBUG_LEVEL         0
#define DFL_PERMISSIVE          0

//ca_file: The single file containing the top-level CA(s) you fully trust
//crl_file: The single CRL file you want to use

/*
 * global options
 */
struct options4
{
    int mode;                   /* the mode to run the application in   */
    const char *filename;       /* filename of the certificate file     */
    const char *ca_file;        /* the file with the CA certificate(s)  */
    const char *crl_file;       /* the file with the CRL to use         */
    const char *ca_path;        /* the path with the CA certificate(s) reside */
    const char *server_name;    /* hostname of the server (client only) */
    const char *server_port;    /* port on which the ssl service runs   */
    int debug_level;            /* level of debugging                   */
    int permissive;             /* permissive parsing                   */
} optt4;

static void my_debug( void *ctx, int level, const char *file, int line, const char *str )
{
    ((void) level);

    mbedtls_fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}

static int my_verify( void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags )
{
    char buf[1024];
    ((void) data);

    mbedtls_printf( "\nVerify requested for (Depth %d):\n", depth );
    mbedtls_x509_crt_info( buf, sizeof( buf ) - 1, "", crt );
    mbedtls_printf( "%s", buf );

    if ( ( *flags ) == 0 )
        mbedtls_printf( "  This certificate has no flags\n" );
    else
    {
        mbedtls_x509_crt_verify_info( buf, sizeof( buf ), "  ! ", *flags );
        mbedtls_printf( "%s\n", buf );
    }

    return( 0 );
}

void cert_app( void *param )
{
	(void)param;
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_net_context server_fd;
    unsigned char buf[1024];
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert=&self_certificate;
    mbedtls_x509_crl cacrl=&slave_certificate;
    //int i, j;
    uint32_t flags;
    int verify = 1;
    //char *p, *q;
    const char *pers = "cert_app";

    /*
     * Set to sane values
     */
    mbedtls_net_init( &server_fd );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_x509_crt_init( &cacert );
#if defined(MBEDTLS_X509_CRL_PARSE_C)
    mbedtls_x509_crl_init( &cacrl );
#else
    /* Zeroize structure as CRL parsing is not supported and we have to pass
       it to the verify function */
    memset( &cacrl, 0, sizeof(mbedtls_x509_crl) );
#endif

    optt4.mode                = DFL_MODE;
    optt4.filename            = DFL_FILENAME;
    optt4.ca_file             = DFL_CA_FILE;
    optt4.crl_file            = DFL_CRL_FILE;
    optt4.ca_path             = DFL_CA_PATH;
    optt4.server_name         = DFL_SERVER_NAME;
    optt4.server_port         = DFL_SERVER_PORT;
    optt4.debug_level         = DFL_DEBUG_LEVEL;
    optt4.permissive          = DFL_PERMISSIVE;


    /*
     * 1.1. Load the trusted CA
     */
    /*mbedtls_printf( "  . Loading the CA root certificate ..." );
    fflush( stdout );

    if( strlen( optt4.ca_path ) )
    {
        if( ( ret = mbedtls_x509_crt_parse_path( &cacert, optt4.ca_path ) ) < 0 )
        {
            mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse_path returned -0x%x\n\n", -ret );
            goto exit;
        }

        verify = 1;
    }*/
    /*else if( strlen( optt4.ca_file ) )
    {
        if( ( ret = mbedtls_x509_crt_parse_file( &cacert, optt4.ca_file ) ) < 0 )
        {
            mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse_file returned -0x%x\n\n", -ret );
            goto exit;
        }

        verify = 1;
    }

    mbedtls_printf( " ok (%d skipped)\n", ret );*/

//#if defined(MBEDTLS_X509_CRL_PARSE_C)
    /*if( strlen( optt4.crl_file ) )
    {
        if( ( ret = mbedtls_x509_crl_parse_file( &cacrl, optt4.crl_file ) ) != 0 )
        {
            mbedtls_printf( " failed\n  !  mbedtls_x509_crl_parse returned -0x%x\n\n", -ret );
            goto exit;
        }

        verify = 1;
    }*/
//#endif

    if( optt4.mode == MODE_FILE )
    {
        mbedtls_x509_crt crt;
        mbedtls_x509_crt *cur = &crt;
        mbedtls_x509_crt_init( &crt );

        /*
         * 1.1. Load the certificate(s)
         */
        mbedtls_printf( "\n  . Loading the certificate(s) ..." );
        fflush( stdout );

        ret = mbedtls_x509_crt_parse_file( &crt, optt4.filename );

        if( ret < 0 )
        {
            mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse_file returned %d\n\n", ret );
            mbedtls_x509_crt_free( &crt );
            goto exit;
        }

        if( optt4.permissive == 0 && ret > 0 )
        {
            mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse failed to parse %d certificates\n\n", ret );
            mbedtls_x509_crt_free( &crt );
            goto exit;
        }

        mbedtls_printf( " ok\n" );

        /*
         * 1.2 Print the certificate(s)
         */
        while( cur != NULL )
        {
            mbedtls_printf( "  . Peer certificate information    ...\n" );
            ret = mbedtls_x509_crt_info( (char *) buf, sizeof( buf ) - 1, "      ",
                                 cur );
            if( ret == -1 )
            {
                mbedtls_printf( " failed\n  !  mbedtls_x509_crt_info returned %d\n\n", ret );
                mbedtls_x509_crt_free( &crt );
                goto exit;
            }

            mbedtls_printf( "%s\n", buf );

            cur = cur->next;
        }

        /*
         * 1.3 Verify the certificate
         */
        if( verify )
        {
            mbedtls_printf( "  . Verifying X.509 certificate..." );

            if( ( ret = mbedtls_x509_crt_verify( &crt, &cacert, &cacrl, NULL, &flags,
                                         my_verify, NULL ) ) != 0 )
            {
                char vrfy_buf[512];

                mbedtls_printf( " failed\n" );

                mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );

                mbedtls_printf( "%s\n", vrfy_buf );
            }
            else
                mbedtls_printf( " ok\n" );
        }

        mbedtls_x509_crt_free( &crt );
    }
    else if( optt4.mode == MODE_SSL )
    {
        /*
         * 1. Initialize the RNG and the session data
         */
        mbedtls_printf( "\n  . Seeding the random number generator..." );
        fflush( stdout );

        mbedtls_entropy_init( &entropy );
        if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                   (const unsigned char *) pers,
                                   strlen( pers ) ) ) != 0 )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
            goto ssl_exit;
        }

        mbedtls_printf( " ok\n" );

#if defined(MBEDTLS_DEBUG_C)
        mbedtls_debug_set_threshold( optt4.debug_level );
#endif

        /*
         * 2. Start the connection
         */
        mbedtls_printf( "  . SSL connection to tcp/%s/%s...", optt4.server_name,
                                                              optt4.server_port );
        fflush( stdout );

        if( ( ret = mbedtls_net_connect( &server_fd, optt4.server_name,
                                 optt4.server_port, MBEDTLS_NET_PROTO_TCP ) ) != 0 )
        {
            mbedtls_printf( " failed\n  ! mbedtls_net_connect returned %d\n\n", ret );
            goto ssl_exit;
        }

        /*
         * 3. Setup stuff
         */
        if( ( ret = mbedtls_ssl_config_defaults( &conf,
                        MBEDTLS_SSL_IS_CLIENT,
                        MBEDTLS_SSL_TRANSPORT_STREAM,
                        MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
            goto exit;
        }

        if( verify )
        {
            mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_REQUIRED );
            mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
            mbedtls_ssl_conf_verify( &conf, my_verify, NULL );
        }
        else
            mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_NONE );

        mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
        mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );

        if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
            goto ssl_exit;
        }

        if( ( ret = mbedtls_ssl_set_hostname( &ssl, optt4.server_name ) ) != 0 )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
            goto ssl_exit;
        }

        mbedtls_ssl_set_bio( &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

        /*
         * 4. Handshake
         */
        while( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 )
        {
            if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
            {
                mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret );
                goto ssl_exit;
            }
        }

        mbedtls_printf( " ok\n" );

        /*
         * 5. Print the certificate
         */
#if !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
        mbedtls_printf( "  . Peer certificate information    ... skipped\n" );
#else
        mbedtls_printf( "  . Peer certificate information    ...\n" );
        ret = mbedtls_x509_crt_info( (char *) buf, sizeof( buf ) - 1, "      ",
                                     mbedtls_ssl_get_peer_cert( &ssl ) );
        if( ret == -1 )
        {
            mbedtls_printf( " failed\n  !  mbedtls_x509_crt_info returned %d\n\n", ret );
            goto ssl_exit;
        }

        mbedtls_printf( "%s\n", buf );
#endif /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */

        mbedtls_ssl_close_notify( &ssl );

ssl_exit:
        mbedtls_ssl_free( &ssl );
        mbedtls_ssl_config_free( &conf );
    }

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

    mbedtls_net_free( &server_fd );
    mbedtls_x509_crt_free( &cacert );
#if defined(MBEDTLS_X509_CRL_PARSE_C)
    mbedtls_x509_crl_free( &cacrl );
#endif
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    printf("EXIT CERT APP: %d",exit_code);
    wait_cert_app=false;
    vTaskDelete(NULL);
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C && MBEDTLS_SSL_TLS_C &&
          MBEDTLS_SSL_CLI_C && MBEDTLS_NET_C && MBEDTLS_RSA_C &&
          MBEDTLS_X509_CRT_PARSE_C && MBEDTLS_FS_IO && MBEDTLS_CTR_DRBG_C */
