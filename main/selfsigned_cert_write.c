/*
 * selfsigned_cert_write.c
 *
 * Certificate generation and signing
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
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if !defined(MBEDTLS_X509_CRT_WRITE_C) || \
    !defined(MBEDTLS_X509_CRT_PARSE_C) || !defined(MBEDTLS_FS_IO) || \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C) || \
    !defined(MBEDTLS_ERROR_C) || !defined(MBEDTLS_SHA256_C) || \
    !defined(MBEDTLS_PEM_WRITE_C)
void selfsigned_cert_write( void )
{
    mbedtls_printf( "MBEDTLS_X509_CRT_WRITE_C and/or MBEDTLS_X509_CRT_PARSE_C and/or "
            "MBEDTLS_FS_IO and/or MBEDTLS_SHA256_C and/or "
            "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C and/or "
            "MBEDTLS_ERROR_C not defined.\n");
    printf("EXIT CODE SELF SIGNED CERTIFICATE: 00");
}
#else

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "nvs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "selfsigned_cert_write.h"


bool wait_self_cert_generation;
extern mbedtls_pk_context key_key;
extern mbedtls_x509_crt self_certificate;

#if defined(MBEDTLS_X509_CSR_PARSE_C)
#define USAGE_CSR                                                           \
    "    request_file=%%s         default: (empty)\n"                           \
    "                            If request_file is specified, subject_key,\n"  \
    "                            subject_pwd and subject_name are ignored!\n"
#else
#define USAGE_CSR ""
#endif /* MBEDTLS_X509_CSR_PARSE_C */

#define DFL_ISSUER_CRT_S          ""
#define DFL_REQUEST_FILE_S        ""
#define DFL_SUBJECT_KEY_S         "subject.key"
#define DFL_ISSUER_KEY_S          "ca.key"
#define DFL_SUBJECT_PWD_S         ""
#define DFL_ISSUER_PWD_S          ""
#define DFL_OUTPUT_FILENAME_S     "cert.crt"
#define DFL_SUBJECT_NAME_S        "CN=CA,O=Comelit,C=IT"
#define DFL_ISSUER_NAME_S         "CN=CA,O=Comelit,C=IT"
#define DFL_NOT_BEFORE_S          "19690101000000"
#define DFL_NOT_AFTER_S           "20501231235959"
#define DFL_SERIAL_S              "1"
#define DFL_SELFSIGN_S            1 //0 default
#define DFL_IS_CA_S               1 //0 default (1 = capable of signing other certificates)
#define DFL_MAX_PATHLEN_S         2 //-1 default
#define DFL_KEY_USAGE_S           0
#define DFL_NS_CERT_TYPE_S        0
#define DFL_VERSION_S             3
#define DFL_AUTH_IDENT_S          1
#define DFL_SUBJ_IDENT_S          1
#define DFL_CONSTRAINTS_S         1
#define DFL_DIGEST_S              MBEDTLS_MD_SHA256


#if defined(MBEDTLS_CHECK_PARAMS)
#define mbedtls_exit            exit
void mbedtls_param_failed( const char *failure_condition,
                           const char *file,
                           int line )
{
    mbedtls_printf( "%s:%i: Input param failed - %s\n",
                    file, line, failure_condition );
    mbedtls_exit( MBEDTLS_EXIT_FAILURE );
}
#endif

/*
 * global options
 */
struct opttions
{
    const char *issuer_crt;     /* filename of the issuer certificate   */
    const char *request_file;   /* filename of the certificate request  */
    const char *subject_key;    /* filename of the subject key file     */
    const char *issuer_key;     /* filename of the issuer key file      */
    const char *subject_pwd;    /* password for the subject key file    */
    const char *issuer_pwd;     /* password for the issuer key file     */
    const char *output_file;    /* where to store the constructed CRT   */
    const char *subject_name;   /* subject name for certificate         */
    const char *issuer_name;    /* issuer name for certificate          */
    const char *not_before;     /* validity period not before           */
    const char *not_after;      /* validity period not after            */
    const char *serial;         /* serial number string                 */
    int selfsign;               /* selfsign the certificate             */
    int is_ca;                  /* is a CA certificate                  */
    int max_pathlen;            /* maximum CA path length               */
    int authority_identifier;   /* add authority identifier to CRT      */
    int subject_identifier;     /* add subject identifier to CRT        */
    int basic_constraints;      /* add basic constraints ext to CRT     */
    int version;                /* CRT version                          */
    mbedtls_md_type_t md;       /* Hash used for signing                */
    unsigned char key_usage;    /* key usage flags                      */
    unsigned char ns_cert_type; /* NS cert type                         */
} optt;

int write_certificate( mbedtls_x509write_cert *crt, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret;
    unsigned char output_buf[4096];
    size_t len = 0;

    memset( output_buf, 0, 4096 );
    if( ( ret = mbedtls_x509write_crt_pem( crt, output_buf, 4096, f_rng, p_rng ) ) < 0 )
        return( ret );

    len = strlen( (char *) output_buf );

    printf("\nDIMENSIONE DEL SELF_CERTIFICATE: %d",len);
    printf("\nSELF_CERTIFICATE: %s",output_buf);

    //SALVO SELF CERTIFICATE - inizio
    //TODO: salvare il self certificate
    //SALVO IL SELF CERTIFICATE - fine

    //LO CARICO DIRETTAMENTE NELLA RAM IN FORMATO mbedtls_x509_crt
    if( ( ret = mbedtls_x509_crt_parse(&self_certificate, output_buf, sizeof(output_buf)) ) != 0 ){
        printf("\nNon sono riuscito a caricare il CRT nella RAM");
        return( ret );
    }
    else{
    	printf("\nCRT caricato in RAM!");
    	return( ret );
    }
    //

    return( 0 );
}

void selfsigned_cert_write( void *param)
{
	(void)param;
    int ret = 1, exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_x509_crt issuer_crt;
    mbedtls_pk_context loaded_issuer_key, loaded_subject_key;
    mbedtls_pk_context *issuer_key = &key_key, *subject_key = &key_key;
    char buf[1024];
#if defined(MBEDTLS_X509_CSR_PARSE_C)
    mbedtls_x509_csr csr;
#endif
    mbedtls_x509write_cert crt;
    mbedtls_mpi serial;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "crt esp32";

    /*
     * Set to sane values
     */
    mbedtls_x509write_crt_init( &crt );
    mbedtls_pk_init( &loaded_issuer_key );
    mbedtls_pk_init( &loaded_subject_key );
    mbedtls_mpi_init( &serial );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
#if defined(MBEDTLS_X509_CSR_PARSE_C)
    mbedtls_x509_csr_init( &csr );
#endif
    mbedtls_x509_crt_init( &issuer_crt );
    memset( buf, 0, 1024 );

    optt.issuer_crt          = DFL_ISSUER_CRT_S;
    optt.request_file        = DFL_REQUEST_FILE_S;
    optt.subject_key         = DFL_SUBJECT_KEY_S;
    optt.issuer_key          = DFL_ISSUER_KEY_S;
    optt.subject_pwd         = DFL_SUBJECT_PWD_S;
    optt.issuer_pwd          = DFL_ISSUER_PWD_S;
    optt.output_file         = DFL_OUTPUT_FILENAME_S;
    optt.subject_name        = DFL_SUBJECT_NAME_S;
    optt.issuer_name         = DFL_ISSUER_NAME_S;
    optt.not_before          = DFL_NOT_BEFORE_S;
    optt.not_after           = DFL_NOT_AFTER_S;
    optt.serial              = DFL_SERIAL_S;
    optt.selfsign            = DFL_SELFSIGN_S;
    optt.is_ca               = DFL_IS_CA_S;
    optt.max_pathlen         = DFL_MAX_PATHLEN_S;
    optt.key_usage           = DFL_KEY_USAGE_S;
    optt.ns_cert_type        = DFL_NS_CERT_TYPE_S;
    optt.version             = DFL_VERSION_S - 1;
    optt.md                  = DFL_DIGEST_S;
    optt.subject_identifier   = DFL_SUBJ_IDENT_S;
    optt.authority_identifier = DFL_AUTH_IDENT_S;
    optt.basic_constraints    = DFL_CONSTRAINTS_S;

    /*
     * 0. Seed the PRNG
     */
    mbedtls_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,(const unsigned char *) pers, strlen( pers ) ) ) != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_ctr_drbg_seed returned %d - %s\n", ret, buf );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    // Parse serial to MPI
    //
    mbedtls_printf( "  . Reading serial number..." );
    fflush( stdout );

    if( ( ret = mbedtls_mpi_read_string( &serial, 10, optt.serial ) ) != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_mpi_read_string returned -0x%04x - %s\n\n", -ret, buf );
        goto exit;
    }

    mbedtls_printf( " ok\n" );


    if( optt.selfsign )
    {
        optt.subject_name = optt.issuer_name;
        //subject_key = issuer_key;
    }

    mbedtls_x509write_crt_set_subject_key( &crt, subject_key );
    mbedtls_x509write_crt_set_issuer_key( &crt, issuer_key );

    /*
     * 1.0. Check the names for validity
     */
    if( ( ret = mbedtls_x509write_crt_set_subject_name( &crt, optt.subject_name ) ) != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_subject_name "
                        "returned -0x%04x - %s\n\n", -ret, buf );
        goto exit;
    }

    if( ( ret = mbedtls_x509write_crt_set_issuer_name( &crt, optt.issuer_name ) ) != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_issuer_name "
                        "returned -0x%04x - %s\n\n", -ret, buf );
        goto exit;
    }

    mbedtls_printf( "  . Setting certificate values ..." );
    fflush( stdout );

    mbedtls_x509write_crt_set_version( &crt, optt.version );
    mbedtls_x509write_crt_set_md_alg( &crt, optt.md );

    ret = mbedtls_x509write_crt_set_serial( &crt, &serial );
    if( ret != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_serial "
                        "returned -0x%04x - %s\n\n", -ret, buf );
        goto exit;
    }

    ret = mbedtls_x509write_crt_set_validity( &crt, optt.not_before, optt.not_after );
    if( ret != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_validity "
                        "returned -0x%04x - %s\n\n", -ret, buf );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    if( optt.version == MBEDTLS_X509_CRT_VERSION_3 &&
        optt.basic_constraints != 0 )
    {
        mbedtls_printf( "  . Adding the Basic Constraints extension ..." );
        fflush( stdout );

        ret = mbedtls_x509write_crt_set_basic_constraints( &crt, optt.is_ca,
                                                           optt.max_pathlen );
        if( ret != 0 )
        {
            mbedtls_strerror( ret, buf, 1024 );
            mbedtls_printf( " failed\n  !  x509write_crt_set_basic_contraints "
                            "returned -0x%04x - %s\n\n", -ret, buf );
            goto exit;
        }

        mbedtls_printf( " ok\n" );
    }

#if defined(MBEDTLS_SHA1_C)
    if( optt.version == MBEDTLS_X509_CRT_VERSION_3 &&
        optt.subject_identifier != 0 )
    {
        mbedtls_printf( "  . Adding the Subject Key Identifier ..." );
        fflush( stdout );

        ret = mbedtls_x509write_crt_set_subject_key_identifier( &crt );
        if( ret != 0 )
        {
            mbedtls_strerror( ret, buf, 1024 );
            mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_subject"
                            "_key_identifier returned -0x%04x - %s\n\n",
                            -ret, buf );
            goto exit;
        }

        mbedtls_printf( " ok\n" );
    }

    if( optt.version == MBEDTLS_X509_CRT_VERSION_3 &&
        optt.authority_identifier != 0 )
    {
        mbedtls_printf( "  . Adding the Authority Key Identifier ..." );
        fflush( stdout );

        ret = mbedtls_x509write_crt_set_authority_key_identifier( &crt );
        if( ret != 0 )
        {
            mbedtls_strerror( ret, buf, 1024 );
            mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_authority_"
                            "key_identifier returned -0x%04x - %s\n\n",
                            -ret, buf );
            goto exit;
        }

        mbedtls_printf( " ok\n" );
    }
#endif /* MBEDTLS_SHA1_C */

    if( optt.version == MBEDTLS_X509_CRT_VERSION_3 &&
        optt.key_usage != 0 )
    {
        mbedtls_printf( "  . Adding the Key Usage extension ..." );
        fflush( stdout );

        ret = mbedtls_x509write_crt_set_key_usage( &crt, optt.key_usage );
        if( ret != 0 )
        {
            mbedtls_strerror( ret, buf, 1024 );
            mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_key_usage "
                            "returned -0x%04x - %s\n\n", -ret, buf );
            goto exit;
        }

        mbedtls_printf( " ok\n" );
    }

    if( optt.version == MBEDTLS_X509_CRT_VERSION_3 &&
        optt.ns_cert_type != 0 )
    {
        mbedtls_printf( "  . Adding the NS Cert Type extension ..." );
        fflush( stdout );

        ret = mbedtls_x509write_crt_set_ns_cert_type( &crt, optt.ns_cert_type );
        if( ret != 0 )
        {
            mbedtls_strerror( ret, buf, 1024 );
            mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_ns_cert_type "
                            "returned -0x%04x - %s\n\n", -ret, buf );
            goto exit;
        }

        mbedtls_printf( " ok\n" );
    }

    /*
     * 1.2. Writing the certificate
     */
    mbedtls_printf( "  . Writing the certificate..." );
    fflush( stdout );

    if( ( ret = write_certificate( &crt, mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  write_certificate -0x%04x - %s\n\n",
                        -ret, buf );
        goto exit;
    }
    //self_certificate = crt;
    mbedtls_printf( " ok\n" );

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
#if defined(MBEDTLS_X509_CSR_PARSE_C)
    mbedtls_x509_csr_free( &csr );
#endif /* MBEDTLS_X509_CSR_PARSE_C */
    mbedtls_x509_crt_free( &issuer_crt );
    mbedtls_x509write_crt_free( &crt );
    mbedtls_pk_free( &loaded_subject_key );
    mbedtls_pk_free( &loaded_issuer_key );
    mbedtls_mpi_free( &serial );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    printf("EXIT CODE SELF SIGNED CERTIFICATE: %d",exit_code);
    wait_self_cert_generation=false;
    vTaskDelete(NULL);
}
#endif /* MBEDTLS_X509_CRT_WRITE_C && MBEDTLS_X509_CRT_PARSE_C &&
          MBEDTLS_FS_IO && MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C &&
          MBEDTLS_ERROR_C && MBEDTLS_PEM_WRITE_C */
