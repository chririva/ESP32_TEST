/*
 * master_cert_write.c
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
int main( void )
{
    mbedtls_printf( "MBEDTLS_X509_CRT_WRITE_C and/or MBEDTLS_X509_CRT_PARSE_C and/or "
            "MBEDTLS_FS_IO and/or MBEDTLS_SHA256_C and/or "
            "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C and/or "
            "MBEDTLS_ERROR_C not defined.\n");
    return( 0 );
}
#else

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "nvs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "master_cert_write.h"

bool wait_slave_cert_write;
extern mbedtls_pk_context master_priv_key, slave_pub_key;
extern mbedtls_x509_crt master_certificate;
extern mbedtls_x509_crt slave_certificate;

#if defined(MBEDTLS_X509_CSR_PARSE_C)
#define USAGE_CSR                                                           \
    "    request_file=%%s         default: (empty)\n"                           \
    "                            If request_file is specified, subject_key,\n"  \
    "                            subject_pwd and subject_name are ignored!\n"
#else
#define USAGE_CSR ""
#endif /* MBEDTLS_X509_CSR_PARSE_C */

#define DFL_ISSUER_CRT_D         ""
#define DFL_REQUEST_FILE_D        ""
#define DFL_SUBJECT_KEY_D         "subject.key"
#define DFL_ISSUER_KEY_D          "ca.key"
#define DFL_SUBJECT_PWD_D         ""
#define DFL_ISSUER_PWD_D          ""
#define DFL_OUTPUT_FILENAME_D     "cert.crt"
#define DFL_SUBJECT_NAME_D        "CN=CA,O=Comelit,C=IT"
#define DFL_ISSUER_NAME_D         "CN=CA,O=Comelit,C=IT"
#define DFL_NOT_BEFORE_D          "19690101000000"
#define DFL_NOT_AFTER_D           "20201231235959"
#define DFL_SERIAL_D              "1"
#define DFL_SELFSIGN_D            0
#define DFL_IS_CA_D               0 //0 default (1 = capable of signing other certificates)
#define DFL_MAX_PATHLEN_D         0 //-1 default
#define DFL_KEY_USAGE_D           0
#define DFL_NS_CERT_TYPE_D        0
#define DFL_VERSION_D             3
#define DFL_AUTH_IDENT_D          1
#define DFL_SUBJ_IDENT_D          1
#define DFL_CONSTRAINTS_D         1
#define DFL_DIGEST_D              MBEDTLS_MD_SHA256


/*
 * global options
 */
struct opttions3
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
} optt3;

int write_certificate3( mbedtls_x509write_cert *crt, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret;
    //FILE *f;
    unsigned char output_buf[4096];
    size_t len = 0;

    memset( output_buf, 0, 4096 );
    if( ( ret = mbedtls_x509write_crt_pem( crt, output_buf, 4096, f_rng, p_rng ) ) < 0 )
        return( ret );

    len = strlen( (char *) output_buf );

    printf("\nDIMENSIONE DELLO SLAVE_CERTIFICATE: %d",len);
    printf("\nSLAVE_CERTIFICATE: %s",output_buf);

    //LO CARICO DIRETTAMENTE NELLA RAM IN FORMATO mbedtls_x509_crt
    if( ( ret = mbedtls_x509_crt_parse(&slave_certificate, output_buf, sizeof(output_buf)) ) != 0 ){
        printf("\nNon sono riuscito a caricare il CRT nella RAM");
        return( ret );
    }
    else{
    	printf("\nCRT caricato in RAM!");
    	return( ret );
    }

    return( 0 );
}

void slave_cert_write( void *param )
{
	(void)param;
    int ret = 1, exit_code = MBEDTLS_EXIT_FAILURE;
    //mbedtls_x509_crt *issuer_crt = &self_certificate;
    //mbedtls_pk_context loaded_issuer_key, loaded_subject_key;
    mbedtls_pk_context *issuer_key = &master_priv_key;
    mbedtls_pk_context *subject_key = &slave_pub_key;
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
    //mbedtls_pk_init( &loaded_issuer_key );
    //mbedtls_pk_init( &loaded_subject_key );
    mbedtls_mpi_init( &serial );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
#if defined(MBEDTLS_X509_CSR_PARSE_C)
    mbedtls_x509_csr_init( &csr );
#endif
    //mbedtls_x509_crt_init( &issuer_crt );
    memset( buf, 0, 1024 );

    //CARICO IL SELF CERTIFICATE - inizio
    //TODO: caricare il self certificate
    //CARICO IL SELF CERTIFICATE - fine

    optt3.issuer_crt          = DFL_ISSUER_CRT_D;
    optt3.request_file        = DFL_REQUEST_FILE_D;
    optt3.subject_key         = DFL_SUBJECT_KEY_D;
    optt3.issuer_key          = DFL_ISSUER_KEY_D;
    optt3.subject_pwd         = DFL_SUBJECT_PWD_D;
    optt3.issuer_pwd          = DFL_ISSUER_PWD_D;
    optt3.output_file         = DFL_OUTPUT_FILENAME_D;
    optt3.subject_name        = DFL_SUBJECT_NAME_D;
    optt3.issuer_name         = DFL_ISSUER_NAME_D;
    optt3.not_before          = DFL_NOT_BEFORE_D;
    optt3.not_after           = DFL_NOT_AFTER_D;
    optt3.serial              = DFL_SERIAL_D;
    optt3.selfsign            = DFL_SELFSIGN_D;
    optt3.is_ca               = DFL_IS_CA_D;
    optt3.max_pathlen         = DFL_MAX_PATHLEN_D;
    optt3.key_usage           = DFL_KEY_USAGE_D;
    optt3.ns_cert_type        = DFL_NS_CERT_TYPE_D;
    optt3.version             = DFL_VERSION_D - 1;
    optt3.md                  = DFL_DIGEST_D;
    optt3.subject_identifier   = DFL_SUBJ_IDENT_D;
    optt3.authority_identifier = DFL_AUTH_IDENT_D;
    optt3.basic_constraints    = DFL_CONSTRAINTS_D;

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

    if( ( ret = mbedtls_mpi_read_string( &serial, 10, optt3.serial ) ) != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_mpi_read_string returned -0x%04x - %s\n\n", -ret, buf );
        goto exit;
    }

    mbedtls_printf( " ok\n" );


    // Check if key and issuer certificate match
    //
    if( mbedtls_pk_check_pair( &(master_certificate.pk), issuer_key ) != 0 )
	//if( mbedtls_pk_check_pair( issuer_crt.pk, issuer_key ) != 0 )
	{
		mbedtls_printf( " failed\n  !  issuer_key does not match issuer certificate\n\n" );
		goto exit;
	}

    mbedtls_printf( " ok\n" );

    /*if( optt3.selfsign )
    {
        optt3.subject_name = optt3.issuer_name;
        subject_key = issuer_key;
    }*/

    mbedtls_x509write_crt_set_subject_key( &crt, subject_key );
    mbedtls_x509write_crt_set_issuer_key( &crt, issuer_key );

    /*
     * 1.0. Check the names for validity
     */
    if( ( ret = mbedtls_x509write_crt_set_subject_name( &crt, optt3.subject_name ) ) != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_subject_name "
                        "returned -0x%04x - %s\n\n", -ret, buf );
        goto exit;
    }

    if( ( ret = mbedtls_x509write_crt_set_issuer_name( &crt, optt3.issuer_name ) ) != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_issuer_name "
                        "returned -0x%04x - %s\n\n", -ret, buf );
        goto exit;
    }

    mbedtls_printf( "  . Setting certificate values ..." );
    fflush( stdout );

    mbedtls_x509write_crt_set_version( &crt, optt3.version );
    mbedtls_x509write_crt_set_md_alg( &crt, optt3.md );

    ret = mbedtls_x509write_crt_set_serial( &crt, &serial );
    if( ret != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_serial "
                        "returned -0x%04x - %s\n\n", -ret, buf );
        goto exit;
    }

    ret = mbedtls_x509write_crt_set_validity( &crt, optt3.not_before, optt3.not_after );
    if( ret != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_validity "
                        "returned -0x%04x - %s\n\n", -ret, buf );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    if( optt3.version == MBEDTLS_X509_CRT_VERSION_3 &&
        optt3.basic_constraints != 0 )
    {
        mbedtls_printf( "  . Adding the Basic Constraints extension ..." );
        fflush( stdout );

        ret = mbedtls_x509write_crt_set_basic_constraints( &crt, optt3.is_ca,
                                                           optt3.max_pathlen );
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
    if( optt3.version == MBEDTLS_X509_CRT_VERSION_3 &&
        optt3.subject_identifier != 0 )
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

    if( optt3.version == MBEDTLS_X509_CRT_VERSION_3 &&
        optt3.authority_identifier != 0 )
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

    if( optt3.version == MBEDTLS_X509_CRT_VERSION_3 &&
        optt3.key_usage != 0 )
    {
        mbedtls_printf( "  . Adding the Key Usage extension ..." );
        fflush( stdout );

        ret = mbedtls_x509write_crt_set_key_usage( &crt, optt3.key_usage );
        if( ret != 0 )
        {
            mbedtls_strerror( ret, buf, 1024 );
            mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_key_usage "
                            "returned -0x%04x - %s\n\n", -ret, buf );
            goto exit;
        }

        mbedtls_printf( " ok\n" );
    }

    if( optt3.version == MBEDTLS_X509_CRT_VERSION_3 &&
        optt3.ns_cert_type != 0 )
    {
        mbedtls_printf( "  . Adding the NS Cert Type extension ..." );
        fflush( stdout );

        ret = mbedtls_x509write_crt_set_ns_cert_type( &crt, optt3.ns_cert_type );
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

    if( ( ret = write_certificate3( &crt, mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  write_certificate -0x%04x - %s\n\n",
                        -ret, buf );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
#if defined(MBEDTLS_X509_CSR_PARSE_C)
    mbedtls_x509_csr_free( &csr );
#endif /* MBEDTLS_X509_CSR_PARSE_C */
    //mbedtls_x509_crt_free( &issuer_crt );
    mbedtls_x509write_crt_free( &crt );
    //mbedtls_pk_free( &loaded_subject_key );
    //mbedtls_pk_free( &loaded_issuer_key );
    mbedtls_mpi_free( &serial );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    printf("EXIT CODE SLAVE CERT WRITE: %d",exit_code);
    wait_slave_cert_write=false;
    vTaskDelete(NULL);
}
#endif /* MBEDTLS_X509_CRT_WRITE_C && MBEDTLS_X509_CRT_PARSE_C &&
          MBEDTLS_FS_IO && MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C &&
          MBEDTLS_ERROR_C && MBEDTLS_PEM_WRITE_C */
