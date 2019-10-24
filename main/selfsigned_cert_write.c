/*
 * selfsigned_cert_write.c
 *
 *
 */


/*
 *  Certificate generation and signing
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
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
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/error.h"
#include "nvs.h"
//#include "gatts_demo.c"
extern mbedtls_pk_context key_key;
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
bool wait_self_cert_generation;

#if defined(MBEDTLS_X509_CSR_PARSE_C)
#define USAGE_CSR                                                           \
    "    request_file=%%s         default: (empty)\n"                           \
    "                            If request_file is specified, subject_key,\n"  \
    "                            subject_pwd and subject_name are ignored!\n"
#else
#define USAGE_CSR ""
#endif /* MBEDTLS_X509_CSR_PARSE_C */

#define DFL_ISSUER_CRT          ""
#define DFL_REQUEST_FILE        ""
#define DFL_SUBJECT_KEY         "subject.key"
#define DFL_ISSUER_KEY          "ca.key"
#define DFL_SUBJECT_PWD         ""
#define DFL_ISSUER_PWD          ""
#define DFL_OUTPUT_FILENAME     "cert.crt"
#define DFL_SUBJECT_NAME        "CN=Cert,O=Comelit,C=IT"
#define DFL_ISSUER_NAME         "CN=CA,O=Comelit,C=IT"
#define DFL_NOT_BEFORE          "20000101000000"
#define DFL_NOT_AFTER           "20501231235959"
#define DFL_SERIAL              "1"
#define DFL_SELFSIGN            1 //0 default
#define DFL_IS_CA               1 //0 default (1 = capable of signing other certificates)
#define DFL_MAX_PATHLEN         -1 //-1 default
#define DFL_KEY_USAGE           0
#define DFL_NS_CERT_TYPE        0
#define DFL_VERSION             3
#define DFL_AUTH_IDENT          1
#define DFL_SUBJ_IDENT          1
#define DFL_CONSTRAINTS         1
#define DFL_DIGEST              MBEDTLS_MD_SHA256


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

//TODO: da sostituire con il salvataggio in nvs
int write_certificate( mbedtls_x509write_cert *crt, const char *output_file,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng )
{
    int ret;
    //FILE *f;
    unsigned char output_buf[4096];
    size_t len = 0;

    memset( output_buf, 0, 4096 );
    if( ( ret = mbedtls_x509write_crt_pem( crt, output_buf, 4096, f_rng, p_rng ) ) < 0 )
        return( ret );

    len = strlen( (char *) output_buf );

    printf("\nCERTIFICATO: %s",output_buf);
    /*if( ( f = fopen( output_file, "w" ) ) == NULL )
        return( -1 );

    if( fwrite( output_buf, 1, len, f ) != len )
    {
        fclose( f );
        return( -1 );
    }

    fclose( f );*/

    return( 0 );
}

void selfsigned_cert_write( void )
{
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

    optt.issuer_crt          = DFL_ISSUER_CRT;
    optt.request_file        = DFL_REQUEST_FILE;
    optt.subject_key         = DFL_SUBJECT_KEY;
    optt.issuer_key          = DFL_ISSUER_KEY;
    optt.subject_pwd         = DFL_SUBJECT_PWD;
    optt.issuer_pwd          = DFL_ISSUER_PWD;
    optt.output_file         = DFL_OUTPUT_FILENAME;
    optt.subject_name        = DFL_SUBJECT_NAME;
    optt.issuer_name         = DFL_ISSUER_NAME;
    optt.not_before          = DFL_NOT_BEFORE;
    optt.not_after           = DFL_NOT_AFTER;
    optt.serial              = DFL_SERIAL;
    optt.selfsign            = DFL_SELFSIGN;
    optt.is_ca               = DFL_IS_CA;
    optt.max_pathlen         = DFL_MAX_PATHLEN;
    optt.key_usage           = DFL_KEY_USAGE;
    optt.ns_cert_type        = DFL_NS_CERT_TYPE;
    optt.version             = DFL_VERSION - 1;
    optt.md                  = DFL_DIGEST;
    optt.subject_identifier   = DFL_SUBJ_IDENT;
    optt.authority_identifier = DFL_AUTH_IDENT;
    optt.basic_constraints    = DFL_CONSTRAINTS;

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

    if( ( ret = write_certificate( &crt, optt.output_file,
                                   mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
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
