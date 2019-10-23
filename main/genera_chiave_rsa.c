/*
 * genera_chiave_rsa.c
 *
 *
 */


/*
 *  Example RSA key generation program
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

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "nvs_flash.h"
#include "esp_system.h"
#include "nvs.h"

bool wait_key_generation;

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

#if defined(MBEDTLS_BIGNUM_C) && defined(MBEDTLS_ENTROPY_C) && \
    defined(MBEDTLS_RSA_C) && defined(MBEDTLS_GENPRIME) && \
    defined(MBEDTLS_FS_IO) && defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/bignum.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/rsa.h"

#include <stdio.h>
#include <string.h>
#endif

#define KEY_SIZE 2048
#define EXPONENT 65537

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_ENTROPY_C) ||   \
    !defined(MBEDTLS_RSA_C) || !defined(MBEDTLS_GENPRIME) ||      \
    !defined(MBEDTLS_FS_IO) || !defined(MBEDTLS_CTR_DRBG_C)
void genera_chiave_rsa( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_ENTROPY_C and/or "
           "MBEDTLS_RSA_C and/or MBEDTLS_GENPRIME and/or "
           "MBEDTLS_FS_IO and/or MBEDTLS_CTR_DRBG_C not defined.\n");
    //return( 0 );
    printf( " EXIT CODE GENERA CHIAVE: 00\n");
    vTaskDelete(NULL);
}
#else

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

bool salva_chiavi(const mbedtls_mpi *N, const mbedtls_mpi *P, const mbedtls_mpi *Q,
				  const mbedtls_mpi *D, const mbedtls_mpi *E, const mbedtls_mpi *DP,
				  const mbedtls_mpi *DQ, const mbedtls_mpi *QP){

    //SALVATAGGIO SU FILE! /////////////////////////////////////////////////////////////////
    // Initialize NVS
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // NVS partition was truncated and needs to be erased
        // Retry nvs_flash_init
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK( err );
    // Open
    printf("\nOpening Non-Volatile Storage (NVS) handle... ");
    nvs_handle my_handle;
    err = nvs_open("stored_keys", NVS_READWRITE, &my_handle);
    if (err != ESP_OK) {
        printf("\nError (%s) opening NVS handle!\n", esp_err_to_name(err));
    } else{
        printf("\nFile Aperto con successo.\n");

		//CONVERTO TUTTI I mbedtls_mpi IN STRINGHE PER IL SALVATAGGIO SU FILE.
		size_t n_N,n_E,n_D,n_P,n_Q,n_DP,n_DQ,n_QP;
		//TODO: Ottimizzare il consumo della memoria di questi vettori
		static char N_string[1024],E_string[1024],D_string[1024],P_string[1024],Q_string[1024],DP_string[1024],DQ_string[1024],QP_string[1024];
		memset(N_string, 0, sizeof(N_string));
		memset(E_string, 0, sizeof(E_string));
		memset(D_string, 0, sizeof(D_string));
		memset(P_string, 0, sizeof(P_string));
		memset(Q_string, 0, sizeof(Q_string));
		memset(DP_string, 0, sizeof(DP_string));
		memset(DQ_string, 0, sizeof(DQ_string));
		memset(QP_string, 0, sizeof(QP_string));
		mbedtls_mpi_write_string(N, 16, N_string, sizeof(N_string)-1, &n_N);
		mbedtls_mpi_write_string(E, 16, E_string, sizeof(E_string)-1, &n_E);
		mbedtls_mpi_write_string(D, 16, D_string, sizeof(D_string)-1, &n_D);
		mbedtls_mpi_write_string(P, 16, P_string, sizeof(P_string)-1, &n_P);
		mbedtls_mpi_write_string(Q, 16, Q_string, sizeof(Q_string)-1, &n_Q);
		mbedtls_mpi_write_string(DP, 16, DP_string, sizeof(DP_string)-1, &n_DP);
		mbedtls_mpi_write_string(DQ, 16, DQ_string, sizeof(DQ_string)-1, &n_DQ);
		mbedtls_mpi_write_string(QP, 16, QP_string, sizeof(QP_string)-1, &n_QP);

		//STAMPE
		printf("\nN_lenght: %d",n_N);
		printf("\nN_value: %s \n",N_string);
		printf("\nE_lenght: %d",n_E);
		printf("\nE_value: %s \n",E_string);
		printf("\nD_lenght: %d",n_D);
		printf("\nD_value: %s \n",D_string);
		printf("\nP_lenght: %d",n_P);
		printf("\nP_value: %s \n",P_string);
		printf("\nQ_lenght: %d",n_Q);
		printf("\nQ_value: %s \n",Q_string);
		printf("\nDP_lenght: %d",n_DP);
		printf("\nDP_value: %s \n",DP_string);
		printf("\nDQ_lenght: %d",n_DQ);
		printf("\nDQ_value: %s \n",DQ_string);
		printf("\nQP_lenght: %d",n_QP);
		printf("\nQP_value: %s \n",QP_string);

		// Write
		printf("Writing values in NVS ... ");
		err = nvs_set_str(my_handle, "N", N_string); printf((err != ESP_OK) ? "Failed!\n" : "Done\n");
		err = nvs_set_str(my_handle, "E", E_string); printf((err != ESP_OK) ? "Failed!\n" : "Done\n");
		err = nvs_set_str(my_handle, "D", D_string); printf((err != ESP_OK) ? "Failed!\n" : "Done\n");
		err = nvs_set_str(my_handle, "P", P_string); printf((err != ESP_OK) ? "Failed!\n" : "Done\n");
		err = nvs_set_str(my_handle, "Q", Q_string); printf((err != ESP_OK) ? "Failed!\n" : "Done\n");
		err = nvs_set_str(my_handle, "DP", DP_string); printf((err != ESP_OK) ? "Failed!\n" : "Done\n");
		err = nvs_set_str(my_handle, "DQ", DQ_string); printf((err != ESP_OK) ? "Failed!\n" : "Done\n");
		err = nvs_set_str(my_handle, "QP", QP_string); printf((err != ESP_OK) ? "Failed!\n" : "Done\n");

		// Commit written value.
		// After setting any values, nvs_commit() must be called to ensure changes are written
		// to flash storage. Implementations may write to storage at other times,
		// but this is not guaranteed.
		printf("Committing updates in NVS ... ");
		err = nvs_commit(my_handle);
		printf((err != ESP_OK) ? "Failed!\n" : "Done\n");
		// Close
		nvs_close(my_handle);
		printf("file chiuso.\n");
    }

	return true;
}

void genera_chiave_rsa( void )
{
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
    FILE *fpub  = NULL;
    FILE *fpriv = NULL;
    const char *pers = "rsa_genkey";

    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );
    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
    mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &DP );
    mbedtls_mpi_init( &DQ ); mbedtls_mpi_init( &QP );

    mbedtls_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n  . Generating the RSA key [ %d-bit ]...", KEY_SIZE );
    fflush( stdout );

    if( ( ret = mbedtls_rsa_gen_key( &rsa, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE, EXPONENT ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_gen_key returned %d\n\n", ret );
        goto exit;
    }

    //mbedtls_printf( " ok\n  . Exporting the public  key in rsa_pub.txt...." );
    fflush( stdout );

    if( ( ret = mbedtls_rsa_export    ( &rsa, &N, &P, &Q, &D, &E ) ) != 0 ||
        ( ret = mbedtls_rsa_export_crt( &rsa, &DP, &DQ, &QP ) )      != 0 )
    {
        mbedtls_printf( " failed\n  ! could not export RSA parameters\n\n" );
        goto exit;
    }
    // PRINTO LE CHIAVI
    	//printf("\nRSA_PUB: N= %u--%u\n",*N.p);
    	/*printf("%u\n", *N.p);
    	printf("%u\n", *E.p);
    	printf("%u\n", *(N.p));
    	printf("%u\n", *(E.p));*/
    //
    /*if( ( fpub = fopen( "rsa_pub.txt", "wb+" ) ) == NULL )
    {
        mbedtls_printf( " failed\n  ! could not open rsa_pub.txt for writing\n\n" );
        goto exit;
    }*/

    /*if( ( ret = mbedtls_mpi_write_file( "N = ", &N, 16, NULL ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "E = ", &E, 16, NULL ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_write_file returned %d\n\n", ret );
        goto exit;
    }*/

    //mbedtls_printf( " ok\n  . Exporting the private key in rsa_priv.txt..." );
    //fflush( stdout );

    /*if( ( fpriv = fopen( "rsa_priv.txt", "wb+" ) ) == NULL )
    {
        mbedtls_printf( " failed\n  ! could not open rsa_priv.txt for writing\n" );
        goto exit;
    }*/

    printf("\n - Le chiavi sono state generate con successo.\n");
    printf("\n - SALVO LE CHIAVI IN MEMORIA.\n");

    if(salva_chiavi(&N,&P,&Q,&D,&E,&DP,&DQ,&QP))
    	printf("\n - Le chiavi sono state salvate in un posto sicuro.\n");
	else
		printf("\n - Non sono riuscito a salvare le chiavi.\n");

    /*
       if( ( ret = mbedtls_mpi_write_file( "N = " , &N , 16, NULL ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "E = " , &E , 16, NULL ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "D = " , &D , 16, NULL ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "P = " , &P , 16, NULL ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "Q = " , &Q , 16, NULL ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "DP = ", &DP, 16, NULL ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "DQ = ", &DQ, 16, NULL ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "QP = ", &QP, 16, NULL ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_write_file returned %d\n\n", ret );
        goto exit;
    }*/
/*
    mbedtls_printf( " ok\n  . Generating the certificate..." );
    x509write_init_raw( &cert );
    x509write_add_pubkey( &cert, &rsa );
    x509write_add_subject( &cert, "CN='localhost'" );
    x509write_add_validity( &cert, "2007-09-06 17:00:32",
                                   "2010-09-06 17:00:32" );
    x509write_create_selfsign( &cert, &rsa );
    x509write_crtfile( &cert, "cert.der", X509_OUTPUT_DER );
    x509write_crtfile( &cert, "cert.pem", X509_OUTPUT_PEM );
    x509write_free_raw( &cert );
*/

    //mbedtls_printf( " ok\n\n" );

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

    if( fpub  != NULL )
        fclose( fpub );

    if( fpriv != NULL )
        fclose( fpriv );

    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
    mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
    mbedtls_rsa_free( &rsa );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );


    printf( " EXIT CODE GENERA CHIAVE: %d\n",exit_code);
    wait_key_generation=false;
    vTaskDelete(NULL);
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C && MBEDTLS_RSA_C &&
          MBEDTLS_GENPRIME && MBEDTLS_FS_IO && MBEDTLS_CTR_DRBG_C */


