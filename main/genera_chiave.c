/*
 *  Key generation application
 *
 *
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
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if defined(MBEDTLS_PK_WRITE_C) && defined(MBEDTLS_FS_IO) && \
    defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/rsa.h"
#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/rsa.h"
#include "mbedtls/bignum.h"
#include "nvs_flash.h"
#include "esp_system.h"
#include "nvs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool wait_key_gen;

#if !defined(_WIN32)
#include <unistd.h>
#define DEV_RANDOM_THRESHOLD        32

int dev_random_entropy_poll( void *data, unsigned char *output,
                             size_t len, size_t *olen )
{
    FILE *file;
    size_t ret, left = len;
    unsigned char *p = output;
    ((void) data);

    *olen = 0;

    file = fopen( "/dev/random", "rb" );
    if( file == NULL )
        return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );

    while( left > 0 )
    {
        /* /dev/random can return much less than requested. If so, try again */
        ret = fread( p, 1, left, file );
        if( ret == 0 && ferror( file ) )
        {
            fclose( file );
            return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );
        }

        p += ret;
        left -= ret;
        sleep( 1 );
    }
    fclose( file );
    *olen = len;

    return( 0 );
}
#endif /* !_WIN32 */
#endif

#if defined(MBEDTLS_ECP_C)
#define DFL_EC_CURVE            mbedtls_ecp_curve_list()->grp_id
#else
#define DFL_EC_CURVE            0
#endif

#if !defined(_WIN32) && defined(MBEDTLS_FS_IO)
#define USAGE_DEV_RANDOM \
    "    use_dev_random=0|1    default: 0\n"
#else
#define USAGE_DEV_RANDOM ""
#endif /* !_WIN32 && MBEDTLS_FS_IO */

#define FORMAT_PEM              0
#define FORMAT_DER              1

#define DFL_TYPE                MBEDTLS_PK_RSA
#define DFL_RSA_KEYSIZE         2048
#define DFL_FILENAME            "keyfile.key"
#define DFL_FORMAT              FORMAT_PEM
#define DFL_USE_DEV_RANDOM      0

#define USAGE \
    "\n usage: gen_key param=<>...\n"                   \
    "\n acceptable parameters:\n"                       \
    "    type=rsa|ec           default: rsa\n"          \
    "    rsa_keysize=%%d        default: 4096\n"        \
    "    ec_curve=%%s           see below\n"            \
    "    filename=%%s           default: keyfile.key\n" \
    "    format=pem|der        default: pem\n"          \
    USAGE_DEV_RANDOM                                    \
    "\n"

#if !defined(MBEDTLS_PK_WRITE_C) || !defined(MBEDTLS_PEM_WRITE_C) || \
    !defined(MBEDTLS_FS_IO) || !defined(MBEDTLS_ENTROPY_C) || \
    !defined(MBEDTLS_CTR_DRBG_C)
void genera_chiave( void )
{
    mbedtls_printf( "MBEDTLS_PK_WRITE_C and/or MBEDTLS_FS_IO and/or "
            "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C and/or "
            "MBEDTLS_PEM_WRITE_C"
            "not defined.\n" );
    return;
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

/*
 * global options
 */
struct options
{
    int type;                   /* the type of key to generate          */
    int rsa_keysize;            /* length of key in bits                */
    int ec_curve;               /* curve identifier for EC keys         */
    const char *filename;       /* filename of the key file             */
    int format;                 /* the output format to use             */
    int use_dev_random;         /* use /dev/random as entropy source    */
} opt;

bool salva_chiavi_key(const mbedtls_pk_context *key, const mbedtls_mpi *N, const mbedtls_mpi *P, const mbedtls_mpi *Q,
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

/*static int write_private_key( mbedtls_pk_context *key, const char *output_file )
{
	printf("\nRICHIAMO: write_private_key\n");
    int ret;
    FILE *f;
    unsigned char output_buf[16000];
    unsigned char *c = output_buf;
    size_t len = 0;

    memset(output_buf, 0, 16000);
    if( opt.format == FORMAT_PEM )
    {
        if( ( ret = mbedtls_pk_write_key_pem( key, output_buf, 16000 ) ) != 0 )
            return( ret );

        len = strlen( (char *) output_buf );
    }
    else
    {
        if( ( ret = mbedtls_pk_write_key_der( key, output_buf, 16000 ) ) < 0 )
            return( ret );

        len = ret;
        c = output_buf + sizeof(output_buf) - len;
    }

    if( ( f = fopen( output_file, "wb" ) ) == NULL )
        return( -1 );

    if( fwrite( c, 1, len, f ) != len )
    {
        fclose( f );
        return( -1 );
    }

    fclose( f );

    return( 0 );
}*/

void genera_chiave()
{
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_pk_context key;
    char buf[1024];
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "gen_key";

    /*
     * Set to sane values
     */

    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
    mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &DP );
    mbedtls_mpi_init( &DQ ); mbedtls_mpi_init( &QP );

    mbedtls_pk_init( &key );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    memset( buf, 0, sizeof( buf ) );

    opt.type                = DFL_TYPE;
    opt.rsa_keysize         = DFL_RSA_KEYSIZE;
    opt.ec_curve            = DFL_EC_CURVE;
    opt.filename            = DFL_FILENAME;
    opt.format              = DFL_FORMAT;
    opt.use_dev_random      = DFL_USE_DEV_RANDOM;

    mbedtls_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );
    mbedtls_entropy_init( &entropy );
#if !defined(_WIN32) && defined(MBEDTLS_FS_IO)
    if( opt.use_dev_random )
    {
        if( ( ret = mbedtls_entropy_add_source( &entropy, dev_random_entropy_poll,
                                        NULL, DEV_RANDOM_THRESHOLD,
                                        MBEDTLS_ENTROPY_SOURCE_STRONG ) ) != 0 )
        {
            mbedtls_printf( " failed\n  ! mbedtls_entropy_add_source returned -0x%04x\n", -ret );
            goto exit;
        }

        mbedtls_printf("\n    Using /dev/random, so can take a long time! " );
        fflush( stdout );
    }
#endif /* !_WIN32 && MBEDTLS_FS_IO */

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret );
        goto exit;
    }

    /*
     * 1.1. Generate the key
     */
    mbedtls_printf( "\n  . Generating the private key ..." );
    fflush( stdout );

    if( ( ret = mbedtls_pk_setup( &key, mbedtls_pk_info_from_type( (mbedtls_pk_type_t) opt.type ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_pk_setup returned -0x%04x", -ret );
        goto exit;
    }

//#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_GENPRIME)
    if( opt.type == MBEDTLS_PK_RSA )
    {
        ret = mbedtls_rsa_gen_key( mbedtls_pk_rsa( key ), mbedtls_ctr_drbg_random, &ctr_drbg, opt.rsa_keysize, 65537 );
        if( ret != 0 )
        {
            mbedtls_printf( " failed\n  !  mbedtls_rsa_gen_key returned -0x%04x", -ret );
            goto exit;
        }
    }
    else
//#endif /* MBEDTLS_RSA_C */
////////////////////////////////////////////COSO TOLTO
    {
        mbedtls_printf( " failed\n  !  key type not supported\n" );
        goto exit;
    }

    /*
     * 1.2 Print the key
     */
    mbedtls_printf( " ok\n  . Key information:\n" );

//#if defined(MBEDTLS_RSA_C)
    if( mbedtls_pk_get_type( &key ) == MBEDTLS_PK_RSA )
    {
        mbedtls_rsa_context *rsa = mbedtls_pk_rsa( key );
        if( ( ret = mbedtls_rsa_export    ( rsa, &N, &P, &Q, &D, &E ) ) != 0 ||
            ( ret = mbedtls_rsa_export_crt( rsa, &DP, &DQ, &QP ) )      != 0 )
        {
            mbedtls_printf( " failed\n  ! could not export RSA parameters\n\n" );
            goto exit;
        }

        printf("\n - Le chiavi sono state generate con successo.\n");
        printf("\n - SALVO LE CHIAVI IN MEMORIA.\n");

        /*if(salva_chiavi_key(&key,&N,&P,&Q,&D,&E,&DP,&DQ,&QP))
        	printf("\n - Le chiavi sono state salvate in un posto sicuro.\n");
    	else
    		printf("\n - Non sono riuscito a salvare le chiavi.\n");*/

        mbedtls_mpi_write_file( "N:  ",  &N,  16, NULL );
        mbedtls_mpi_write_file( "E:  ",  &E,  16, NULL );
        mbedtls_mpi_write_file( "D:  ",  &D,  16, NULL );
        mbedtls_mpi_write_file( "P:  ",  &P,  16, NULL );
        mbedtls_mpi_write_file( "Q:  ",  &Q,  16, NULL );
        mbedtls_mpi_write_file( "DP: ",  &DP, 16, NULL );
        mbedtls_mpi_write_file( "DQ:  ", &DQ, 16, NULL );
        mbedtls_mpi_write_file( "QP:  ", &QP, 16, NULL );
        //stampo la key
        int rett;
        unsigned char output_buf[16000];
        size_t len = 0;

        memset(output_buf, 0, 16000);
        if( opt.format == FORMAT_PEM )
        {
            if( ( rett = mbedtls_pk_write_key_pem( &key, output_buf, 16000 ) ) != 0 )
                printf("\nPROBLEMONE");

            len = strlen( (char *) output_buf );
        }
        printf("\n La key pem vale: %s",output_buf);
        printf("\n La sua lunghezza vale: %d",len);
    }
    else
//#endif
/*#if defined(MBEDTLS_ECP_C)
    if( mbedtls_pk_get_type( &key ) == MBEDTLS_PK_ECKEY )
    {
        mbedtls_ecp_keypair *ecp = mbedtls_pk_ec( key );
        mbedtls_printf( "curve: %s\n", mbedtls_ecp_curve_info_from_grp_id( ecp->grp.id )->name );
        mbedtls_mpi_write_file( "X_Q:   ", &ecp->Q.X, 16, NULL );
        mbedtls_mpi_write_file( "Y_Q:   ", &ecp->Q.Y, 16, NULL );
        mbedtls_mpi_write_file( "D:     ", &ecp->d  , 16, NULL );
    }
    else
#endif*/
        mbedtls_printf("  ! key type not supported\n");

    /*
     * 1.3 Export key
     */
    /*mbedtls_printf( "  . Writing key to file..." );

    if( ( ret = write_private_key( &key, opt.filename ) ) != 0 )
    {
    	printf("\nDebug_9");
        mbedtls_printf( " -failed\n" );
        goto exit;
    }
    printf("\n--------NON LA SALVO IN MEMORIA!----------\n");

    mbedtls_printf( " ok\n" );*/

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

    if( exit_code != MBEDTLS_EXIT_SUCCESS )
    {
#ifdef MBEDTLS_ERROR_C
        mbedtls_strerror( ret, buf, sizeof( buf ) );
        mbedtls_printf( " - %s\n", buf );
#else
        mbedtls_printf("\n");
#endif
    }

    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
    mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );

    mbedtls_pk_free( &key );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    printf("\n\t\t EXIT CODE DEL GENERA CHIAVE: %d \n",exit_code);
    wait_key_gen=false;
    vTaskDelete(NULL);

}
#endif /* MBEDTLS_PK_WRITE_C && MBEDTLS_PEM_WRITE_C && MBEDTLS_FS_IO &&
        * MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C */

