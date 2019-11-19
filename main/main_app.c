/*
 * main_app.c
 *
 * Entry Point
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include <time.h>
#include <sys/time.h>

#include "genera_chiave.c"
#include "selfsigned_cert_write.h"
#include "master_cert_write.h"
#include "slave_cert_write_DEBUG_TEST.h"
#include "random_challenge_sign_TEST.h"
#include "random_challenge_verify.h"
#include "cert_app.h"

#include "esp_bt.h"
#include "esp_gap_ble_api.h"
#include "esp_gatts_api.h"
#include "esp_bt_defs.h"
#include "esp_bt_main.h"
#include "esp_gatt_common_api.h"
#include "ble_server.h"
//#include "ble.c"


#include "sdkconfig.h"

#define GATTS_TAG "GATTS_DEMO"


//CHIAVI DEL DISPOSITIVO
mbedtls_mpi N_key, P_key, Q_key, D_key, E_key, DP_key, DQ_key, QP_key; //Forse non verranno mai utilizzate
mbedtls_pk_context key_key, master_pub_key,slave_pub_key; //key_key è la chiave della esp. device_pub_key dello smartphone master
mbedtls_pk_context master_priv_key, slave_priv_key; //TODO: DA TOGLIERE, MI SERVE SOLO PER SIMULARLE LA CATENA DI CERTIFICATI
mbedtls_x509_crt self_certificate; //Self certificate della esp
mbedtls_x509_crt master_certificate; //Certificate dello smartphone master
mbedtls_x509_crt slave_certificate; //Certificate dello smartphone slave
unsigned char master_pub_key_string[] =  "-----BEGIN PUBLIC KEY-----\n"\
							    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0/ulB5uTYevMNjbPQNX0\n"\
								"k1GXNvFQDtScRDQA8StKZQ4ZBdpJKiIrlWMtRgpvmx7BJtshSHIzjAOx7EcOegCj\n"\
								"lpgG2KI/dvwaQak9PkZbyR47Uiwx+x4FOa8pM/UWurs/rkyrxXhPvUBftn8j1PQT\n"\
								"R3afl9PE0eKPTwYTEO1WbZbOCMiO3SKaNsaopuHTRcdQpjaT/nSqPGiBCEpfuw2D\n"\
								"snEkuLyh+LAALCLFvO4pXtcaXNzXz+G9h3rcb588Ebolns+ia5xVWM9oRbdXV8d+\n"\
								"uKk7HrG+t/Pk740dwfHa/cHwGqowXSxME6m7W7xfgA7HCG3OsjIY/yYDAIHu/QQM\n"\
								"hQIDAQAB\n"\
								"-----END PUBLIC KEY-----"; //TODO: Ricevere la vera chiave

unsigned char master_priv_key_string[] =  "-----BEGIN RSA PRIVATE KEY-----\n"\
							    "MIIEpAIBAAKCAQEA0/ulB5uTYevMNjbPQNX0k1GXNvFQDtScRDQA8StKZQ4ZBdpJ\n"\
								"KiIrlWMtRgpvmx7BJtshSHIzjAOx7EcOegCjlpgG2KI/dvwaQak9PkZbyR47Uiwx\n"\
								"+x4FOa8pM/UWurs/rkyrxXhPvUBftn8j1PQTR3afl9PE0eKPTwYTEO1WbZbOCMiO\n"\
								"3SKaNsaopuHTRcdQpjaT/nSqPGiBCEpfuw2DsnEkuLyh+LAALCLFvO4pXtcaXNzX\n"\
								"z+G9h3rcb588Ebolns+ia5xVWM9oRbdXV8d+uKk7HrG+t/Pk740dwfHa/cHwGqow\n"\
								"XSxME6m7W7xfgA7HCG3OsjIY/yYDAIHu/QQMhQIDAQABAoIBAQCN/LswWlOgvikd\n"\
								"kx7FJcpZNshbY80k8eHtiQusfjupboTyN6DUGOkqebCkfm787t+fYB1uAhhmyz7M\n"\
								"rVeT/oOUZiYHyr1JvFj17B76bHQkRRyk0Ld1pUkItzuY8qwTzUI9RFu1u/1lHQ4/\n"\
								"Fe/xPr7/GgSR1KW7k847tyzkJKTEZ4pZSuKH/1OVRc34F9YMUxGLWxRHcwMvfU6/\n"\
								"udDi4hSV5YLUYe5YlpKBPIeOfJPd16j5/GOrd4haF3zdecrxUOFTCsTc+zRc1s42\n"\
								"np9OE27RP9ELnfVWhJau2/za6RY9tQlUuO6Tq9hGZ6H4tQkjyZQFTWunN+sPTDvt\n"\
								"RdofLYmNAoGBAP0ih+xPvChwZpHKpRoMbEErOYNhP/Y7b5M9t3cHkXSmJWVXTD2W\n"\
								"KL5JvF8Qem/j3MYXjjyeKziLU+AVxpyXGBStzg7XPOFv7xkZFUE4+Sri4qsl8j58\n"\
								"9eJcij1Ru3es11Pd3O2Bz0OoHh/GqTtZs+dTNPD7bPvSEd0MVHzHv6NzAoGBANZh\n"\
								"39Pa+GB5ZJQSA4AxkE5N5iRgBbxVpdFp1QVay1WApu4NrAYynszIQvNX3EsHYcr0\n"\
								"2VR+5uVFTshNU8V3ixFJNM3J36thvu10I2JqBUmMr/lWteVo9A3PQYkc8KZmnvQl\n"\
								"4ZPYi08NxpyuvBuZ9Im33INu9ZMrmf5M25Cb98InAoGAMNNVRmaG04ICtsJQoDqf\n"\
								"Mt7EhCvg63zBY7Q2zBXAn7BgbDCvev2YtEOCuw9xnl1kOy1V+SlFCu4M6p8opRGb\n"\
								"ynlP0pr/mjg99Shaai80GGqU8BAsrpLp1pSk8XjvYQEMs5eKwqEUOmeWD+kAwXrm\n"\
								"8YqiHo1Qky4M1gdH0J2ywDMCgYEAxa7axnBUOCG4LRGvSLZraslKPqCMqW4QyVnd\n"\
								"pGJkvSM0yq6wwcZLyGmh0uJhsI3OD2hYPyIFp8SRMQKdDKl/AyGOH3TXWyF2/V7q\n"\
								"ggVhesDQRAtBD5oH8fP7aoPVJJvcVyXXLI2xZ+Q8EJ7PtmPwqk1weYIH0P2TsnsM\n"\
								"u/wWKmECgYBOEyb6gggg8pzO0m76v1jFdGgFWTeWiGVyvqn680BaTkl8m9Y8VSCr\n"\
								"vbBDrQdxyXybY1xDVcp5baTTCqBt5ADLHyoipDvT/4SM+jdYp2kM/xgHhupVKYwL\n"\
								"3BONrGy2mLSWFlyF+4C2CdJZM594bBmsrO3bsZni8Z5UhPRkfPkh1g==\n"\
								"-----END RSA PRIVATE KEY-----"; //TODO: Ricevere la vera chiave

unsigned char slave_pub_key_string[] =  "-----BEGIN PUBLIC KEY-----\n"\
							    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhGCqrEfcr4mdhJKqYqDb\n"\
								"Ele6K2hAzShC4NQQb0HTbprIRnQ/5b2FPcU0Rwu+EE6ntuKUvttRCPmdXFR3yrg3\n"\
							    "uPBedwDnBIOaQbH0CEliDu2I1hqsZTCfasdcwtRwNeqtljjQ4Zdn9HQXHJxs/ST9\n"\
								"1k9r2LGWwg8mZJ9CtF+rplFHCH0OhnCIWqqj0XWxh9EsplskfjWwo0vRnyZl9Bp2\n"\
							    "XVBtUhIhgZeeKMoPNodzCXhCZgcZKZB2wMkwJiPbfH/B1PApUvo8YQcUDrDOhwGp\n"\
								"jJfjR9GwQ1ehQgNb2Wk/Fk1GY3Zl363EzDMd79Xaofm2fwW6vG8dZm7agHJrg6km\n"\
							    "4QIDAQAB\n"\
								"-----END PUBLIC KEY-----"; //TODO: Ricevere la vera chiave

unsigned char slave_priv_key_string[] =  "-----BEGIN RSA PRIVATE KEY-----\n"\
							    "MIIEpAIBAAKCAQEAhGCqrEfcr4mdhJKqYqDbEle6K2hAzShC4NQQb0HTbprIRnQ/\n"\
							    "5b2FPcU0Rwu+EE6ntuKUvttRCPmdXFR3yrg3uPBedwDnBIOaQbH0CEliDu2I1hqs\n"\
								"ZTCfasdcwtRwNeqtljjQ4Zdn9HQXHJxs/ST91k9r2LGWwg8mZJ9CtF+rplFHCH0O\n"\
							    "hnCIWqqj0XWxh9EsplskfjWwo0vRnyZl9Bp2XVBtUhIhgZeeKMoPNodzCXhCZgcZ\n"\
								"KZB2wMkwJiPbfH/B1PApUvo8YQcUDrDOhwGpjJfjR9GwQ1ehQgNb2Wk/Fk1GY3Zl\n"\
							    "363EzDMd79Xaofm2fwW6vG8dZm7agHJrg6km4QIDAQABAoIBAAbRs/kL+qJQRHz/\n"\
								"0ScjgiV/v2ddB3mKCWfrhK02ht27u3Vlp6T+Dk8QSZEfWbsdUiZppZ/vTE1aDnEj\n"\
							    "KMiYlMZCG5ulwEDLRrb7o8aJgTOjqNjepuLPjmbBvlWK+/zLCgYjBx+X3RMKp+Yh\n"\
								"aLvhm/HeRX/0Jf/5J9EnIxiHlSAMHLPSRyISERHUl0zoDRDLrL2iPvL7GcH9JXcr\n"\
							    "8dLeCkdQ97ey8TRPgJcSK9P919547s7KeeUkgPQpDHY47FQWqq7rm/MijtBH229j\n"\
								"osaPqtCA1FCA8cftMGPrPvlny+LbaTzH8C3CaZf3CWPTOdL8y6Y+RRlabrsLjgtn\n"\
							    "5T3jcAECgYEAzwMh0x84qbxWVCdpkERB+rtA14m6u/BTIiGQ6MTPMYCJ/zSFMOrs\n"\
								"JcJcw1F/KD5VjT074P8+OTAoR24ViXsqNojCD754PYxgh0ZEvFstaEGDNPMu7PtA\n"\
							    "km5Gj+upMKjQnVq9mnxzPcOfHb+ln+QFWkqTxrS2OS5Db+eXLlsvfVECgYEAo7Ql\n"\
								"BHnu1dR/S+kvxZkJ7A5dSiHSjwFPecd8ip7s2bA+nf0ye5CMxFZx7gFq4YS0gZ3G\n"\
							    "68IZ98Bmn/pgoRgovwtmTKH3iO2fmF25jl1jUQ2IyiJ+MQQ5nLIYySZCsDKyVx+v\n"\
								"UaDorkjVaiHiwig4aBttdA8JkU06f+h7V2lVbJECgYEAsvTjNc7kvh85hhB4OqY3\n"\
							    "X5inKm0/R58vTu8zhXY2I3YaVcvCZJKByPaoGJWIVnLkpG/OJuigkvGlsHJjHfGi\n"\
								"gXhiQxgGfDaxb9/4JdiwfVM9KPYdl/JwVOYOC/bO0Wjux0kdZcK2ISvOjvoRJRMK\n"\
							    "6Y5VB89LRE1RMRlE4Wcku7ECgYEAggy627OCaZ1HA6dcrD3IBB/lPN9hxvnjiXtR\n"\
								"FU7sGoRJOnnLgR50tgV2vP2jS0WBoPcW8HRi7M+Mt8rQuSnYNO15d6e0XrNn9kN/\n"\
							    "BfpqzBlUckC0v3v7yOAzkJk0oYWk6FHjlZWfQ9XYtVf2LQiGxy4C5hCMKUKRFsw6\n"\
								"MFcd5gECgYADC1PZEnGuGDssFFoLL6fC6QdY7BGQbkiffmHRXqM0kzZioc/od5kX\n"\
							    "MWgsI/f1pwoDydVGEegldWHdY/X6EeGB1n9JFPO7XJR/VdOuWUeSUiVIaJW9ROmG\n"\
								"Eu90pcvHiqpfvpbf2950NP0eyUlUvjCeRewspt5buxwo4jKWfVEjbA==\n"\
								"-----END RSA PRIVATE KEY-----"; //TODO: Ricevere la vera chiave

char rand_challenge_str[] =  "una stringa da generare random";
unsigned char rand_challenge_firmato[MBEDTLS_MPI_MAX_SIZE];

bool wait_cert_app_master;
bool wait_cert_app_slave;
bool master_cert_validity, slave_cert_validity;


void ritardo(int secondi){
	for(;secondi>0;secondi--){
		vTaskDelay(1000 / portTICK_PERIOD_MS);
		printf("\nParto tra %d secondi",secondi);
		fflush(stdout);
	}
}

void print_available_ram(){
    uint freeRAM = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
	printf("\n\n ---> FREE RAM IS: %d.\n\n", freeRAM);
	fflush(stdout);
}

bool carica_chiavi(){
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
    printf("\n -> Opening Non-Volatile Storage (NVS) handle... ");
    nvs_handle my_handle;
    err = nvs_open("stored_keys", NVS_READONLY, &my_handle);
    if (err != ESP_OK) {
        printf("\n   -> Error (%s) opening NVS handle!\n", esp_err_to_name(err));
        return false;
    } else {
        printf("\n   -> File Aperto con successo.");
        // Read
        size_t n_N,n_E,n_D,n_P,n_Q,n_DP,n_DQ,n_QP,n_key;
        //Mi interessa solo la dimensione per poter creare array dinamici //TODO: sistemare il return, se fallisce qualcosa deve ritornare false
        printf("\n -> Verifico che tutte le chiavi siano in memoria..");
        err = nvs_get_str(my_handle, "N", NULL, &n_N); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "E", NULL, &n_E); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "D", NULL, &n_D); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "P", NULL, &n_P); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "Q", NULL, &n_Q); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "DP", NULL, &n_DP); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "DQ", NULL, &n_DQ); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "QP", NULL, &n_QP); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "KEY", NULL, &n_key); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
        char* N_string=pvPortMalloc(n_N);
        char* E_string=pvPortMalloc(n_E);
		char* D_string=pvPortMalloc(n_D);
		char* P_string=pvPortMalloc(n_P);
		char* Q_string=pvPortMalloc(n_Q);
		char* DP_string=pvPortMalloc(n_DP);
		char* DQ_string=pvPortMalloc(n_DQ);
		char* QP_string=pvPortMalloc(n_QP);
		char* key_string=pvPortMalloc(n_key);
		//Leggo effettivamente il valore
		printf("\n -> Carico le chiavi in formato string");
		err = nvs_get_str(my_handle, "N", N_string, &n_N); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "E", E_string, &n_E); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "D", D_string, &n_D); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "P", P_string, &n_P); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "Q", Q_string, &n_Q); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "DP", DP_string, &n_DP); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "DQ", DQ_string, &n_DQ); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "QP", QP_string, &n_QP); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "KEY", key_string, &n_key); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");

		//Stampo le chiavi a video
		printf("\n\n\t ----- STAMPO LE CHIAVI -----\n");
		printf("\nLA N CARICATA VALE (string): %s\n",N_string);
		printf("\nLA E CARICATA VALE (string) : %s\n",E_string);
		printf("\nLA D CARICATA VALE (string) : %s\n",D_string);
		printf("\nLA P CARICATA VALE (string) : %s\n",P_string);
		printf("\nLA Q CARICATA VALE (string) : %s\n",Q_string);
		printf("\nLA DP CARICATA VALE (string) : %s\n",DP_string);
		printf("\nLA DQ CARICATA VALE (string) : %s\n",DQ_string);
		printf("\nLA QP CARICATA VALE (string) : %s\n",QP_string);
		printf("\n----- CHIAVE PRIVATA DELLA ESP32 -----\n%s\n",key_string);
        // Close
        nvs_close(my_handle);
        printf("\n -> File chiuso.");
        printf("\n -> Converto le chiavi da STRING a MPI.");
        //Converto da STRINGA ad MPI
        //N_key, P_key, Q_key, D_key, E_key, DP_key, DQ_key, QP_key;
        int error;
        error = mbedtls_mpi_read_string(&N_key,16,N_string); printf((error != 0) ? "\n   -> Conversion to MPI Failed!" : "\n   -> Conversion to MPI Done");
        error = mbedtls_mpi_read_string(&E_key,16,E_string); printf((error != 0) ? "\n   -> Conversion to MPI Failed!" : "\n   -> Conversion to MPI Done");
        error = mbedtls_mpi_read_string(&D_key,16,D_string); printf((error != 0) ? "\n   -> Conversion to MPI Failed!" : "\n   -> Conversion to MPI Done");
        error = mbedtls_mpi_read_string(&P_key,16,P_string); printf((error != 0) ? "\n   -> Conversion to MPI Failed!" : "\n   -> Conversion to MPI Done");
        error = mbedtls_mpi_read_string(&Q_key,16,Q_string); printf((error != 0) ? "\n   -> Conversion to MPI Failed!" : "\n   -> Conversion to MPI Done");
        error = mbedtls_mpi_read_string(&DP_key,16,DP_string); printf((error != 0) ? "\n   -> Conversion to MPI Failed!" : "\n   -> Conversion to MPI Done");
        error = mbedtls_mpi_read_string(&DQ_key,16,DQ_string); printf((error != 0) ? "\n   -> Conversion to MPI Failed!" : "\n   -> Conversion to MPI Done");
        error = mbedtls_mpi_read_string(&QP_key,16,QP_string); printf((error != 0) ? "\n   -> Conversion to MPI Failed!" : "\n   -> Conversion to MPI Done");
        mbedtls_pk_init(&key_key);
        printf("\n -> Converto le chiavi da STRING a PK.");
        error = mbedtls_pk_parse_key( &key_key, (unsigned char*)key_string, n_key,NULL,0);
        if(error!=0){
        	printf("\n   -> Conversion to PK Failed!");
        	return false;
        }
        else{
        	printf("\n   -> Conversion to PK Done");
            printf("\n\n\t ----- ESTRAGGO LA CHIAVE PUBBLICA DA QUELLA PRIVATA -----\n");
            unsigned char output_buf[1800];
            //size_t len = 0;
            memset(output_buf, 0, 1800);
    		if( mbedtls_pk_write_pubkey_pem( &key_key, output_buf, 1800 ) != 0 ){
    			printf("\n -> Estrazione fallita.");
    			return false;
    		}
            //len = strlen( (char *) output_buf );
            //printf("\n\nLunghezza Chiave Pubblica: %d",len);
            printf("\n----- CHIAVE PUBBLICA DELLA ESP32 -----\n%s",output_buf);
        }


        //TODO: DA TOGLIERE: EMULO LE CHIAVI PRIVATE E PUBBLICHE! begin
    	printf("\n\n------------------------------------------------------------------------------------------\n");
    	printf("\n\t ----- MI INVENTO DELLE CHIAVI PRIVATE E PUBBLICHE PER MASTER E SLAVE -----\n");
        mbedtls_pk_init(&master_pub_key);
        mbedtls_pk_init(&master_priv_key);
        mbedtls_pk_init(&slave_pub_key);
        mbedtls_pk_init(&slave_priv_key);
        //printf("\n La pub_key pem vale: %s",master_pub_key_string);
        //printf("\n La sua lunghezza vale: %d\n",lung);
        fflush( stdout );
        printf("\n -> Converto le chiavi da STRING a PK.");
        error = mbedtls_pk_parse_public_key( &master_pub_key, (unsigned char*)master_pub_key_string, sizeof(master_pub_key_string)); printf((error != 0) ? "\n   -> Conversion to PK Failed!" : "\n   -> Conversion to PK Done");
        error = mbedtls_pk_parse_key( &master_priv_key, (unsigned char*)master_priv_key_string, sizeof(master_priv_key_string),NULL,0); printf((error != 0) ? "\n   -> Conversion to PK Failed!" : "\n   -> Conversion to PK Done");
        error = mbedtls_pk_parse_public_key( &slave_pub_key, (unsigned char*)slave_pub_key_string, sizeof(slave_pub_key_string)); printf((error != 0) ? "\n   -> Conversion to PK Failed!" : "\n   -> Conversion to PK Done");
        error = mbedtls_pk_parse_key( &slave_priv_key, (unsigned char*)slave_priv_key_string, sizeof(slave_priv_key_string),NULL,0); printf((error != 0) ? "\n   -> Conversion to PK Failed!" : "\n   -> Conversion to PK Done");
        printf("\n -> Verifico la coppia chiave pubblica/privata di master e slave");
        error = mbedtls_pk_check_pair(&master_pub_key, &master_priv_key); printf((error != 0) ? "\n   -> Coppia chiave privata/pubblica NON VALIDA" : "\n   -> Coppia chiave privata/pubblica OK");
        error = mbedtls_pk_check_pair(&slave_pub_key, &slave_priv_key); printf((error != 0) ? "\n   -> Coppia chiave privata/pubblica NON VALIDA" : "\n   -> Coppia chiave privata/pubblica OK");
        //TODO: DA TOGLIERE: EMULO LE CHIAVI PRIVATE E PUBBLICHE! end


        //LIBERO LA MEMORIA
        vPortFree(N_string); vPortFree(E_string); vPortFree(D_string);
        vPortFree(P_string); vPortFree(Q_string); vPortFree(DP_string);
        vPortFree(DQ_string); vPortFree(QP_string); vPortFree(key_string);

    }
    return true;
}

bool cancella_tutto(){
    // Initialize NVS
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // NVS partition was truncated and needs to be erased. Retry nvs_flash_init
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK( err );

    //printf("\nOpening Non-Volatile Storage (NVS) handle... ");
    nvs_handle my_handle;
    err = nvs_open("stored_keys", NVS_READONLY, &my_handle);
    if (err != ESP_OK) {
        //printf("\nError (%s) opening NVS handle!\n", esp_err_to_name(err));
    	printf("\n -> Non c'è niente da cancellare, il file non esiste.");
        nvs_close(my_handle);
        return false;
    }
    ESP_ERROR_CHECK(nvs_flash_erase());
    ESP_ERROR_CHECK(nvs_flash_init());
    return true;
}

void print_date_time(){
	printf("\n\ntime - begin");
	time_t now;
	struct tm timeinfo;
	time(&now);
	char strftime_buf[64];
	tzset();
	localtime_r(&now, &timeinfo);
	strftime(strftime_buf, sizeof(strftime_buf), "%c", &timeinfo);
	printf("\n -> The current date/time is: %s", strftime_buf);
	printf("\ntime - end\n\n");
}
void print_all_certificates(){
	printf("\n\n\t ----- PRINTO TUTTI I CERTIFICATI ----- \n\n");

	unsigned char buf[1024];
	int ret2;
    mbedtls_printf( "  . Peer certificate information    ...\n" );
    ret2 = mbedtls_x509_crt_info( (char *) buf, sizeof( buf ) - 1, "      ", &self_certificate );
    if( ret2 == -1 )
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_info returned %d\n\n", ret2 );
    printf( "\nSELF CERT:\n%s\n", buf );
    ret2 = mbedtls_x509_crt_info( (char *) buf, sizeof( buf ) - 1, "      ", &master_certificate );
    if( ret2 == -1 )
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_info returned %d\n\n", ret2 );
    printf( "\nMASTER CERT:\n%s\n", buf );
    ret2 = mbedtls_x509_crt_info( (char *) buf, sizeof( buf ) - 1, "      ", &slave_certificate );
    if( ret2 == -1 )
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_info returned %d\n\n", ret2 );
    printf( "\nSLAVE CERT:\n%s\n", buf );
}

bool verifica_certificati(){
	master_cert_validity = false;
	slave_cert_validity = false;

	//print_all_certificates();
	wait_cert_app_master=true;
	xTaskCreate(cert_app_master_certificate,"CertAppMaster",8000,NULL,3,NULL);
	printf("\n -> Attendi, verifica del Master Certificate..\n");
	while(wait_cert_app_master){
		vTaskDelay(100 / portTICK_PERIOD_MS);
	}

	vTaskDelay(100 / portTICK_PERIOD_MS);
	//print_all_certificates();
	wait_cert_app_slave=true;
	xTaskCreate(cert_app_slave_certificate,"CertAppSlave",8000,NULL,3,NULL);
	printf("\n -> Attendi, verifica dello Slave Certificate..\n");
	while(wait_cert_app_slave){
		vTaskDelay(100 / portTICK_PERIOD_MS);
	}
	return master_cert_validity & slave_cert_validity; //TODO: sistemare
}

void ble_init(){
    esp_err_t ret;
    // Initialize NVS. (Non-volatile storage)
    ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK( ret );

    ESP_ERROR_CHECK(esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT));

    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ret = esp_bt_controller_init(&bt_cfg);
    if (ret) {
        ESP_LOGE(GATTS_TAG, "%s initialize controller failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }

    ret = esp_bt_controller_enable(ESP_BT_MODE_BLE); //Bluetooth parte in modalità solo BLE. ESP_BT_MODE_BTDM: Dual mode (BLE + BT Classic)
    if (ret) {
        ESP_LOGE(GATTS_TAG, "%s enable controller failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }
    ret = esp_bluedroid_init();
    if (ret) {
        ESP_LOGE(GATTS_TAG, "%s init bluetooth failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }
    ret = esp_bluedroid_enable();
    if (ret) {
        ESP_LOGE(GATTS_TAG, "%s enable bluetooth failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }

    ret = esp_ble_gatts_register_callback(gatts_event_handler);
    if (ret){
        ESP_LOGE(GATTS_TAG, "gatts register error, error code = %x", ret);
        return;
    }
    ret = esp_ble_gap_register_callback(gap_event_handler);
    if (ret){
        ESP_LOGE(GATTS_TAG, "gap register error, error code = %x", ret);
        return;
    }

    gaps_init();

    ret = esp_ble_gatts_app_register(0);
    if (ret){
        ESP_LOGE(GATTS_TAG, "gatts app register error, error code = %x", ret);
        return;
    }

    vTaskDelay(1000 / portTICK_PERIOD_MS);
    printf("\nREGISTRO APP 1\n");
    ret = esp_ble_gatts_app_register(1);
    if (ret){
        ESP_LOGE(GATTS_TAG, "gatts app register error, error code = %x", ret);
        return;
    }
    printf("\nFINE REGISTRAZIONE APP 1\n");
    esp_err_t local_mtu_ret = esp_ble_gatt_set_local_mtu(500);
    if (local_mtu_ret){
        ESP_LOGE(GATTS_TAG, "set local  MTU failed, error code = %x", local_mtu_ret);
    }
}

void app_main()
{
	print_available_ram();
	print_date_time();
	ritardo(5); //TODO: debug. da cancellare
	/*if(cancella_tutto()){
		printf("\n\t\t --- HO CANCELLATO TUTTO --- \n");
		for(int i=10;i>0;i--){
			vTaskDelay(1000 / portTICK_PERIOD_MS);
			printf("\nRestart in %d seconds",i);
		}
		esp_restart();
	}
	else
		printf("\n\t\t --- CANCELLAZIONE FALLITA --- \n");
	ritardo(5); //TODO: debug. da cancellare*/

	/*wait_key_gen=true;
	xTaskCreate(genera_chiave,"GeneraChiave",64768,NULL,2,NULL);
	printf("\nAttendo.");
	while(wait_key_gen){
		printf(".");
		vTaskDelay(100 / portTICK_PERIOD_MS);
	}*/

	printf("\n\n------------------------------------------------------------------------------------------\n");

	/*printf("\n\t ----- TENTO DI CARICARE LE CHIAVI DALLA NVS -----\n");
	if(carica_chiavi())
		printf("\n -> Chiavi caricate con successo \n");
	else{
		printf("\n -> Chiavi non trovate.\n");
		printf("\n\t ----- GENERO LA COPPIA CHIAVE PUBBLICA E PRIVATA ----- \n");
		wait_key_gen=true;
		xTaskCreate(genera_chiave,"GeneraChiave",64768,NULL,2,NULL);
		printf("\n -> Attendo..\n");
		while(wait_key_gen){
			//printf(".");
			vTaskDelay(100 / portTICK_PERIOD_MS);
		}
		printf("\n\t ----- CARICO LE CHIAVI DALLA MEMORIA ----- \n\t(per verificare la corretta scrittura delle chiavi in memoria)");
		if(carica_chiavi()){
			printf("\n -> Chiavi generate, salvate e ricaricate con successo\n");
		}
		else{
			printf("\n -> Ho creato le chiavi, ho tentato di salvarle, e non sono riuscito a ricaricarle. Qualcosa è andato storto..\n");
			printf("\n   ----- RIAVVIO LA ESP -----\n");
			for(int i=8;i>0;i--){
				vTaskDelay(1000 / portTICK_PERIOD_MS);
				printf("\n<Restart in %d seconds>",i);
				fflush(stdout);
			}
			esp_restart();
		}
	}

	printf("\n\n----------------------------------------------------------------------\n");
	print_available_ram();
	//GENERA SELF CERTIFICATE
	printf("\n\n\t --- GENERA SELF CERTIFICATE --- \n\n");
	wait_self_cert_generation=true;
	xTaskCreate(selfsigned_cert_write,"GeneraSelfCert",32768,NULL,2,NULL);
	printf("\n -> Attendo..\n");
	do{
		//printf(".");
		vTaskDelay(100 / portTICK_PERIOD_MS);
	}while(wait_self_cert_generation);

	printf("\n\n----------------------------------------------------------------------\n");
	print_available_ram();
	//MASTER CERT WRITE
	printf("\n\n\t --- GENERA MASTER CERT WRITE --- \n\n");
	wait_master_cert_write=true;
	xTaskCreate(master_cert_write,"MasterCertWrite",32768,NULL,2,NULL);
	printf("\n -> Attendo..\n");
	do{
		//printf(".");
		vTaskDelay(100 / portTICK_PERIOD_MS);
	}while(wait_master_cert_write);

	printf("\n\n----------------------------------------------------------------------\n");
	print_available_ram();
	//SLAVE CERT WRITE
	printf("\n\n\t --- GENERA SLAVE CERT WRITE --- \n\n");
	wait_slave_cert_write=true;
	xTaskCreate(slave_cert_write,"SlaveCertWrite",32768,NULL,2,NULL);
	printf("\n -> Attendo..\n");
	do{
		//printf(".");
		vTaskDelay(100 / portTICK_PERIOD_MS);
	}while(wait_slave_cert_write);

	printf("\n\n----------------------------------------------------------------------\n");
	print_available_ram();
	//VERIFICO LA CATENA.
	//print_all_certificates();

    printf("\n\n----------------------------------------------------------------------\n");

	//VERIFICO LA CATENA.
	printf("\n\n\t ----- VERIFICO CERTIFICATI ----- \n\n");
    if(!verifica_certificati()){
    	printf("\n -> I certificati non sono stati approvati.");
    }
    else{
    	printf("\n -> I certificati sono stati approvati.");
    	printf("\n\n----------------------------------------------------------------------\n");
    	printf("\n\n\t ----- RANDOM CHALLENGE ----- \n\n");
    	printf("\n -> Avvio il Random Challenge");
    	if(random_challenge_sign()==0){
    		printf("\n -> random firmato.");
    		printf("\n -> Ora verifico la firma");
    		if(random_challenge_verify()==0){
    			printf("\n -> Firma del random challenge verificata.");
    			printf("\n\n\n------------------------------------------------------------------------------------------------\n"\
    					"------------------------------------------------------------------------------------------------\n"\
						"-------------------------------------------APRO LA PORTA----------------------------------------\n"\
						"------------------------------------------------------------------------------------------------\n"\
						"------------------------------------------------------------------------------------------------\n\n\n");
    		}
    		else{
    			printf("\n -> Firma del random non verificata.");
    		}
    	}
    	else{
    		printf("\n -> Firma del random fallita.");
    	}
    }*/

	printf("\n\n----------------------------------------------------------------------\n");
	print_available_ram();
	printf("\n\t --- AVVIO IL BLUETOOTH E TUTTI I SERVIZI ASSOCIATI --- \n");
	ble_init();
	fflush(stdout);
	printf("\nFINE DEL MAIN.");
    //printf("\nHO LANCIATO TUTTI I SERVIZI, PRESTO SARANNO DISPONIBILI");
    return;
}
