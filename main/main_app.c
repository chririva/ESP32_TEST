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
//mbedtls
#include "mbedtls/platform.h"
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/rsa.h"
#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/rsa.h"
#include "mbedtls/bignum.h"

#include "main_app.h"
#include "genera_chiave.h"
#include "selfsigned_cert_write.h"
#include "master_cert_write.h"
#include "slave_cert_write_DEBUG_TEST.h"
#include "random_challenge_sign_TEST.h"
#include "random_challenge_verify.h"
#include "cert_app.h"
#include "ble_state_machine.h"

#include "esp_bt.h"
#include "esp_gap_ble_api.h"
#include "esp_gatts_api.h"
#include "esp_bt_defs.h"
#include "esp_bt_main.h"
#include "esp_gatt_common_api.h"
#include "ble_server.h"
#include "ble_config.h"

#include "sdkconfig.h"

bool MASTER_MODE = false;

//CHIAVI DEL DISPOSITIVO
//mbedtls_mpi N_key, P_key, Q_key, D_key, E_key, DP_key, DQ_key, QP_key; //Forse non verranno mai utilizzate
mbedtls_pk_context key_key, master_pub_key,slave_pub_key; //key_key è la chiave della esp. device_pub_key dello smartphone master
//mbedtls_pk_context master_priv_key, slave_priv_key;
mbedtls_x509_crt self_certificate; //Self certificate della esp
mbedtls_x509_crt master_certificate; //Certificate dello smartphone master
mbedtls_x509_crt slave_certificate; //Certificate dello smartphone slave
/*unsigned char master_pub_key_string[] =  "-----BEGIN PUBLIC KEY-----\n"\
							    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0/ulB5uTYevMNjbPQNX0\n"\
								"k1GXNvFQDtScRDQA8StKZQ4ZBdpJKiIrlWMtRgpvmx7BJtshSHIzjAOx7EcOegCj\n"\
								"lpgG2KI/dvwaQak9PkZbyR47Uiwx+x4FOa8pM/UWurs/rkyrxXhPvUBftn8j1PQT\n"\
								"R3afl9PE0eKPTwYTEO1WbZbOCMiO3SKaNsaopuHTRcdQpjaT/nSqPGiBCEpfuw2D\n"\
								"snEkuLyh+LAALCLFvO4pXtcaXNzXz+G9h3rcb588Ebolns+ia5xVWM9oRbdXV8d+\n"\
								"uKk7HrG+t/Pk740dwfHa/cHwGqowXSxME6m7W7xfgA7HCG3OsjIY/yYDAIHu/QQM\n"\
								"hQIDAQAB\n"\
								"-----END PUBLIC KEY-----";

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
								"-----END RSA PRIVATE KEY-----";

unsigned char slave_pub_key_string[] =  "-----BEGIN PUBLIC KEY-----\n"\
							    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhGCqrEfcr4mdhJKqYqDb\n"\
								"Ele6K2hAzShC4NQQb0HTbprIRnQ/5b2FPcU0Rwu+EE6ntuKUvttRCPmdXFR3yrg3\n"\
							    "uPBedwDnBIOaQbH0CEliDu2I1hqsZTCfasdcwtRwNeqtljjQ4Zdn9HQXHJxs/ST9\n"\
								"1k9r2LGWwg8mZJ9CtF+rplFHCH0OhnCIWqqj0XWxh9EsplskfjWwo0vRnyZl9Bp2\n"\
							    "XVBtUhIhgZeeKMoPNodzCXhCZgcZKZB2wMkwJiPbfH/B1PApUvo8YQcUDrDOhwGp\n"\
								"jJfjR9GwQ1ehQgNb2Wk/Fk1GY3Zl363EzDMd79Xaofm2fwW6vG8dZm7agHJrg6km\n"\
							    "4QIDAQAB\n"\
								"-----END PUBLIC KEY-----";

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
								"-----END RSA PRIVATE KEY-----";*/

char rand_challenge_str[GATTS_CHAR_RND_LEN_MAX] =  "una stringa da generare random";
unsigned char rand_challenge_firmato[MBEDTLS_MPI_MAX_SIZE];

bool wait_key_gen;
bool wait_self_cert_generation;
bool wait_cert_app_master;
bool wait_cert_app_slave;
bool master_cert_validity, slave_cert_validity;
bool charateristic_flags[16];

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
	bool exit_code=true;
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
        size_t n_key;
        //Mi interessa solo la dimensione per poter creare array dinamici
        printf("\n -> Verifico che tutte le chiavi siano in memoria..");
        if(nvs_get_str(my_handle, "KEY", NULL, &n_key)!=ESP_OK){
        	printf("\n     -> Failed!");
        	return false;
        }
        printf("\n     -> Done");
		char* key_string=pvPortMalloc(n_key);
		//Leggo effettivamente il valore
		printf("\n -> Carico le chiavi in formato string");
        if(nvs_get_str(my_handle, "KEY", key_string, &n_key)!=ESP_OK){
        	printf("\n     -> Failed!");
        	exit_code = false;
        	goto exit;
        }
		// Close
        nvs_close(my_handle);
        printf("\n -> File chiuso.");

        mbedtls_pk_init(&key_key);
        printf("\n -> Converto le chiavi da STRING a PK.");
        if(mbedtls_pk_parse_key( &key_key, (unsigned char*)key_string, n_key,NULL,0)!=0){
        	printf("\n   -> Conversion to PK Failed!");
			exit_code=false;
			goto exit;
        }
        else{
        	printf("\n   -> Conversion to PK Done");
            printf("\n -> Estraggo la chiave pubblica da quella privata..");
            unsigned char output_buf[1800];
            //size_t len = 0;
            memset(output_buf, 0, 1800);
    		if( mbedtls_pk_write_pubkey_pem( &key_key, output_buf, 1800 ) != 0 ){
    			printf("\n   -> Estrazione fallita.");
    			exit_code=false;
    			goto exit;
    		}
    		else
    			printf("\n   -> Estrazione completata.");
            //len = strlen( (char *) output_buf );
            //printf("\n\nLunghezza Chiave Pubblica: %d",len);
    		//Stampo le chiavi a video
    		printf("\n\n\t ----- STAMPO LE CHIAVI -----\n");
    		printf("\n\t\t----- CHIAVE PRIVATA DELLA ESP32 -----\n%s\n",key_string);
            printf("\n\t\t----- CHIAVE PUBBLICA DELLA ESP32 -----\n%s",output_buf);
        }

        //TODO: DA TOGLIERE: EMULO LE CHIAVI PRIVATE E PUBBLICHE! begin
    	/*
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
        */
        //TODO: DA TOGLIERE: EMULO LE CHIAVI PRIVATE E PUBBLICHE! end

        exit:
        //LIBERO LA MEMORIA
        vPortFree(key_string);

    }
    return exit_code;
}

bool master_phone_exists(){
	bool exit_code=true;
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
    err = nvs_open("stored_master", NVS_READONLY, &my_handle);
    if (err != ESP_OK) {
        printf("\n   -> Error (%s) opening NVS handle!\n", esp_err_to_name(err));
        return false;
    } else {
        printf("\n   -> File Aperto con successo.");
        // Read
        size_t n_key, n_cert;
        //Mi interessa solo la dimensione per poter creare array dinamici
        printf("\n -> Verifico che tutte le chiavi siano in memoria..");
        if(nvs_get_str(my_handle, "MPKey", NULL, &n_key)!=ESP_OK){
        	printf("\n     -> Failed!");
        	return false;
        }
        if(nvs_get_str(my_handle, "MCert", NULL, &n_cert)!=ESP_OK){
        	printf("\n     -> Failed!");
        	return false;
        }
        printf("\n     -> Done");
		char* key_string=pvPortMalloc(n_key);
		char* cert_string=pvPortMalloc(n_cert);
		//Leggo effettivamente il valore
		printf("\n -> Carico la chiave in formato string");
        if(nvs_get_str(my_handle, "MPKey", key_string, &n_key)!=ESP_OK){
        	printf("\n     -> Failed!");
        	exit_code = false;
        	goto exit;
        }
		printf("\n -> Carico il certificato in formato string");
        if(nvs_get_str(my_handle, "MCert", cert_string, &n_cert)!=ESP_OK){
        	printf("\n     -> Failed!");
        	exit_code = false;
        	goto exit;
        }
		// Close
        nvs_close(my_handle);
        printf("\n -> File chiuso.");

        //Verifico validità di chiave pubblica e certificato master
        printf("\n -> Ora verifico che siano validi!");
        mbedtls_pk_context m_pub_key;
        mbedtls_pk_init(&m_pub_key);

        //
        printf("\nKEY_STRING:\n%s\n",key_string);
        printf("\nCERT_STRING:\n%s\n",cert_string);
        ///

        if(mbedtls_pk_parse_public_key( &m_pub_key, (unsigned char*)key_string, n_key)==0){
        	printf("\n   -> Master PKey valida");
        }else{
        	printf("\n   -> Master PKey non valida");
			exit_code=false;
			goto exit;
        }
        mbedtls_x509_crt m_cert;
		if(mbedtls_x509_crt_parse(&m_cert, (unsigned char*)cert_string, n_cert)== 0 ){
			printf("\n   -> Master Cert valido.");
		}else{
			printf("\n   -> Master Cert non valido");
			exit_code=false;
			goto exit;
		}

        exit:
        //LIBERO LA MEMORIA
        vPortFree(key_string);
        vPortFree(cert_string);

    }
    return exit_code;
}

/* Per eliminare chiave pubblica e privata della ESP32 dalla memoria
 */
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

/* Per eliminare il master dalla memoria
 */
bool elimina_master(){
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
    err = nvs_open("stored_master", NVS_READWRITE, &my_handle);
    err = nvs_erase_all(my_handle);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Error (%s) nvs_erase_all!", esp_err_to_name(err));
    }
    else
    {
        ESP_LOGI(TAG, "nvs_erase_all success");
        //commit changes
        err = nvs_commit(my_handle);
        if (err != ESP_OK)
        {
            ESP_LOGE(TAG, "Error (%s) nvs_commit!", esp_err_to_name(err));
        }
        else
        {
            ESP_LOGI(TAG, "nvs_commit success");
        }
    }
    //close NVS page
    nvs_close(my_handle);


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
    ret = esp_ble_gatts_app_register(1);
    if (ret){
        ESP_LOGE(GATTS_TAG, "gatts app register error, error code = %x", ret);
        return;
    }

    esp_err_t local_mtu_ret = esp_ble_gatt_set_local_mtu(500);
    if (local_mtu_ret){
        ESP_LOGE(GATTS_TAG, "set local  MTU failed, error code = %x", local_mtu_ret);
    }
}

void security_init(){
	/* set the security iocap & auth_req & key size & init key response key parameters to the stack*/
	esp_ble_auth_req_t auth_req = ESP_LE_AUTH_REQ_SC_MITM_BOND;     //bonding with peer device after authentication
	esp_ble_io_cap_t iocap = ESP_IO_CAP_NONE;           //set the IO capability to No output No input
	uint8_t key_size = 16;      //the key size should be 7~16 bytes
	uint8_t init_key = ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK;
	uint8_t rsp_key = ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK;
	//set static passkey
	uint32_t passkey = 123456;
	uint8_t auth_option = ESP_BLE_ONLY_ACCEPT_SPECIFIED_AUTH_DISABLE;
	uint8_t oob_support = ESP_BLE_OOB_DISABLE;
	esp_ble_gap_set_security_param(ESP_BLE_SM_SET_STATIC_PASSKEY, &passkey, sizeof(uint32_t));
	esp_ble_gap_set_security_param(ESP_BLE_SM_AUTHEN_REQ_MODE, &auth_req, sizeof(uint8_t));
	esp_ble_gap_set_security_param(ESP_BLE_SM_IOCAP_MODE, &iocap, sizeof(uint8_t));
	esp_ble_gap_set_security_param(ESP_BLE_SM_MAX_KEY_SIZE, &key_size, sizeof(uint8_t));
	esp_ble_gap_set_security_param(ESP_BLE_SM_ONLY_ACCEPT_SPECIFIED_SEC_AUTH, &auth_option, sizeof(uint8_t));
	esp_ble_gap_set_security_param(ESP_BLE_SM_OOB_SUPPORT, &oob_support, sizeof(uint8_t));
	/* If your BLE device acts as a Slave, the init_key means you hope which types of key of the master should distribute to you,
	and the response key means which key you can distribute to the master;
	If your BLE device acts as a master, the response key means you hope which types of key of the slave should distribute to you,
	and the init key means which key you can distribute to the slave. */
	esp_ble_gap_set_security_param(ESP_BLE_SM_SET_INIT_KEY, &init_key, sizeof(uint8_t));
	esp_ble_gap_set_security_param(ESP_BLE_SM_SET_RSP_KEY, &rsp_key, sizeof(uint8_t));

	/* Just show how to clear all the bonded devices
	 * Delay 30s, clear all the bonded devices
	 *
	 * vTaskDelay(30000 / portTICK_PERIOD_MS);
	 * remove_all_bonded_devices();
	 */

}

void app_main()
{
	print_available_ram();
	print_date_time();
	//fgetc(stdin);
	ritardo(5);
	//elimina_master();
	//ritardo(5);
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
	ritardo(5); */

	/*wait_key_gen=true;
	xTaskCreate(genera_chiave,"GeneraChiave",64768,NULL,2,NULL);
	printf("\nAttendo.");
	while(wait_key_gen){
		printf(".");
		vTaskDelay(100 / portTICK_PERIOD_MS);
	}*/

	printf("\n\n------------------------------------------------------------------------------------------\n");

	printf("\n\t ----- TENTO DI CARICARE LE CHIAVI DALLA NVS -----\n");
	if(carica_chiavi()){
		printf("\n -> Chiavi caricate con successo \n");
		printf("\n\n------------------------------------------------------------------------------------------\n");
	}
	else{
		printf("\n -> Chiavi non trovate.\n");
		printf("\n\n------------------------------------------------------------------------------------------\n");
		MASTER_MODE = true;
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
		vTaskDelay(100 / portTICK_PERIOD_MS);
	}while(wait_self_cert_generation);

	printf("\n\n----------------------------------------------------------------------\n");

	//Tento di capire se è già collegato un master. se sì parto in slave mode.
	printf("\n\n\t --- MASTER MODE / SLAVE MODE --- \n\n");
	if(master_phone_exists()){
		printf("\n -> Master già settato.\n   -> Avvio in Slave Mode.");
	}
	else{
		printf("\n -> Master non trovato.\n   -> Avvio in Master Mode.");
		MASTER_MODE = true;
	}
	printf("\n\n------------------------------------------------------------------------------------------\n");
	/*p
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

	xTaskCreate(listener,"StateMachine",8196,NULL,2,NULL);

	printf("\n\t --- AVVIO IL BLUETOOTH E TUTTI I SERVIZI ASSOCIATI --- \n");
	ble_init();
	security_init();
	fflush(stdout);
	printf("\nFINE DEL MAIN.\n");
	print_available_ram();
	fflush(stdout);
    //printf("\nHO LANCIATO TUTTI I SERVIZI, PRESTO SARANNO DISPONIBILI");
    return;
}
