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
mbedtls_pk_context key_key, master_pub_key,slave_pub_key; //key_key è la chiave della esp. device_pub_key dello smartphone master
mbedtls_x509_crt self_certificate; //Self certificate della esp
mbedtls_x509_crt master_certificate; //Certificate dello smartphone master
mbedtls_x509_crt slave_certificate; //Certificate dello smartphone slave
char esp_mac[13];

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
bool elimina_master(){ //TODO: potrebbe essere necessario rigenerare anche le chiavi! Ho eliminato il master ma ha ancora i poteri
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

void print_mac_address(){
	uint8_t mac_id[6];
	char esp_mac[13];
    ESP_ERROR_CHECK(esp_read_mac(mac_id, 2));  //type of MAC address, 0:wifi station, 1:wifi softap, 2:bluetooth, 3:ethernet.
    sprintf(esp_mac, "%02x%02x%02x%02x%02x%02x", mac_id[0],mac_id[1],mac_id[2],mac_id[3], mac_id[4],mac_id[5]);
    printf("\n\nESP_MAC - %s\n\n", esp_mac);
}

void app_main()
{
	//ritardo(5);
	print_available_ram();
	print_date_time();
	print_mac_address();
	ritardo(3);

	elimina_master(); //TODO: va tolto da qua
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
