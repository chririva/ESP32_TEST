/*
 * ble_state_machine.c
 *
 *  Created on: 19 nov 2019
 *      Author: gaetano
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

#include "genera_chiave.h"
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

int state;

extern bool charateristic_flags[16];
extern bool MASTER_MODE;
extern mbedtls_pk_context master_pub_key,slave_pub_key;
extern mbedtls_x509_crt self_certificate;
extern mbedtls_x509_crt master_certificate;
extern uint8_t service1_master_pubkey_str[];
extern esp_attr_value_t gatts_service1_master_pubkey_val;
extern esp_attr_value_t gatts_service1_master_certificate1_val;
extern esp_attr_value_t gatts_service1_master_certificate2_val;
extern esp_attr_value_t gatts_service1_master_certificate3_val;
extern esp_attr_value_t gatts_service1_info_val;
extern esp_attr_value_t gatts_service2_master_pubkey_val;
extern esp_attr_value_t gatts_service2_master_certificate1_val;
extern esp_attr_value_t gatts_service2_master_certificate2_val;
extern esp_attr_value_t gatts_service2_master_certificate3_val;
extern esp_attr_value_t gatts_service2_info_val;
extern unsigned char master_pub_key_string[];

static void service1_info_write(unsigned char info[]){
	gatts_service1_info_val.attr_len = strlen((const char*)info);
    for(int valpos=0 ; valpos<strlen((const char*)info) ; valpos++ )
    	gatts_service1_info_val.attr_value[valpos]=info[valpos];
    gatts_service1_info_val.attr_value[strlen((const char*)info)] = 0; //terminatore stringa
}

static void service2_info_write(unsigned char info[]){
	gatts_service2_info_val.attr_len = strlen((const char*)info);
    for(int valpos=0 ; valpos<strlen((const char*)info) ; valpos++ )
    	gatts_service2_info_val.attr_value[valpos]=info[valpos];
    gatts_service2_info_val.attr_value[strlen((const char*)info)] = 0; //terminatore stringa
}

void state_machine_init(){
	for(int i=0;i<10;i++){
		charateristic_flags[i] = false;
	}
	if(MASTER_MODE)
		state = 0; //stato iniziale per il master mode
	else
		state = 10; //stato inizialle lo slave mode
}

void listener(){
	state_machine_init();
	while(state!=-1){
		printf("\n\nSTATE MACHINE STATUS: %d\n",state);
		switch (state){
			case 0:
				//master deve mandare la chiave pubblica
				mbedtls_pk_init(&master_pub_key);

				while(!charateristic_flags[0]){ //MASTER PKEY
					vTaskDelay(100 / portTICK_PERIOD_MS);
				}
				charateristic_flags[0]=false;
				//Ho Ricevuto qualcosa in master pkey. Controllo che sia la chiave pubblica!
				if(mbedtls_pk_parse_public_key( &master_pub_key, (unsigned char*)gatts_service1_master_pubkey_val.attr_value, gatts_service1_master_pubkey_val.attr_len + 1)==0){
					printf("\n   -> Chiave pubblica master accettata.");
					service1_info_write((unsigned char*)"wait");
					//devo generare il certificato
					state=1;
				}else{
					printf("\n   -> Chiave pubblica master non accettata.");
					service1_info_write((unsigned char*)"error");
				}
				break;

			case 1:
				printf("\n -> ATTENDOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO..\n");
				vTaskDelay(10000 / portTICK_PERIOD_MS);
				//genero il certificato master e lo scrito nella caratteristica
				//MASTER CERT WRITE
				printf("\n\n\t --- GENERA MASTER CERT WRITE --- \n\n");
				wait_master_cert_write=true;
				xTaskCreate(master_cert_write,"MasterCertWrite",32768,NULL,3,NULL);
				printf("\n -> Attendo..\n");
				do{
					vTaskDelay(100 / portTICK_PERIOD_MS);
				}while(wait_master_cert_write);
				printf("\n\n----------------------------------------------------------------------\n");
				//aggiorno il campo info:
				service1_info_write((unsigned char*)"ready");
				state = 2;
				break;

			case 2:
				printf("\n\nFATTO TUTTO, CONTROLLA\n\n");
				while(!charateristic_flags[0]){
					vTaskDelay(100 / portTICK_PERIOD_MS);
				}
				//RIAVVIO LA ESP IN SLAVE MODE
				state = 10; //TODO: deciedere se va tolto o riavviato
				MASTER_MODE = false; //TODO: va salvato in memoria
				break;

			case 10:
				//slave deve mandare la pkey master,pkey slave, cert master, cert slave
				mbedtls_pk_init(&master_pub_key);
				mbedtls_pk_init(&slave_pub_key);
				while(!charateristic_flags[5] && !charateristic_flags[6] && !charateristic_flags[7] && !charateristic_flags[8]){ //MASTER PKEY,MASER CERT
					vTaskDelay(100 / portTICK_PERIOD_MS);
				}
				charateristic_flags[5]=false;
				charateristic_flags[6]=false;
				charateristic_flags[7]=false;
				charateristic_flags[8]=false;
				//Ho Ricevuto qualcosa in master pkey e master cert
				//Controllo che siano la chiave pubblica e il certificato!
				if(mbedtls_pk_parse_public_key( &master_pub_key, (unsigned char*)gatts_service2_master_pubkey_val.attr_value, gatts_service2_master_pubkey_val.attr_len + 1)==0){
					printf("\n   -> Chiave pubblica master accettata.");
					//service2_info_write((unsigned char*)"wait");
					//devo generare il certificato
					state=10;
				}else{
					printf("\n   -> Chiave pubblica master non accettata.");
					service2_info_write((unsigned char*)"error");
				}
				break;

			case 100:
				//per convertire da string a crt
			    /*if( ( ret = mbedtls_x509_crt_parse(&master_certificate, output_buf, sizeof(output_buf)) ) != 0 ){
			        printf("\nNon sono riuscito a caricare il CRT nella RAM");
			        return( ret );
			    }
			    else{
			    	printf("\nCRT caricato in RAM!");
			    	return( ret );
			    }*/
				break;
		}
	}
	printf("\n\nERRORE CRITICO. LA MACCHINA A STATI SI E' BLOCCATA.");

}



