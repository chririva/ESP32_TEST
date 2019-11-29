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

extern bool charateristic_flags[10];
extern mbedtls_pk_context key_key, master_pub_key;
extern mbedtls_x509_crt self_certificate;
extern mbedtls_x509_crt master_certificate;
extern uint8_t service1_master_pubkey_str[];
extern esp_attr_value_t gatts_service1_master_pubkey_val;
extern unsigned char master_pub_key_string[];

void state_machine_init(){
	for(int i=0;i<10;i++){
		charateristic_flags[i] = false;
	}
	state = 0;
}

void listener(){
	while(state!=-1){
		printf("\n\nSTATE MACHINE STATUS: %d",state);
		switch (state){
			case 0:
				//master deve mandare la chiave pubblica
				while(!charateristic_flags[0]){
					vTaskDelay(100 / portTICK_PERIOD_MS);
				}
				charateristic_flags[0]=false;
				//Ho la chiave pubblica
				mbedtls_pk_init(&master_pub_key);
				esp_log_buffer_hex("CIAO", master_pub_key_string, strlen((const char*)master_pub_key_string));
				if(mbedtls_pk_parse_public_key( &master_pub_key, (unsigned char*)gatts_service1_master_pubkey_val.attr_value, gatts_service1_master_pubkey_val.attr_len + 1)==0){
					printf("\n   -> Chiave pubblica master accettata.");

					//GENERO IL CERTIFICATO

				}else{
					printf("\n   -> Chiave pubblica master non accettata.");
				}
				break;
		}
	}






}



