/*
 * ble_state_machine.c
 *
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
#include "ble_state_machine.h"

#include "esp_bt.h"
#include "esp_gap_ble_api.h"
#include "esp_gatts_api.h"
#include "esp_bt_defs.h"
#include "esp_bt_main.h"
#include "esp_gatt_common_api.h"
#include "ble_server.h"
#include "random_gen.h"

int state;

extern bool charateristic_flags[16];
extern bool MASTER_MODE;
extern bool wait_cert_app_master;
extern bool wait_cert_app_slave;
extern bool master_cert_validity, slave_cert_validity;
extern mbedtls_pk_context master_pub_key,slave_pub_key;
extern mbedtls_x509_crt slave_certificate;
extern mbedtls_x509_crt master_certificate;
extern unsigned char rand_challenge_firmato[1024];
extern esp_attr_value_t gatts_service1_master_pubkey_val;
extern esp_attr_value_t gatts_service1_info_val;
extern esp_attr_value_t gatts_service2_master_pubkey_val;
extern esp_attr_value_t gatts_service2_slave_pubkey_val;
extern esp_attr_value_t gatts_service2_master_certificate1_val;
extern esp_attr_value_t gatts_service2_master_certificate2_val;
extern esp_attr_value_t gatts_service2_master_certificate3_val;
extern esp_attr_value_t gatts_service2_slave_certificate1_val;
extern esp_attr_value_t gatts_service2_slave_certificate2_val;
extern esp_attr_value_t gatts_service2_slave_certificate3_val;
extern esp_attr_value_t gatts_service2_random_signed_val;
extern esp_attr_value_t gatts_service2_info_val;

bool verifica_certificati();

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

void flags_reset(){
	for(int i=0;i<16;i++){
		charateristic_flags[i] = false;
	}
}

void state_machine_init(){
	flags_reset();
	random_string_generator();//aggiorno il rnd challenge.
	if(MASTER_MODE){
		state = SERVICE_1_STATE_WAIT_MASTER_KEY; //stato iniziale per il master mode
		service1_info_write((unsigned char*)"ready");
		service2_info_write((unsigned char*)"master_mode"); //per avvisare il client che accetta solo il master, non apre la porta.
		printf("\n\n\tAvvio in MASTER MODE\n");
	}else{
		state = SERVICE_2_STATE_WAIT_KEYS_AND_CERTIFICATES; //stato inizialle lo slave mode
		service1_info_write((unsigned char*)"slave_mode"); //per avvisare il client che accetta solo gli slaves, non accetta nessun altro master
		service2_info_write((unsigned char*)"ready");
		printf("\n\n\tAvvio in SLAVE MODE\n");
	}
}

void listener(){
	state_machine_init();
	while(state!=-1){
		printf("\n\nSTATE MACHINE STATUS: %d\n",state);
		switch (state){
			case SERVICE_1_STATE_WAIT_MASTER_KEY:
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
					state = SERVICE_1_STATE_WRITE_CERT;
				}else{
					printf("\n   -> Chiave pubblica master non accettata.");
					service1_info_write((unsigned char*)"error");
				}
				break;

			case SERVICE_1_STATE_WRITE_CERT:
				//printf("\n -> ATTENDO 10 secondi per debug..\n"); //TODO: TOGLIERE (simulo l'elaborazione lunga della esp... perchè è troppo veloce)
				//vTaskDelay(10000 / portTICK_PERIOD_MS);
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
				service1_info_write((unsigned char*)"read");
				state = SERVICE_1_WAIT_CONFIRMATION;
				break;

			case SERVICE_1_WAIT_CONFIRMATION:
				printf("\n\nFATTO TUTTO, CONTROLLA\n\n");
				while(!charateristic_flags[0]){
					vTaskDelay(100 / portTICK_PERIOD_MS);
				}

				//RIAVVIO LA ESP?
				state = SERVICE_2_STATE_WAIT_KEYS_AND_CERTIFICATES; //TODO: deciedere se va tolto o riavviato???
				MASTER_MODE = false;
				flags_reset();
				service1_info_write((unsigned char*)"slave_mode");
				break;

			case SERVICE_2_STATE_WAIT_KEYS_AND_CERTIFICATES:
				//vTaskDelay(1000 / portTICK_PERIOD_MS); //ATTENDO 1 SECONDO e aggiorno la scritta.
				service2_info_write((unsigned char*)"ready");
				//slave deve mandare la pkey master,pkey slave, cert master, cert slave
				state = SERVICE_2_STATE_WAIT_SIGN_FOR_CONFIRMATION;
				mbedtls_pk_init(&master_pub_key);
				mbedtls_pk_init(&slave_pub_key);
				while(!charateristic_flags[5] || !charateristic_flags[6] || !charateristic_flags[7] || !charateristic_flags[8]){ //MASTER PKEY,MASER CERT
					vTaskDelay(80 / portTICK_PERIOD_MS);
				}
				while(!charateristic_flags[9] || !charateristic_flags[10] || !charateristic_flags[11] || !charateristic_flags[12]){ //SLAVE PKEY,SLAVE CERT
					vTaskDelay(80 / portTICK_PERIOD_MS);
				}
				service2_info_write((unsigned char*)"checking_kc");
				charateristic_flags[5]=false;
				charateristic_flags[6]=false;
				charateristic_flags[7]=false;
				charateristic_flags[8]=false;
				charateristic_flags[9]=false;
				charateristic_flags[10]=false;
				charateristic_flags[11]=false;
				charateristic_flags[12]=false;
				//Ho Ricevuto qualcosa in master pkey e master cert
				//Controllo che siano la chiave pubblica e il certificato!
				if(mbedtls_pk_parse_public_key( &master_pub_key, (unsigned char*)gatts_service2_master_pubkey_val.attr_value, gatts_service2_master_pubkey_val.attr_len + 1)==0){
					printf("\n   -> Chiave pubblica master ricevuta.");
				}else{
					printf("\n   -> Chiave pubblica master non ricevuta.");
					service2_info_write((unsigned char*)"error1");
					state = SERVICE_2_STATE_WAIT_KEYS_AND_CERTIFICATES; //qualcosa è andato storto, rimane in questo stato!
				}
				if(mbedtls_pk_parse_public_key( &slave_pub_key, (unsigned char*)gatts_service2_slave_pubkey_val.attr_value, gatts_service2_slave_pubkey_val.attr_len + 1)==0){
					printf("\n   -> Chiave pubblica slave ricevuta.");
				}else{
					printf("\n   -> Chiave pubblica slave non ricevuta.");
					service2_info_write((unsigned char*)"error2");
					state = SERVICE_2_STATE_WAIT_KEYS_AND_CERTIFICATES; //qualcosa è andato storto, rimane in questo stato!
				}
				size_t len1 = gatts_service2_master_certificate1_val.attr_len, len2 = gatts_service2_master_certificate2_val.attr_len, len3 = gatts_service2_master_certificate3_val.attr_len;
				size_t len4 = gatts_service2_slave_certificate1_val.attr_len, len5 = gatts_service2_slave_certificate2_val.attr_len, len6 = gatts_service2_slave_certificate3_val.attr_len;
				char *cert_master_buff = (char*) malloc(len1 + len2 + len3 + 1);
				char *cert_slave_buff = (char*) malloc(len4 + len5 + len6 + 1);
				memcpy(cert_master_buff, gatts_service2_master_certificate1_val.attr_value, len1);
				memcpy(cert_master_buff+len1, gatts_service2_master_certificate2_val.attr_value, len2);
				memcpy(cert_master_buff+len1+len2, gatts_service2_master_certificate3_val.attr_value, len3+1);
				memcpy(cert_slave_buff, gatts_service2_slave_certificate1_val.attr_value, len4);
				memcpy(cert_slave_buff+len4, gatts_service2_slave_certificate2_val.attr_value, len5);
				memcpy(cert_slave_buff+len4+len5, gatts_service2_slave_certificate3_val.attr_value, len6+1);
				printf("\n\nHO RICEVUTO IL CERT MASTER:\n\n%s",cert_master_buff);
				printf("\n\nHO RICEVUTO IL CERT SLAVE:\n\n%s",cert_slave_buff);
				mbedtls_x509_crt_init(&master_certificate);
				if(mbedtls_x509_crt_parse(&master_certificate, (unsigned char*)cert_master_buff, len1+len2+len3+1)== 0 ){
					printf("\n   -> Certificato master ricevuto.");
				}else{
					printf("\n   -> Certificato master non ricevuto.");
					service2_info_write((unsigned char*)"error3");
					state=SERVICE_2_STATE_WAIT_KEYS_AND_CERTIFICATES; //qualcosa è andato storto, rimane in questo stato!
				 }
				mbedtls_x509_crt_init(&slave_certificate);
				if(mbedtls_x509_crt_parse(&slave_certificate, (unsigned char*)cert_slave_buff, len4+len5+len6+1)== 0 ){
					printf("\n   -> Certificato slave ricevuto.");
				}else{
					printf("\n   -> Certificato slave non ricevuto.");
					service2_info_write((unsigned char*)"error4");
					state=SERVICE_2_STATE_WAIT_KEYS_AND_CERTIFICATES; //qualcosa è andato storto, rimane in questo stato!
				}
				free(cert_master_buff); //libero i 2 buffer di stringhe
				free(cert_slave_buff);
				if(state!=SERVICE_2_STATE_WAIT_KEYS_AND_CERTIFICATES){
					//Ho tutto, controllo che vadano bene
					printf("\n\n----------------------------------------------------------------------\n");
					printf("\n\n\t ----- VERIFICO CERTIFICATI ----- \n\n");
				    if(!verifica_certificati()){
				    	printf("\n -> I certificati non sono stati approvati.");
				    	service2_info_write((unsigned char*)"error5");
				    	state = SERVICE_2_STATE_WAIT_KEYS_AND_CERTIFICATES;
				    }
				    else{
				    	printf("\n -> I certificati sono stati approvati.");
				    	service2_info_write((unsigned char*)"wait_rnd");
				    	//andrà nello state = SERVICE_2_STATE_WAIT_SIGN_FOR_CONFIRMATION;
				    }
				}
				if(state == SERVICE_2_STATE_WAIT_KEYS_AND_CERTIFICATES){ //qualcosa è andato storto, rimane in questo stato, ma attende 2 secondi
					vTaskDelay(2000 / portTICK_PERIOD_MS);
				}
				break;

			case SERVICE_2_STATE_WAIT_SIGN_FOR_CONFIRMATION:
				while(!charateristic_flags[14]){ //RANDOM SIGNED
					vTaskDelay(100 / portTICK_PERIOD_MS); //TODO: Aggiungere timeout!!!
				}
				service2_info_write((unsigned char*)"checking_rnd");
				charateristic_flags[14]=false;
				//Apertura porta confermata, verifico la firma
				memcpy(rand_challenge_firmato, gatts_service2_random_signed_val.attr_value, gatts_service2_random_signed_val.attr_len);
				rand_challenge_firmato[gatts_service2_random_signed_val.attr_len] = 0; //terminatore
				//ricevo
		    	printf("\n\n----------------------------------------------------------------------\n");
		    	printf("\n\n\t ----- RANDOM CHALLENGE ----- \n\n");
		    	printf("\n -> Verifico la firma del Random Challenge");

				if(random_challenge_verify()==0){
					printf("\n   -> Firma del random challenge verificata.");

					printf("\n\n\n------------------------------------------------------------------------------------------------\n"\
							"------------------------------------------------------------------------------------------------\n"\
							"-------------------------------------------APRO LA PORTA----------------------------------------\n"\
							"------------------------------------------------------------------------------------------------\n"\
							"------------------------------------------------------------------------------------------------\n\n\n");
					service2_info_write((unsigned char*)"door_opened");
				}
				else{
					printf("\n   -> Firma del random non verificata.");
					service2_info_write((unsigned char*)"signature_failed");
				}
				//in ogni caso...
				random_string_generator();//aggiorno il rnd challenge.

				mbedtls_x509_crt_free(&master_certificate); // libero la memoria dei certificati
				mbedtls_x509_crt_free(&slave_certificate);
				state = SERVICE_2_STATE_WAIT_KEYS_AND_CERTIFICATES;
				//flags_reset(); //per essere certi che i flag siano bassi.. magari qualcuno li ha flaggati con un altro client
				vTaskDelay(2000 / portTICK_PERIOD_MS); //ATTENDO 2 SECONDI COSI IL CLIENT PUO' LEGGERE E SAPERE IL RISULTATO
				break;

		}
	}
	printf("\n\nERRORE CRITICO. LA MACCHINA A STATI SI E' BLOCCATA.");

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

	vTaskDelay(150 / portTICK_PERIOD_MS);
	//print_all_certificates();
	wait_cert_app_slave=true;
	xTaskCreate(cert_app_slave_certificate,"CertAppSlave",8000,NULL,3,NULL);
	printf("\n -> Attendi, verifica dello Slave Certificate..\n");
	while(wait_cert_app_slave){
		vTaskDelay(100 / portTICK_PERIOD_MS);
	}
	return master_cert_validity & slave_cert_validity;
}

