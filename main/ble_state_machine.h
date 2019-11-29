/*
 * ble_state_machine.h
 *
 *  Created on: 19 nov 2019
 *      Author: gaetano
 */

#ifndef MAIN_BLE_STATE_MACHINE_H_
#define MAIN_BLE_STATE_MACHINE_H_

void state_machine_init();
void listener();
bool verifica_certificati();

typedef enum {
    SERVICE_1_STATE_WAIT_MASTER_KEY = 0,		/* Quando sto aspettando la chiave del master, così gli creo il certificato */
	SERVICE_1_STATE_WRITE_CERT,					/* Ho scritto il certificato master, attendo una conferma prima di passare in slave mode */
	SERVICE_1_WAIT_CONFIRMATION,				/* Attendo la conferma */
    SERVICE_2_STATE_WAIT_KEYS_AND_CERTIFICATES,	/* In attesa di key master + key slave + cert master + cert slave */
	SERVICE_2_STATE_WAIT_SIGN_FOR_CONFIRMATION,	/* In attesa della firma, viene mandata dall'app solo con conferma per evitare relay attack */
} ble_state_machine_status;


#endif /* MAIN_BLE_STATE_MACHINE_H_ */
