/*
 * ble_server.h
 *
 *
 */

#ifndef MAIN_BLE_SERVER_H_
#define MAIN_BLE_SERVER_H_
	#include "esp_bt.h"
	#include "esp_gap_ble_api.h"
	#include "esp_gatts_api.h"
	#include "esp_bt_defs.h"
	#include "esp_bt_main.h"
	#include "esp_gatt_common_api.h"

	//extern nvs_handle eg_nvs;
	extern bool status_connected;

	void gaps_init();
	void gaps_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param);

	void gatts_event_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param);
	void gatts_init_values();

#endif /* MAIN_BLE_SERVER_H_ */
