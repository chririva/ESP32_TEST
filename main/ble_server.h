/*
 * ble_server.h
 *
 *
 */

#ifndef MAIN_BLE_SERVER_H_
#define MAIN_BLE_SERVER_H_

void gaps_init();
void gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param);

void gatts_event_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param);

#endif /* MAIN_BLE_SERVER_H_ */
