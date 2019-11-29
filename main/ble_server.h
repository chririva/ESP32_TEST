/*
 * ble_server.h
 *
 *
 */

#ifndef MAIN_BLE_SERVER_H_
#define MAIN_BLE_SERVER_H_

#define PREPARE_BUF_MAX_SIZE 2048

typedef struct {
    uint8_t		*prepare_buf;
    int			prepare_len;
    int			char_position; //a quale caratteristica si riferisce
} prepare_type_env_t;

void gaps_init();
void gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param);

void example_write_event_env(esp_gatt_if_t gatts_if, prepare_type_env_t *prepare_write_env, esp_ble_gatts_cb_param_t *param);
void example_exec_write_event_env(prepare_type_env_t *prepare_write_env, esp_ble_gatts_cb_param_t *param);
void gatts_event_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param);


#endif /* MAIN_BLE_SERVER_H_ */
