/*
 * ble_server.c
 *
 *
 */



/*
   This example code is in the Public Domain (or CC0 licensed, at your option.)
   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

/****************************************************************************
*
* This demo showcases BLE GATT server. It can send adv data, be connected by client.
* Run the gatt_client demo, the client demo will automatically connect to the gatt_server demo.
* Client demo will enable gatt_server's notify after connection. The two devices will then exchange
* data.
*
****************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_bt.h"
#include "esp_gap_ble_api.h"
#include "esp_gatts_api.h"
#include "esp_bt_defs.h"
#include "esp_bt_main.h"
#include "esp_gatt_common_api.h"
#include "ble_config.h"
#include "ble_server.h"

#include "sdkconfig.h"

extern uint8_t service1_master_pubkey_str[GATTS_CHAR_PUBKEY_LEN_MAX]; //TODO: TOGLIERE, solo per debug
extern bool charateristic_flags[10];

/* ************************************************************ */
/* *************************** GAP **************************** */
/* ************************************************************ */

#define BLE_SERVICE_UUID_SIZE GATTS_SERVICE_NUM*ESP_UUID_LEN_128
static uint8_t ble_service_uuid128[BLE_SERVICE_UUID_SIZE] = {
	GATTS_SERVICE1_UUID,
	GATTS_SERVICE2_UUID
};

//static uint8_t ble_manufacturer[BLE_MANUFACTURER_DATA_LEN] = BLE_MANUFACTURER_DATA;

static uint8_t adv_config_done = 0;
#define adv_config_flag      (1 << 0)
#define scan_rsp_config_flag (1 << 1)

static esp_ble_adv_data_t adv_data = {
    .set_scan_rsp = false,
    .include_name = true,
    .include_txpower = true,
    .min_interval = 0x0006, //slave connection min interval, Time = min_interval * 1.25 msec
    .max_interval = 0x0010, //slave connection max interval, Time = max_interval * 1.25 msec
    .appearance = 0x00,
    .manufacturer_len = 0, //TEST_MANUFACTURER_DATA_LEN,
    .p_manufacturer_data =  NULL, //&test_manufacturer[0],
    .service_data_len = 0,
    .p_service_data = NULL,
    .service_uuid_len = sizeof(ble_service_uuid128),
    .p_service_uuid = ble_service_uuid128,
    .flag = (ESP_BLE_ADV_FLAG_GEN_DISC | ESP_BLE_ADV_FLAG_BREDR_NOT_SPT),
};
// scan response data
static esp_ble_adv_data_t scan_rsp_data = {
    .set_scan_rsp = true,
    .include_name = true,
    .include_txpower = true,
    .min_interval = 0x0006,
    .max_interval = 0x0010,
    .appearance = 0x00,
    .manufacturer_len = 0, //TEST_MANUFACTURER_DATA_LEN,
    .p_manufacturer_data =  NULL, //&test_manufacturer[0],
    .service_data_len = 0,
    .p_service_data = NULL,
    .service_uuid_len = sizeof(ble_service_uuid128),
    .p_service_uuid = ble_service_uuid128,
    .flag = (ESP_BLE_ADV_FLAG_GEN_DISC | ESP_BLE_ADV_FLAG_BREDR_NOT_SPT),
};

static esp_ble_adv_params_t adv_params = {
    .adv_int_min        = 0x20,
    .adv_int_max        = 0x40,
    .adv_type           = ADV_TYPE_IND,
    .own_addr_type      = BLE_ADDR_TYPE_PUBLIC,
    //.peer_addr            =
    //.peer_addr_type       =
    .channel_map        = ADV_CHNL_ALL,
    .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

/* This function initialises the GAP data.
 * ESP_GAP_BLE_ADV_DATA_SET_COMPLETE_EVT is sent to gap_event_handler() below
 * afterwards.
 */
void gaps_init() {
	/*esp_err_t ret;
	//sprintf(device_name, BLE_DEVICE_NAME, *gatts_char[GATTS_BUTTON_NUMBER_CHAR_POS].char_val->attr_value); // copy configured button number into the device name
	esp_ble_gap_set_device_name(DEVICE_NAME);

	ret=esp_ble_gap_config_adv_data(&adv_data);
	ESP_LOGI(GATTS_TAG, "esp_ble_gap_config_adv_data %d", ret);
	*/

    //aggiunto io inizio
		printf("\nroba aggiunta io");
		esp_err_t set_dev_name_ret = esp_ble_gap_set_device_name(DEVICE_NAME);
     if (set_dev_name_ret){
         ESP_LOGE(GATTS_TAG, "set device name failed, error code = %x", set_dev_name_ret);
     }
     //config adv data
     esp_err_t ret = esp_ble_gap_config_adv_data(&adv_data);
     if (ret){
         ESP_LOGE(GATTS_TAG, "config adv data failed, error code = %x", ret);
     }
     adv_config_done |= adv_config_flag;
     //config scan response data
     ret = esp_ble_gap_config_adv_data(&scan_rsp_data);
     if (ret){
         ESP_LOGE(GATTS_TAG, "config scan response data failed, error code = %x", ret);
     }
     adv_config_done |= scan_rsp_config_flag;
     //aggiunto io fine

}

/* In server (config) mode, this function is called whenever the ESP32
 * bluetooth stack generates a GAP event.
 */

void gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param)
{
    switch (event) {
#ifdef CONFIG_SET_RAW_ADV_DATA
    case ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT:
        adv_config_done &= (~adv_config_flag);
        if (adv_config_done==0){
            esp_ble_gap_start_advertising(&adv_params);
        }
        break;
    case ESP_GAP_BLE_SCAN_RSP_DATA_RAW_SET_COMPLETE_EVT:
        adv_config_done &= (~scan_rsp_config_flag);
        if (adv_config_done==0){
            esp_ble_gap_start_advertising(&adv_params);
        }master_cert_validity
        break;
#else
    case ESP_GAP_BLE_ADV_DATA_SET_COMPLETE_EVT:
        adv_config_done &= (~adv_config_flag);
        if (adv_config_done == 0){
            esp_ble_gap_start_advertising(&adv_params);
        }
        break;
    case ESP_GAP_BLE_SCAN_RSP_DATA_SET_COMPLETE_EVT:
        adv_config_done &= (~scan_rsp_config_flag);
        if (adv_config_done == 0){
            esp_ble_gap_start_advertising(&adv_params);
        }
        break;
#endif
    case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
        //advertising start complete event to indicate advertising start successfully or failed
        if (param->adv_start_cmpl.status != ESP_BT_STATUS_SUCCESS) {
            ESP_LOGE(GATTS_TAG, "Advertising start failed\n");
        }
        break;
    case ESP_GAP_BLE_ADV_STOP_COMPLETE_EVT:
        if (param->adv_stop_cmpl.status != ESP_BT_STATUS_SUCCESS) {
            ESP_LOGE(GATTS_TAG, "Advertising stop failed\n");
        } else {
            ESP_LOGI(GATTS_TAG, "Stop adv successfully\n");
        }
        break;
    case ESP_GAP_BLE_UPDATE_CONN_PARAMS_EVT:
         ESP_LOGI(GATTS_TAG, "update connection params status = %d, min_int = %d, max_int = %d,conn_int = %d,latency = %d, timeout = %d",
                  param->update_conn_params.status,
                  param->update_conn_params.min_int,
                  param->update_conn_params.max_int,
                  param->update_conn_params.conn_int,
                  param->update_conn_params.latency,
                  param->update_conn_params.timeout);
        break;
    default:
        break;
    }
}

/* ************************************************************ */
/* *************************** GATT *************************** */
/* ************************************************************ */

/* Services, characteristics and descriptors are defined in arrays below, so
 * that we can have several of each. Which characteristic belongs to which
 * service, and which descriptor belongs to which characteristic, depends on
 * the sequence in which they are added. It needs to be as in the "layout"
 * above.
 * These variables are used to count through the items we're adding so that we
 * always know where in the "layout" we currently are.
 */
static uint16_t ble_add_service_pos;
static uint32_t ble_add_char_pos;
static uint32_t ble_add_descr_pos;

static prepare_type_env_t buff_prepare_write_env;

//per scrivere una lunga caratteristica
void example_write_event_env(esp_gatt_if_t gatts_if, prepare_type_env_t *prepare_write_env, esp_ble_gatts_cb_param_t *param){
    esp_gatt_status_t status = ESP_GATT_OK;
    if (param->write.need_rsp){
        if (param->write.is_prep){
            if (prepare_write_env->prepare_buf == NULL) {
                prepare_write_env->prepare_buf = (uint8_t *)malloc(PREPARE_BUF_MAX_SIZE*sizeof(uint8_t));
                prepare_write_env->prepare_len = 0;
                if (prepare_write_env->prepare_buf == NULL) {
                    ESP_LOGE(GATTS_TAG, "Gatt_server prep no mem\n");
                    status = ESP_GATT_NO_RESOURCES;
                }
            } else {
                if(param->write.offset > PREPARE_BUF_MAX_SIZE) {
                    status = ESP_GATT_INVALID_OFFSET;
                } else if ((param->write.offset + param->write.len) > PREPARE_BUF_MAX_SIZE) {
                    status = ESP_GATT_INVALID_ATTR_LEN;
                }
            }

            esp_gatt_rsp_t *gatt_rsp = (esp_gatt_rsp_t *)malloc(sizeof(esp_gatt_rsp_t));
            gatt_rsp->attr_value.len = param->write.len;
            gatt_rsp->attr_value.handle = param->write.handle;
            gatt_rsp->attr_value.offset = param->write.offset;
            gatt_rsp->attr_value.auth_req = ESP_GATT_AUTH_REQ_NONE;
            memcpy(gatt_rsp->attr_value.value, param->write.value, param->write.len);
            esp_err_t response_err = esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, status, gatt_rsp);
            if (response_err != ESP_OK){
               ESP_LOGE(GATTS_TAG, "Send response error\n");
            }
            free(gatt_rsp);
            if (status != ESP_GATT_OK){
                return;
            }
            memcpy(prepare_write_env->prepare_buf + param->write.offset,
                   param->write.value,
                   param->write.len);
            prepare_write_env->prepare_len += param->write.len;

        }else{
            esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, status, NULL);
        }
    }
}

void example_exec_write_event_env(prepare_type_env_t *prepare_write_env, esp_ble_gatts_cb_param_t *param){
    if (param->exec_write.exec_write_flag == ESP_GATT_PREP_WRITE_EXEC){
        esp_log_buffer_hex(GATTS_TAG, prepare_write_env->prepare_buf, prepare_write_env->prepare_len);
        printf("\nLUNGHEZZA: %d\n",prepare_write_env->prepare_len);
        printf("\nCARATTERISTICA NUMERO: %d\n",prepare_write_env->char_position);

        //copio in memoria
		gatts_char[prepare_write_env->char_position].char_val->attr_len = prepare_write_env->prepare_len;
		for (uint32_t valpos=0; valpos<prepare_write_env->prepare_len;valpos++) {
			gatts_char[prepare_write_env->char_position].char_val->attr_value[valpos]=prepare_write_env->prepare_buf[valpos];
		}
		//Aggiungo il terminatore
		gatts_char[prepare_write_env->char_position].char_val->attr_value[prepare_write_env->prepare_len]=0;
		charateristic_flags[prepare_write_env->char_position]=true; //flaggo la char scritta

    }else{
        ESP_LOGI(GATTS_TAG,"ESP_GATT_PREP_WRITE_CANCEL");
    }
    //service1_master_pubkey_str
    //TODO: TOGLIERE
    //PROVO A STAMPARE QELLO CHE HO SALVATO
    printf("\n\nHO STORATO NELLA ARATTERISTICA NUMERO [%d]:\n[",prepare_write_env->char_position);
	printf("%s]\n\n",(char *)service1_master_pubkey_str);

    if (prepare_write_env->prepare_buf) {
        free(prepare_write_env->prepare_buf);
        prepare_write_env->prepare_buf = NULL;
    }
    prepare_write_env->prepare_len = 0;
}


/* This function is called by gatts_event_handler() in case of an
 * ESP_GATTS_READ_EVT:
 * It walks through all of the gatts_char and gatts_descr arrays until the
 * characteristic or descriptor with the correct handle is found. Then its
 * value is copied byte-by-byte into the response variable (rsp) which is
 * finally sent to the client.
 */
static void gatts_read_value_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param) {
	ESP_LOGI(GATTS_TAG, "gatts_read_value_handler: handle %d\n", param->read.handle);

	// prepare the response to this read request:
	esp_gatt_rsp_t rsp;
	memset(&rsp, 0, sizeof(esp_gatt_rsp_t));
	// set the handle to which we are responding:
	rsp.attr_value.handle = param->read.handle;

	// find the requested attribute among the chars and descrs and copy its value into the response:
	for (uint32_t pos=0;pos<GATTS_CHAR_NUM;pos++) {
		if (gatts_char[pos].char_handle==param->read.handle) {
			ESP_LOGI(GATTS_TAG, "gatts_read_value_handler: found requested handle at char pos %d\n", pos);

			// set the attribute value of the response:
			if (gatts_char[pos].char_val!=NULL) {
				ESP_LOGI(GATTS_TAG, "gatts_read_value_handler: char_val length %d\n",gatts_char[pos].char_val->attr_len);
				rsp.attr_value.len = gatts_char[pos].char_val->attr_len;
				for (uint32_t valpos=0;valpos<gatts_char[pos].char_val->attr_len&&valpos<gatts_char[pos].char_val->attr_max_len;valpos++) {
					rsp.attr_value.value[valpos] = gatts_char[pos].char_val->attr_value[valpos];
				}
				break;
			}
		}
	}
	for (uint32_t pos=0;pos<GATTS_DESCR_NUM;pos++) {
		if (gatts_descr[pos].descr_handle==param->read.handle) {
			ESP_LOGI(GATTS_TAG, "gatts_read_value_handler: found requested handle at descr pos %d\n", pos);

			// set the attribute value of the response:
			if (gatts_descr[pos].descr_val!=NULL) {
				ESP_LOGI(GATTS_TAG, "gatts_read_value_handler: descr_val length %d\n",gatts_descr[pos].descr_val->attr_len);
				rsp.attr_value.len = gatts_descr[pos].descr_val->attr_len;
				for (uint32_t valpos=0;valpos<gatts_descr[pos].descr_val->attr_len&&valpos<gatts_descr[pos].descr_val->attr_max_len;valpos++) {
					rsp.attr_value.value[valpos] = gatts_descr[pos].descr_val->attr_value[valpos];
				}
				break;
			}
		}
	}

	esp_ble_gatts_send_response(gatts_if, param->read.conn_id, param->read.trans_id, ESP_GATT_OK, &rsp);
}

/* This function is called by gatts_event_handler() in case of an
 * ESP_GATTS_WRITE_EVT:
 * It walks through all of the gatts_char and gatts_descr arrays until the
 * characteristic or descriptor with the correct handle is found. Then the
 * requested value is copied byte-by-byte into the characteristic's or
 * descriptor's variable. If .char_nvs is set, the requested value is also
 * written to Non-Volatile Storage (NVS) using the value of .char_nvs as the
 * key.
 * Finally, an empty response is sent to the client.
 */
static void gatts_write_value_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param) {
	ESP_LOGI(GATTS_TAG, "gatts_write_value_handler: handle %d\n", param->write.handle);
	//esp_err_t ret;

	// find the requested attribute among the chars and descrs and copy the request value into it:
	for (uint32_t pos=0;pos<GATTS_CHAR_NUM;pos++) {
		if (gatts_char[pos].char_handle==param->write.handle) {
			ESP_LOGI(GATTS_TAG, "gatts_write_value_handler: found requested handle at char pos %d\n", pos);
			// If the write is a long write, then (param->write.is_prep) will be set,
			//if it is a short write then (param->write.is_prep) will not be set
			if (param->write.is_prep){ // se write.
				//VA SCRITTA UNA LUNGA CARATTERISTICA
				buff_prepare_write_env.char_position = pos;
				example_write_event_env(gatts_if, &buff_prepare_write_env, param);
			}else{
				//VA SCRITTA UNA CORTA CARATTERISTICA
				if (gatts_char[pos].char_val!=NULL) {
					ESP_LOGI(GATTS_TAG, "gatts_write_value_handler: char_val length %d\n", param->write.len);
					gatts_char[pos].char_val->attr_len = param->write.len;
					for (uint32_t valpos=0; valpos<param->write.len && valpos<gatts_char[pos].char_val->attr_max_len;valpos++) {
						gatts_char[pos].char_val->attr_value[valpos]=param->write.value[valpos];
					}
					//Aggiungo il terminatore
					gatts_char[pos].char_val->attr_value[param->write.len]=0;

					ESP_LOGI(TAG, "gatts_write_value_handler %.*s", gatts_char[pos].char_val->attr_len, (char*)gatts_char[pos].char_val->attr_value);

					esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, ESP_GATT_OK, NULL);
					// TODO: notify?
					break;
				}
			}
		}
	}
	for (uint32_t pos=0;pos<GATTS_DESCR_NUM;pos++) {
		if (gatts_descr[pos].descr_handle==param->write.handle) {
			ESP_LOGI(GATTS_TAG, "gatts_write_value_handler: found requested handle at descr pos %d\n", pos);

			// set the attribute value:
			if (gatts_descr[pos].descr_val!=NULL) {
				ESP_LOGI(GATTS_TAG, "gatts_write_value_handler: descr_val length %d\n", param->write.len);
				gatts_descr[pos].descr_val->attr_len = param->write.len;
				for (uint32_t valpos=0; valpos<param->write.len && valpos<gatts_descr[pos].descr_val->attr_max_len;valpos++) {
					gatts_descr[pos].descr_val->attr_value[valpos]=param->write.value[valpos];
				}
				//Aggiungo il terminatore
				gatts_descr[pos].descr_val->attr_value[param->write.len]=0;

				ESP_LOGI(TAG, "gatts_write_value_handler: wrote: %.*s", gatts_descr[pos].descr_val->attr_len, (char*)gatts_descr[pos].descr_val->attr_value);

				esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, ESP_GATT_OK, NULL);
				// TODO: notify?
				break;
			}
		}
	}
	//printf("\nFINE: gatts_write_value_handler \n");
}


/* This function is first called by gatts_event_handler() in case of an
 * ESP_GATTS_CREATE_EVT (after a service has been added) and then again when
 * there are no more descriptors to add to a characteristic:
 * It walks through all of the gatts_char array until a characteristic is found
 * which belongs to the current service (checking .service_pos) and does not
 * yet have a handle (i.e. hasn't been added yet).
 * After the characteristic has been added, an ESP_GATTS_ADD_CHAR_EVT event is
 * generated, which causes gatts_check_add_char() to be called below.
 */
static void gatts_add_char() {
	ESP_LOGI(GATTS_TAG, "gatts_add_char: service %d", ble_add_service_pos);

	for (uint32_t pos=0;pos<GATTS_CHAR_NUM;pos++) {
		if (gatts_char[pos].service_pos==ble_add_service_pos && gatts_char[pos].char_handle==0) {
			ESP_LOGI(GATTS_TAG, "gatts_add_char: adding char pos %d to service pos %d (service handle %d)", pos, ble_add_service_pos, gatts_service[ble_add_service_pos].service_handle);
			ble_add_char_pos=pos;
			esp_ble_gatts_add_char(gatts_service[ble_add_service_pos].service_handle, &gatts_char[pos].char_uuid,
								   gatts_char[pos].char_perm,gatts_char[pos].char_property,gatts_char[pos].char_val, gatts_char[pos].char_control);
			break;
		}
	}
}

/* This function is first called by gatts_check_add_char() below after a
 * characteristic has been added and then again after each added descriptor.
 * It walks through all of the gatts_descr array until a descriptor is found
 * which belongs to the current characteristic (checking .char_pos) and does
 * not yet have a handle (i.e. hasn't been added yet).
 * After the descriptor has been added, an ESP_GATTS_ADD_CHAR_DESCR_EVT event
 * is generated, which causes gatts_check_add_descr() to be called below.
 * If there are no more descriptors left for the current characteristic,
 * gatts_add_char() is called in order to add the next characteristic.
 */
static void gatts_add_descr() {
	ESP_LOGI(GATTS_TAG, "gatts_add_descr: service %d, char %d", ble_add_service_pos, ble_add_char_pos);

	for (uint32_t pos=0;pos<GATTS_DESCR_NUM;pos++) {
		if (gatts_descr[pos].descr_handle==0 && gatts_descr[pos].char_pos==ble_add_char_pos) {
			ESP_LOGI(GATTS_TAG, "gatts_add_descr: adding descr pos %d to char pos %d (handle %d) on service %d (handle %d)", pos, ble_add_char_pos, gatts_char[ble_add_char_pos].char_handle, ble_add_service_pos, gatts_service[ble_add_service_pos].service_handle);
			ble_add_descr_pos=pos;
			esp_ble_gatts_add_char_descr(gatts_service[ble_add_service_pos].service_handle, &gatts_descr[pos].descr_uuid,
										gatts_descr[pos].descr_perm, gatts_descr[pos].descr_val, gatts_descr[pos].descr_control);
			break;
		} else if (pos == GATTS_DESCR_NUM-1) {
			// went through all of the descriptors without finding one to add -> add next characteristic
			gatts_add_char();
		}
	}
}

/* This function is called by gatts_event_handler() in case of an
 * ESP_GATTS_ADD_CHAR_EVT, i.e. after a characteristic has been added.
 * It sets the .char_handle variable of the current characteristic to the new
 * handle generated by the ESP32. Finally, gatts_add_descr() is called to add
 * the descriptors, if any, to this new characteristic.
 */
static void gatts_check_add_char(esp_bt_uuid_t char_uuid, uint16_t attr_handle) {
	ESP_LOGI(GATTS_TAG, "gatts_check_add_char: char handle %d", attr_handle);

	if (attr_handle != 0) {
		if (char_uuid.len == ESP_UUID_LEN_16) {
			ESP_LOGI(GATTS_TAG, "Char UUID16: %x", char_uuid.uuid.uuid16);
		} else if (char_uuid.len == ESP_UUID_LEN_32) {
			ESP_LOGI(GATTS_TAG, "Char UUID32: %x", char_uuid.uuid.uuid32);
		} else if (char_uuid.len == ESP_UUID_LEN_128) {
			ESP_LOGI(GATTS_TAG, "Char UUID128: %x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x", char_uuid.uuid.uuid128[0],
					 char_uuid.uuid.uuid128[1], char_uuid.uuid.uuid128[2], char_uuid.uuid.uuid128[3],
					 char_uuid.uuid.uuid128[4], char_uuid.uuid.uuid128[5], char_uuid.uuid.uuid128[6],
					 char_uuid.uuid.uuid128[7], char_uuid.uuid.uuid128[8], char_uuid.uuid.uuid128[9],
					 char_uuid.uuid.uuid128[10], char_uuid.uuid.uuid128[11], char_uuid.uuid.uuid128[12],
					 char_uuid.uuid.uuid128[13], char_uuid.uuid.uuid128[14], char_uuid.uuid.uuid128[15]);
		} else {
			ESP_LOGE(GATTS_TAG, "Char UNKNOWN LEN %d\n", char_uuid.len);
		}

		ESP_LOGI(GATTS_TAG, "gatts_check_add_char: found char pos %d, handle %d\n", ble_add_char_pos, attr_handle);
		gatts_char[ble_add_char_pos].char_handle=attr_handle;

		gatts_add_descr(); // try to add descriptors to this characteristic
	}
}

/* This function is called by gatts_event_handler() in case of an
 * ESP_GATTS_ADD_CHAR_DESCR_EVT, i.e. after a descriptor has been added.
 * It sets the .descr_handle variable of the current descriptor to the new
 * handle generated by the ESP32. Finally, gatts_add_descr() is called again to
 * add any further descriptors to the current characteristic.
 */
static void gatts_check_add_descr(esp_bt_uuid_t descr_uuid, uint16_t attr_handle) {

	ESP_LOGI(GATTS_TAG, "gatts_check_add_descr: descr handle %d", attr_handle);
	if (attr_handle != 0) {
		if (descr_uuid.len == ESP_UUID_LEN_16) {
			ESP_LOGI(GATTS_TAG, "Char UUID16: %x", descr_uuid.uuid.uuid16);
		} else if (descr_uuid.len == ESP_UUID_LEN_32) {
			ESP_LOGI(GATTS_TAG, "Char UUID32: %x", descr_uuid.uuid.uuid32);
		} else if (descr_uuid.len == ESP_UUID_LEN_128) {
			ESP_LOGI(GATTS_TAG, "Char UUID128: %x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x", descr_uuid.uuid.uuid128[0],
					 descr_uuid.uuid.uuid128[1], descr_uuid.uuid.uuid128[2], descr_uuid.uuid.uuid128[3],
					 descr_uuid.uuid.uuid128[4], descr_uuid.uuid.uuid128[5], descr_uuid.uuid.uuid128[6],
					 descr_uuid.uuid.uuid128[7], descr_uuid.uuid.uuid128[8], descr_uuid.uuid.uuid128[9],
					 descr_uuid.uuid.uuid128[10], descr_uuid.uuid.uuid128[11], descr_uuid.uuid.uuid128[12],
					 descr_uuid.uuid.uuid128[13], descr_uuid.uuid.uuid128[14], descr_uuid.uuid.uuid128[15]);
		} else {
			ESP_LOGE(GATTS_TAG, "Descriptor UNKNOWN LEN %d\n", descr_uuid.len);
		}
		ESP_LOGI(GATTS_TAG, "gatts_check_add_descr: found descr pos %d, handle %d\n", ble_add_descr_pos, attr_handle);
		gatts_descr[ble_add_descr_pos].descr_handle=attr_handle;
	}
	gatts_add_descr(); // try to add more descriptors
}


static void gatts_update_char_len(){
	for (uint32_t pos=0;pos<GATTS_CHAR_NUM;pos++) {
		gatts_char[pos].char_val->attr_len = strlen((const char*)(gatts_char[pos].char_val->attr_value));
	}
}


/* This function is called whenever the ESP32 bluetooth stack generates a GATT
 * event.
 */
void gatts_event_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param) {
	ESP_LOGI(GATTS_TAG, "gatts_event_handler: reg.app_id: %d", param->reg.app_id);

	switch (event) {
	case ESP_GATTS_REG_EVT:
		ESP_LOGI(GATTS_TAG, "REGISTER_APP_EVT, status %d, app_id %d", param->reg.status, param->reg.app_id);

		if (param->reg.status == ESP_GATT_OK) {
			gatts_service[param->reg.app_id].gatts_if = gatts_if;
		} else {
			ESP_LOGI(GATTS_TAG, "Reg app failed, app_id %04x, status %d\n", param->reg.app_id, param->reg.status);
			return;
		}

		ble_add_service_pos = param->reg.app_id;
		//printf("\nPOSIZIONE: %d\n",ble_add_service_pos);
		gatts_service[param->reg.app_id].service_id.is_primary = true;
		gatts_service[param->reg.app_id].service_id.id.inst_id = 0x00;
		gatts_service[param->reg.app_id].service_id.id.uuid.len = ESP_UUID_LEN_128;
		for (uint8_t pos=0;pos<ESP_UUID_LEN_128;pos++) {
			// copy correct part of ble_service_uuid128 byte by byte into the service struct
			gatts_service[param->reg.app_id].service_id.id.uuid.uuid.uuid128[pos]=ble_service_uuid128[pos+16*param->reg.app_id];
			ESP_LOGI(GATTS_TAG, "Service %d UUID pos %d: %02x", param->reg.app_id, pos, ble_service_uuid128[pos+16*param->reg.app_id]);
		}

		ESP_LOGI(GATTS_TAG, "ble_service_uuid128[0] %d, gatts_service[param].uuid128[0] %d, gatts_service[ble_pos].uuid128[0] %d", ble_service_uuid128[0], gatts_service[param->reg.app_id].service_id.id.uuid.uuid.uuid128[0], gatts_service[ble_add_service_pos].service_id.id.uuid.uuid.uuid128[0]);

		esp_ble_gatts_create_service(gatts_if, &gatts_service[param->reg.app_id].service_id, gatts_service[param->reg.app_id].num_handles);
		break;
	case ESP_GATTS_READ_EVT: {
		ESP_LOGI(GATTS_TAG, "GATT_READ_EVT, conn_id %d, trans_id %d, handle %d", param->read.conn_id, param->read.trans_id, param->read.handle);
		gatts_read_value_handler(event, gatts_if, param);
		break;
	}
	case ESP_GATTS_WRITE_EVT: {
		ESP_LOGI(GATTS_TAG, "GATT_WRITE_EVT, conn_id %d, trans_id %d, handle %d", param->write.conn_id, param->write.trans_id, param->write.handle);
		ESP_LOGI(GATTS_TAG, "GATT_WRITE_EVT, value len %d, value %08x", param->write.len, *(uint32_t *)param->write.value);
		gatts_write_value_handler(event, gatts_if, param);
		break;
	}
	case ESP_GATTS_EXEC_WRITE_EVT:{
        printf("\nEXECUTE WRITE REQUEST:\n");
		ESP_LOGI(GATTS_TAG,"ESP_GATTS_EXEC_WRITE_EVT");
        esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, ESP_GATT_OK, NULL);

        example_exec_write_event_env(&buff_prepare_write_env, param);
        break;
	}
	case ESP_GATTS_MTU_EVT:
	case ESP_GATTS_CONF_EVT:
	case ESP_GATTS_UNREG_EVT:
		break;
	case ESP_GATTS_CREATE_EVT:
		ESP_LOGI(GATTS_TAG, "CREATE_SERVICE_EVT, service %d, status %d,  service_handle %d", ble_add_service_pos, param->create.status, param->create.service_handle);
		ESP_LOGI(GATTS_TAG, "ble_add_service_pos: %d, param->reg.app_id: %d", ble_add_service_pos, param->reg.app_id);
		gatts_service[ble_add_service_pos].service_handle = param->create.service_handle;
		ESP_LOGI(GATTS_TAG, "param->create.service_handle %d, gatts_service[param->reg.app_id].service_handle %d, gatts_service[ble_add_service_pos].service_handle %d\n", param->create.service_handle, gatts_service[param->reg.app_id].service_handle, gatts_service[ble_add_service_pos].service_handle);

		esp_ble_gatts_start_service(gatts_service[ble_add_service_pos].service_handle);
		gatts_add_char();

		gatts_update_char_len(); //messo io per aggiornare il campo length delle caratteristiche

		break;
	case ESP_GATTS_ADD_INCL_SRVC_EVT:
		break;
	case ESP_GATTS_ADD_CHAR_EVT: {
		ESP_LOGI(GATTS_TAG, "ADD_CHAR_EVT, status 0x%X,  attr_handle %d, service_handle %d",
				param->add_char.status, param->add_char.attr_handle, param->add_char.service_handle);
		if (param->add_char.status==ESP_GATT_OK) {
			gatts_check_add_char(param->add_char.char_uuid,param->add_char.attr_handle);
		}
		break;
	}
	case ESP_GATTS_ADD_CHAR_DESCR_EVT:
		ESP_LOGI(GATTS_TAG, "ADD_DESCR_EVT char, status %d, attr_handle %d, service_handle %d",
				param->add_char.status, param->add_char.attr_handle, param->add_char.service_handle);
		ESP_LOGI(GATTS_TAG, "ADD_DESCR_EVT desc, status %d, attr_handle %d, service_handle %d\n",
				param->add_char_descr.status, param->add_char_descr.attr_handle, param->add_char_descr.service_handle);
		if (param->add_char_descr.status==ESP_GATT_OK) {
			gatts_check_add_descr(param->add_char.char_uuid,param->add_char.attr_handle);
		}
		break;
	case ESP_GATTS_DELETE_EVT:
		break;
	case ESP_GATTS_START_EVT:
		ESP_LOGI(GATTS_TAG, "SERVICE_START_EVT, status %d, service_handle %d\n",
				param->start.status, param->start.service_handle);
		break;
	case ESP_GATTS_STOP_EVT:
		break;
	case ESP_GATTS_CONNECT_EVT: {
		esp_ble_conn_update_params_t conn_params = {0};
		memcpy(conn_params.bda, param->connect.remote_bda, sizeof(esp_bd_addr_t));
		/* For the IOS system, please reference the apple official documents about the ble connection parameters restrictions. */
		conn_params.latency = 0;
		conn_params.max_int = BLE_CONNECTED_MAX_INTERVAL;
		conn_params.min_int = BLE_CONNECTED_MIN_INTERVAL;
		conn_params.timeout = BLE_CONNECTED_TIMEOUT;
		ESP_LOGI(GATTS_TAG, "\nESP_GATTS_CONNECT_EVT, conn_id %d, remote %02x:%02x:%02x:%02x:%02x:%02x:\n",
				param->connect.conn_id,
				param->connect.remote_bda[0], param->connect.remote_bda[1], param->connect.remote_bda[2],
				param->connect.remote_bda[3], param->connect.remote_bda[4], param->connect.remote_bda[5]);
		gatts_service[ble_add_service_pos].conn_id = param->connect.conn_id;
		//start send the update connection parameters to the peer device.
		esp_ble_gap_update_conn_params(&conn_params);
		break;
	}
	case ESP_GATTS_DISCONNECT_EVT:
		ESP_LOGI(GATTS_TAG, "ESP_GATTS_DISCONNECT_EVT, disconnect reason 0x%x", param->disconnect.reason);
		esp_ble_gap_start_advertising(&adv_params);
		break;
	case ESP_GATTS_OPEN_EVT:
	case ESP_GATTS_CANCEL_OPEN_EVT:
	case ESP_GATTS_CLOSE_EVT:
	case ESP_GATTS_LISTEN_EVT:
	case ESP_GATTS_CONGEST_EVT:
	default:
		break;
	}
}


