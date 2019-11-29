/*
 * ble_config.h
 *
 *
 */

#ifndef MAIN_BLE_CONFIG_H_
#define MAIN_BLE_CONFIG_H_

#define GATTS_TAG "ESP32_GATTS"
#define TAG "ESP32_TAG"
#define DEVICE_NAME "TEST_ESP32"

#define GATTS_CHAR_VAL_LEN_MAX 50 //usato per i descrittori

#define GATTS_CHAR_INFO32_LEN_MAX 32 //32 bit per info
#define GATTS_CHAR_PUBKEY_LEN_MAX 520 //520 bit per chiavi pubbliche
#define GATTS_CHAR_CERTIFICATE_LEN_MAX 600 //600 bit per certificati
#define GATTS_CHAR_RND_LEN_MAX 100 //100 bit per random, random signed

#define GATTS_SERVICE_NUM 2
#define GATTS_CHAR_NUM 16 //numero di tutte le caratteristiche
#define GATTS_DESCR_NUM	10 //numero di tutti i descrittori

#define GATTS_SERVICE1_UUID			0x0c, 0xdf, 0x6a, 0x53, 0x8a, 0x6d, 0xbc, 0xb3, 0x99, 0x47, 0x24, 0x50, 0xb7, 0xa9, 0xb4, 0xec // random 128bit UUID for custom Teacher's Button Service: ecb4a9b7-5024-4799-b3bc-6d8a536adf0c
#define GATTS_SERVICE1_NUM_HANDLES	16 // 1 + 2*NUM_CHAR_S1 + NUM_DESCR_S1
#define GATTS_SERVICE2_UUID			0xc5, 0xb9, 0x31, 0x68, 0xfa, 0x31, 0x09, 0xa0, 0x8f, 0x42, 0xa5, 0xd3, 0xe9, 0x17, 0xe2, 0x0b // random 128bit UUID for custom Teacher's Button Service: 0be217e9-d3a5-428f-a009-31fa6831b9c5
#define GATTS_SERVICE2_NUM_HANDLES	30 // 1 + 2*NUM_CHAR_S1 + NUM_DESCR_S1

//UUID 128 di tutte le caratteristiche
#define GATTS_SERVICE1_MASTER_PUBKEY_CHAR_UUID			{0x76, 0xf6, 0x15, 0x1d, 0xd9, 0x2f, 0x0f, 0x8d, 0x4c, 0x46, 0xf0, 0xe5, 0x00, 0x00, 0x0b, 0x67} // random 128bit UUID: 670b0000-e5f0-464c-8d0f-2fd91d15f676
#define GATTS_SERVICE1_MASTER_CERTIFICATE1_CHAR_UUID	{0x76, 0xf6, 0x15, 0x1d, 0xd9, 0x2f, 0x0f, 0x8d, 0x4c, 0x46, 0xf0, 0xe5, 0x01, 0x00, 0x0b, 0x67} // random 128bit UUID: 670b0001-e5f0-464c-8d0f-2fd91d15f676
#define GATTS_SERVICE1_MASTER_CERTIFICATE2_CHAR_UUID	{0x76, 0xf6, 0x15, 0x1d, 0xd9, 0x2f, 0x0f, 0x8d, 0x4c, 0x46, 0xf0, 0xe5, 0x02, 0x00, 0x0b, 0x67} // random 128bit UUID: 670b0002-e5f0-464c-8d0f-2fd91d15f676
#define GATTS_SERVICE1_MASTER_CERTIFICATE3_CHAR_UUID	{0x76, 0xf6, 0x15, 0x1d, 0xd9, 0x2f, 0x0f, 0x8d, 0x4c, 0x46, 0xf0, 0xe5, 0x03, 0x00, 0x0b, 0x67} // random 128bit UUID: 670b0003-e5f0-464c-8d0f-2fd91d15f676
#define GATTS_SERVICE1_INFO_CHAR_UUID					{0x76, 0xf6, 0x15, 0x1d, 0xd9, 0x2f, 0x0f, 0x8d, 0x4c, 0x46, 0xf0, 0xe5, 0x04, 0x00, 0x0b, 0x67} // random 128bit UUID: 670b0004-e5f0-464c-8d0f-2fd91d15f676
//da generare
#define GATTS_SERVICE2_MASTER_PUBKEY_CHAR_UUID			{0x64, 0x5d, 0xff, 0x33, 0xd5, 0x2b, 0x42, 0xa1, 0xdc, 0x43, 0xce, 0x9f, 0x00, 0x00, 0x81, 0xc2} // random 128bit UUID: c2810000-9fce-43dc-a142-2bd533ff5d64
#define GATTS_SERVICE2_MASTER_CERTIFICATE1_CHAR_UUID	{0x64, 0x5d, 0xff, 0x33, 0xd5, 0x2b, 0x42, 0xa1, 0xdc, 0x43, 0xce, 0x9f, 0x01, 0x00, 0x81, 0xc2} // random 128bit UUID: c2810001-9fce-43dc-a142-2bd533ff5d64
#define GATTS_SERVICE2_MASTER_CERTIFICATE2_CHAR_UUID	{0x64, 0x5d, 0xff, 0x33, 0xd5, 0x2b, 0x42, 0xa1, 0xdc, 0x43, 0xce, 0x9f, 0x02, 0x00, 0x81, 0xc2} // random 128bit UUID: c2810002-9fce-43dc-a142-2bd533ff5d64
#define GATTS_SERVICE2_MASTER_CERTIFICATE3_CHAR_UUID	{0x64, 0x5d, 0xff, 0x33, 0xd5, 0x2b, 0x42, 0xa1, 0xdc, 0x43, 0xce, 0x9f, 0x03, 0x00, 0x81, 0xc2} // random 128bit UUID: c2810003-9fce-43dc-a142-2bd533ff5d64
#define GATTS_SERVICE2_SLAVE_PUBKEY_CHAR_UUID			{0x64, 0x5d, 0xff, 0x33, 0xd5, 0x2b, 0x42, 0xa1, 0xdc, 0x43, 0xce, 0x9f, 0x04, 0x00, 0x81, 0xc2} // random 128bit UUID: c2810004-9fce-43dc-a142-2bd533ff5d64
#define GATTS_SERVICE2_SLAVE_CERTIFICATE1_CHAR_UUID		{0x64, 0x5d, 0xff, 0x33, 0xd5, 0x2b, 0x42, 0xa1, 0xdc, 0x43, 0xce, 0x9f, 0x05, 0x00, 0x81, 0xc2} // random 128bit UUID: c2810005-9fce-43dc-a142-2bd533ff5d64
#define GATTS_SERVICE2_SLAVE_CERTIFICATE2_CHAR_UUID		{0x64, 0x5d, 0xff, 0x33, 0xd5, 0x2b, 0x42, 0xa1, 0xdc, 0x43, 0xce, 0x9f, 0x06, 0x00, 0x81, 0xc2} // random 128bit UUID: c2810006-9fce-43dc-a142-2bd533ff5d64
#define GATTS_SERVICE2_SLAVE_CERTIFICATE3_CHAR_UUID		{0x64, 0x5d, 0xff, 0x33, 0xd5, 0x2b, 0x42, 0xa1, 0xdc, 0x43, 0xce, 0x9f, 0x07, 0x00, 0x81, 0xc2} // random 128bit UUID: c2810007-9fce-43dc-a142-2bd533ff5d64
#define GATTS_SERVICE2_RANDOM_CHAR_UUID					{0x64, 0x5d, 0xff, 0x33, 0xd5, 0x2b, 0x42, 0xa1, 0xdc, 0x43, 0xce, 0x9f, 0x08, 0x00, 0x81, 0xc2} // random 128bit UUID: c2810008-9fce-43dc-a142-2bd533ff5d64
#define GATTS_SERVICE2_RANDOM_SIGNED_CHAR_UUID			{0x64, 0x5d, 0xff, 0x33, 0xd5, 0x2b, 0x42, 0xa1, 0xdc, 0x43, 0xce, 0x9f, 0x09, 0x00, 0x81, 0xc2} // random 128bit UUID: c2810009-9fce-43dc-a142-2bd533ff5d64
#define GATTS_SERVICE2_INFO_CHAR_UUID					{0x64, 0x5d, 0xff, 0x33, 0xd5, 0x2b, 0x42, 0xa1, 0xdc, 0x43, 0xce, 0x9f, 0x0a, 0x00, 0x81, 0xc2} // random 128bit UUID: c281000a-9fce-43dc-a142-2bd533ff5d64

#define BLE_CONNECTED_MAX_INTERVAL	0x20	// max_int = 0x20*1.25ms = 40ms
#define BLE_CONNECTED_MIN_INTERVAL	0x10	// min_int = 0x10*1.25ms = 20ms
#define BLE_CONNECTED_TIMEOUT		400		// timeout = 400*10ms = 4000ms

#define BLE_MANUFACTURER_DATA_LEN	2					// Length of the manufacturer specific advertising payload. Currently contains only the manufacturer ID (2 bytes)
#define BLE_MANUFACTURER_DATA		{0xFF, 0xFF}		// No manufacturer ID (see https://www.bluetooth.com/specifications/assigned-numbers/company-identifiers)

/* These structs define which attributes each service, characteristic or
 * descriptor have.
 * The individual services, characteristics and descriptors are then defined in
 * gatt_config.c
 */
struct gatts_service_inst {
	uint16_t gatts_if;
	uint16_t app_id;
	uint16_t conn_id;
	uint16_t service_handle;
	esp_gatt_srvc_id_t service_id;
	uint16_t num_handles;
};

struct gatts_char_inst {
	uint32_t service_pos;
	esp_bt_uuid_t char_uuid;
	esp_gatt_perm_t char_perm;
	esp_gatt_char_prop_t char_property;
	esp_attr_value_t *char_val;
	esp_attr_control_t *char_control;
	uint16_t char_handle;
	char char_nvs[16];
};

struct gatts_descr_inst {
	uint32_t char_pos;
	esp_bt_uuid_t descr_uuid;
	esp_gatt_perm_t descr_perm;
	esp_attr_value_t *descr_val;
	esp_attr_control_t *descr_control;
	uint16_t descr_handle;
};

extern struct gatts_service_inst gatts_service[];
extern struct gatts_char_inst gatts_char[];
extern struct gatts_descr_inst gatts_descr[];

#endif /* MAIN_BLE_CONFIG_H_ */
