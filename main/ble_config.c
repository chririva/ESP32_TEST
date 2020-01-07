/*
 * ble_config.c
 *
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
#include "esp_bt.h"
#include "esp_gap_ble_api.h"
#include "esp_bt_defs.h"
#include "esp_bt_main.h"
#include "esp_gatt_common_api.h"
#include "esp_gatts_api.h"
#include "ble_config.h"

#include "sdkconfig.h"

//CARATTERISTICHE
//SERVICE 1
uint8_t service1_master_pubkey_str[GATTS_CHAR_PUBKEY_LEN_MAX] = {0x22};
uint8_t service1_master_certificate1_str[GATTS_CHAR_CERTIFICATE_LEN_MAX] = "CertM1";
uint8_t service1_master_certificate2_str[GATTS_CHAR_CERTIFICATE_LEN_MAX] = "CertM2";
uint8_t service1_master_certificate3_str[GATTS_CHAR_CERTIFICATE_LEN_MAX] = "CertM3";
uint8_t service1_info_str[GATTS_CHAR_INFO32_LEN_MAX] = "No info";
//SERVICE 2
uint8_t service2_master_pubkey_str[GATTS_CHAR_PUBKEY_LEN_MAX] = {0x11,0x22,0x55};
uint8_t service2_master_certificate1_str[GATTS_CHAR_CERTIFICATE_LEN_MAX] = {0x01};
uint8_t service2_master_certificate2_str[GATTS_CHAR_CERTIFICATE_LEN_MAX] = {0x02};
uint8_t service2_master_certificate3_str[GATTS_CHAR_CERTIFICATE_LEN_MAX] = {0x03};
uint8_t service2_slave_pubkey_str[GATTS_CHAR_PUBKEY_LEN_MAX] = {0x11,0x22,0x33};
uint8_t service2_slave_certificate1_str[GATTS_CHAR_CERTIFICATE_LEN_MAX] = {0x01};
uint8_t service2_slave_certificate2_str[GATTS_CHAR_CERTIFICATE_LEN_MAX] = {0x01};
uint8_t service2_slave_certificate3_str[GATTS_CHAR_CERTIFICATE_LEN_MAX] = {0x01};
uint8_t service2_random_str[GATTS_CHAR_RND_LEN_MAX] = "randomstring";
uint8_t service2_random_signed_str[GATTS_CHAR_RND_LEN_MAX] = {0x11,0x22,0x33};
uint8_t service2_info_str[GATTS_CHAR_INFO32_LEN_MAX] = "ready";

//DESCRITTORI
//SERVICE 1
uint8_t service1_master_pubkey_descr_user_str[12] = "Master pkey";
uint8_t service1_master_certificate_descr_user_str[19] = "Master Certificate";
uint8_t service1_info_descr_user_str[5] = "Info";
//SERVICE 2
uint8_t service2_master_pubkey_descr_user_str[12] = "Master pkey";
uint8_t service2_master_certificate_descr_user_str[19] = "Master Certificate";
uint8_t service2_slave_pubkey_descr_user_str[11] = "Slave pkey";
uint8_t service2_slave_certificate_descr_user_str[18] = "Slave Certificate";
uint8_t service2_random_descr_user_str[7] = "Random";
uint8_t service2_random_signed_descr_user_str[14] = "Random signed";
uint8_t service2_info_descr_user_str[5] = "Info";


//SERVICE 1
esp_attr_value_t gatts_service1_master_pubkey_val =
{
    .attr_max_len = GATTS_CHAR_PUBKEY_LEN_MAX,
    .attr_len     = sizeof(service1_master_pubkey_str),
    .attr_value   = service1_master_pubkey_str,
};
esp_attr_value_t gatts_service1_master_pubkey_descr_user_val =
{
    .attr_max_len = GATTS_CHAR_VAL_LEN_MAX,
    .attr_len     = sizeof(service1_master_pubkey_descr_user_str),
    .attr_value   = service1_master_pubkey_descr_user_str,
};

esp_attr_value_t gatts_service1_master_certificate1_val =
{
    .attr_max_len = GATTS_CHAR_CERTIFICATE_LEN_MAX,
    .attr_len     = sizeof(service1_master_certificate1_str),
    .attr_value   = service1_master_certificate1_str,
};
esp_attr_value_t gatts_service1_master_certificate_descr_user_val =
{
    .attr_max_len = GATTS_CHAR_VAL_LEN_MAX,
    .attr_len     = sizeof(service1_master_certificate_descr_user_str),
    .attr_value   = service1_master_certificate_descr_user_str,
};

esp_attr_value_t gatts_service1_master_certificate2_val =
{
    .attr_max_len = GATTS_CHAR_CERTIFICATE_LEN_MAX,
    .attr_len     = sizeof(service1_master_certificate2_str),
    .attr_value   = service1_master_certificate2_str,
};

esp_attr_value_t gatts_service1_master_certificate3_val =
{
    .attr_max_len = GATTS_CHAR_CERTIFICATE_LEN_MAX,
    .attr_len     = sizeof(service1_master_certificate3_str),
    .attr_value   = service1_master_certificate3_str,
};

esp_attr_value_t gatts_service1_info_val =
{
    .attr_max_len = GATTS_CHAR_INFO32_LEN_MAX, //crea define
    .attr_len     = sizeof(service1_info_str),
    .attr_value   = service1_info_str,
};
esp_attr_value_t gatts_service1_info_descr_user_val =
{
    .attr_max_len = GATTS_CHAR_VAL_LEN_MAX,
    .attr_len     = sizeof(service1_info_descr_user_str),
    .attr_value   = service1_info_descr_user_str,
};

//SERVICE 2
esp_attr_value_t gatts_service2_master_pubkey_val =
{
    .attr_max_len = GATTS_CHAR_PUBKEY_LEN_MAX,
    .attr_len     = sizeof(service2_master_pubkey_str),
    .attr_value   = service2_master_pubkey_str,
};
esp_attr_value_t gatts_service2_master_pubkey_descr_user_val =
{
    .attr_max_len = GATTS_CHAR_VAL_LEN_MAX,
    .attr_len     = sizeof(service2_master_pubkey_descr_user_str),
    .attr_value   = service2_master_pubkey_descr_user_str,
};

esp_attr_value_t gatts_service2_master_certificate1_val =
{
    .attr_max_len = GATTS_CHAR_CERTIFICATE_LEN_MAX,
    .attr_len     = sizeof(service2_master_certificate1_str),
    .attr_value   = service2_master_certificate1_str,
};
esp_attr_value_t gatts_service2_master_certificate_descr_user_val =
{
    .attr_max_len = GATTS_CHAR_VAL_LEN_MAX,
    .attr_len     = sizeof(service2_master_certificate_descr_user_str),
    .attr_value   = service2_master_certificate_descr_user_str,
};

esp_attr_value_t gatts_service2_master_certificate2_val =
{
    .attr_max_len = GATTS_CHAR_CERTIFICATE_LEN_MAX,
    .attr_len     = sizeof(service2_master_certificate2_str),
    .attr_value   = service2_master_certificate2_str,
};

esp_attr_value_t gatts_service2_master_certificate3_val =
{
    .attr_max_len = GATTS_CHAR_CERTIFICATE_LEN_MAX,
    .attr_len     = sizeof(service2_master_certificate3_str),
    .attr_value   = service2_master_certificate3_str,
};

esp_attr_value_t gatts_service2_slave_pubkey_val =
{
    .attr_max_len = GATTS_CHAR_PUBKEY_LEN_MAX,
    .attr_len     = sizeof(service2_slave_pubkey_str),
    .attr_value   = service2_slave_pubkey_str,
};
esp_attr_value_t gatts_service2_slave_pubkey_descr_user_val =
{
    .attr_max_len = GATTS_CHAR_VAL_LEN_MAX,
    .attr_len     = sizeof(service2_slave_pubkey_descr_user_str),
    .attr_value   = service2_slave_pubkey_descr_user_str,
};

esp_attr_value_t gatts_service2_slave_certificate1_val =
{
    .attr_max_len = GATTS_CHAR_CERTIFICATE_LEN_MAX,
    .attr_len     = sizeof(service2_slave_certificate1_str),
    .attr_value   = service2_slave_certificate1_str,
};
esp_attr_value_t gatts_service2_slave_certificate_descr_user_val =
{
    .attr_max_len = GATTS_CHAR_VAL_LEN_MAX,
    .attr_len     = sizeof(service2_slave_certificate_descr_user_str),
    .attr_value   = service2_slave_certificate_descr_user_str,
};

esp_attr_value_t gatts_service2_slave_certificate2_val =
{
    .attr_max_len = GATTS_CHAR_CERTIFICATE_LEN_MAX,
    .attr_len     = sizeof(service2_slave_certificate2_str),
    .attr_value   = service2_slave_certificate2_str,
};

esp_attr_value_t gatts_service2_slave_certificate3_val =
{
    .attr_max_len = GATTS_CHAR_CERTIFICATE_LEN_MAX,
    .attr_len     = sizeof(service2_slave_certificate3_str),
    .attr_value   = service2_slave_certificate3_str,
};

esp_attr_value_t gatts_service2_random_val =
{
    .attr_max_len = GATTS_CHAR_RND_LEN_MAX,
    .attr_len     = sizeof(service2_random_str),
    .attr_value   = service2_random_str,
};
esp_attr_value_t gatts_service2_random_descr_user_val =
{
    .attr_max_len = GATTS_CHAR_VAL_LEN_MAX,
    .attr_len     = sizeof(service2_random_descr_user_str),
    .attr_value   = service2_random_descr_user_str,
};

esp_attr_value_t gatts_service2_random_signed_val =
{
    .attr_max_len = GATTS_CHAR_RND_LEN_MAX,
    .attr_len     = sizeof(service2_random_signed_str),
    .attr_value   = service2_random_signed_str,
};
esp_attr_value_t gatts_service2_random_signed_descr_user_val =
{
    .attr_max_len = GATTS_CHAR_VAL_LEN_MAX,
    .attr_len     = sizeof(service2_random_signed_descr_user_str),
    .attr_value   = service2_random_signed_descr_user_str,
};

esp_attr_value_t gatts_service2_info_val =
{
    .attr_max_len = GATTS_CHAR_INFO32_LEN_MAX,
    .attr_len     = sizeof(service2_info_str),
    .attr_value   = service2_info_str,
};
esp_attr_value_t gatts_service2_info_descr_user_val =
{
    .attr_max_len = GATTS_CHAR_VAL_LEN_MAX,
    .attr_len     = sizeof(service2_info_descr_user_str),
    .attr_value   = service2_info_descr_user_str,
};

/* To define each of our services, we just set the .gatts_if to none and the
 * number of handles this service will use as calculated in ble_config.h
 * The gatts_event_handler() below will take care of setting all the values
 * when the service is initialised.
 *
 * 1st service: Service1
 * 2nd service: Service2
 */
struct gatts_service_inst gatts_service[GATTS_SERVICE_NUM] = {
		{
				.gatts_if = ESP_GATT_IF_NONE,       /* gatts_if not known yet, so initial is ESP_GATT_IF_NONE */
				.num_handles = GATTS_SERVICE1_NUM_HANDLES
		},
		{
				.gatts_if = ESP_GATT_IF_NONE,       /* gatts_if not known yet, so initial is ESP_GATT_IF_NONE */
				.num_handles = GATTS_SERVICE2_NUM_HANDLES
		}
};


/* Here we define all the characteristics for all the services.
 * To associate a characteristic with its service, set the .service_pos to the
 * corresponding index in the gatts_service array above:
 * 0 = 1st service, 1 = 2nd service, ...
 *
 * Standard bluetooth characteristics such as "Battery level" (see
 * https://www.bluetooth.com/specifications/gatt/characteristics) use a 16 bit
 * UUID. For custom characteristics, we have to use a random 128 bit UUID as
 * generated by https://www.uuidgenerator.net/ .
 * For better readability, our random UUIDs are defined in ble_server.h .
 *
 * The .char_handle is set automatically by the gatts_check_add_char() function
 * below, once the characteristic has been added to the service.
 *
 * .char_nvs is the key under which the characteristic's value is stored in NVS.
 * Its maximum length is 15 bytes (=15 characters). The array is 16 bytes long
 * instead of just 15, because a string we add to it will be null-terminated
 * (\0 is automatically added as last element. Set it to "" when the
 * value is not stored in NVS.
 */
struct gatts_char_inst gatts_char[GATTS_CHAR_NUM] = {
		//SERVICE 1
		{
				/* Service1 -> Master puclic key */
				.service_pos = 0, // Service1
				.char_uuid.len = ESP_UUID_LEN_128, // Custom characteristic -> 128bit UUID
				.char_uuid.uuid.uuid128 = GATTS_SERVICE1_MASTER_PUBKEY_CHAR_UUID,
				.char_perm = ESP_GATT_PERM_WRITE_ENCRYPTED,
				.char_property = ESP_GATT_CHAR_PROP_BIT_WRITE,
				.char_val = &gatts_service1_master_pubkey_val,
				.char_control = NULL,
				.char_handle = 0,
				.char_nvs = ""
		},
		{
				/* Service1 -> Master certificate PART1 */
				.service_pos = 0, // Service1
				.char_uuid.len = ESP_UUID_LEN_128, // Custom characteristic -> 128bit UUID
				.char_uuid.uuid.uuid128 = GATTS_SERVICE1_MASTER_CERTIFICATE1_CHAR_UUID,
				.char_perm = ESP_GATT_PERM_READ_ENCRYPTED,
				.char_property = ESP_GATT_CHAR_PROP_BIT_READ,
				.char_val = &gatts_service1_master_certificate1_val,
				.char_control = NULL,
				.char_handle = 0,
				.char_nvs = ""
		},
		{
				/* Service1 -> Master certificate PART2 */
				.service_pos = 0, // Service1
				.char_uuid.len = ESP_UUID_LEN_128, // Custom characteristic -> 128bit UUID
				.char_uuid.uuid.uuid128 = GATTS_SERVICE1_MASTER_CERTIFICATE2_CHAR_UUID,
				.char_perm = ESP_GATT_PERM_READ_ENCRYPTED,
				.char_property = ESP_GATT_CHAR_PROP_BIT_READ,
				.char_val = &gatts_service1_master_certificate2_val,
				.char_control = NULL,
				.char_handle = 0,
				.char_nvs = ""
		},
		{
				/* Service1 -> Master certificate PART3 */
				.service_pos = 0, // Service1
				.char_uuid.len = ESP_UUID_LEN_128, // Custom characteristic -> 128bit UUID
				.char_uuid.uuid.uuid128 = GATTS_SERVICE1_MASTER_CERTIFICATE3_CHAR_UUID,
				.char_perm = ESP_GATT_PERM_READ_ENCRYPTED,
				.char_property = ESP_GATT_CHAR_PROP_BIT_READ,
				.char_val = &gatts_service1_master_certificate3_val,
				.char_control = NULL,
				.char_handle = 0,
				.char_nvs = ""
		},
		{
				/* Service1 -> Info */
				.service_pos = 0, // Service1
				.char_uuid.len = ESP_UUID_LEN_128, // Custom characteristic -> 128bit UUID
				.char_uuid.uuid.uuid128 = GATTS_SERVICE1_INFO_CHAR_UUID,
				.char_perm = ESP_GATT_PERM_READ_ENCRYPTED,
				.char_property = ESP_GATT_CHAR_PROP_BIT_READ,
				.char_val = &gatts_service1_info_val,
				.char_control = NULL,
				.char_handle = 0,
				.char_nvs = ""
		},
		//SERVICE 2
		{
				/* Service2 -> Master puclic key */
				.service_pos = 1, // Service2
				.char_uuid.len = ESP_UUID_LEN_128, // Custom characteristic -> 128bit UUID
				.char_uuid.uuid.uuid128 = GATTS_SERVICE2_MASTER_PUBKEY_CHAR_UUID,
				.char_perm = ESP_GATT_PERM_WRITE_ENCRYPTED,
				.char_property = ESP_GATT_CHAR_PROP_BIT_WRITE,
				.char_val = &gatts_service2_master_pubkey_val,
				.char_control = NULL,
				.char_handle = 0,
				.char_nvs = ""
		},
		{
				/* Service2 -> Master certificate PART1*/
				.service_pos = 1, // Service2
				.char_uuid.len = ESP_UUID_LEN_128, // Custom characteristic -> 128bit UUID
				.char_uuid.uuid.uuid128 = GATTS_SERVICE2_MASTER_CERTIFICATE1_CHAR_UUID,
				.char_perm = ESP_GATT_PERM_WRITE_ENCRYPTED,
				.char_property = ESP_GATT_CHAR_PROP_BIT_WRITE,
				.char_val = &gatts_service2_master_certificate1_val,
				.char_control = NULL,
				.char_handle = 0,
				.char_nvs = ""
		},
		{
				/* Service2 -> Master certificate PART2*/
				.service_pos = 1, // Service2
				.char_uuid.len = ESP_UUID_LEN_128, // Custom characteristic -> 128bit UUID
				.char_uuid.uuid.uuid128 = GATTS_SERVICE2_MASTER_CERTIFICATE2_CHAR_UUID,
				.char_perm = ESP_GATT_PERM_WRITE_ENCRYPTED,
				.char_property = ESP_GATT_CHAR_PROP_BIT_WRITE,
				.char_val = &gatts_service2_master_certificate2_val,
				.char_control = NULL,
				.char_handle = 0,
				.char_nvs = ""
		},
		{
				/* Service2 -> Master certificate PART3*/
				.service_pos = 1, // Service2
				.char_uuid.len = ESP_UUID_LEN_128, // Custom characteristic -> 128bit UUID
				.char_uuid.uuid.uuid128 = GATTS_SERVICE2_MASTER_CERTIFICATE3_CHAR_UUID,
				.char_perm = ESP_GATT_PERM_WRITE_ENCRYPTED,
				.char_property = ESP_GATT_CHAR_PROP_BIT_WRITE,
				.char_val = &gatts_service2_master_certificate3_val,
				.char_control = NULL,
				.char_handle = 0,
				.char_nvs = ""
		},
		{
				/* Service1 -> Slave public key */
				.service_pos = 1, // Service2
				.char_uuid.len = ESP_UUID_LEN_128, // Custom characteristic -> 128bit UUID
				.char_uuid.uuid.uuid128 = GATTS_SERVICE2_SLAVE_PUBKEY_CHAR_UUID,
				.char_perm = ESP_GATT_PERM_WRITE_ENCRYPTED,
				.char_property = ESP_GATT_CHAR_PROP_BIT_WRITE,
				.char_val = &gatts_service2_slave_pubkey_val,
				.char_handle = 0,
				.char_nvs = ""
		},
		{
				/* Service1 -> Slave certificate PART1*/
				.service_pos = 1, // Service2
				.char_uuid.len = ESP_UUID_LEN_128, // Custom characteristic -> 128bit UUID
				.char_uuid.uuid.uuid128 = GATTS_SERVICE2_SLAVE_CERTIFICATE1_CHAR_UUID,
				.char_perm = ESP_GATT_PERM_WRITE_ENCRYPTED,
				.char_property = ESP_GATT_CHAR_PROP_BIT_WRITE,
				.char_val = &gatts_service2_slave_certificate1_val,
				.char_control = NULL,
				.char_handle = 0,
				.char_nvs = ""
		},
		{
				/* Service1 -> Slave certificate PART2*/
				.service_pos = 1, // Service2
				.char_uuid.len = ESP_UUID_LEN_128, // Custom characteristic -> 128bit UUID
				.char_uuid.uuid.uuid128 = GATTS_SERVICE2_SLAVE_CERTIFICATE2_CHAR_UUID,
				.char_perm = ESP_GATT_PERM_WRITE_ENCRYPTED,
				.char_property = ESP_GATT_CHAR_PROP_BIT_WRITE,
				.char_val = &gatts_service2_slave_certificate2_val,
				.char_control = NULL,
				.char_handle = 0,
				.char_nvs = ""
		},
		{
				/* Service1 -> Slave certificate PART3*/
				.service_pos = 1, // Service2
				.char_uuid.len = ESP_UUID_LEN_128, // Custom characteristic -> 128bit UUID
				.char_uuid.uuid.uuid128 = GATTS_SERVICE2_SLAVE_CERTIFICATE3_CHAR_UUID,
				.char_perm = ESP_GATT_PERM_WRITE_ENCRYPTED,
				.char_property = ESP_GATT_CHAR_PROP_BIT_WRITE,
				.char_val = &gatts_service2_slave_certificate3_val,
				.char_control = NULL,
				.char_handle = 0,
				.char_nvs = ""
		},
		{
				/* Service1 -> Random */
				.service_pos = 1, // Service2
				.char_uuid.len = ESP_UUID_LEN_128, // Custom characteristic -> 128bit UUID
				.char_uuid.uuid.uuid128 = GATTS_SERVICE2_RANDOM_CHAR_UUID,
				.char_perm = ESP_GATT_PERM_READ_ENCRYPTED,
				.char_property = ESP_GATT_CHAR_PROP_BIT_READ,
				.char_val = &gatts_service2_random_val,
				.char_control = NULL,
				.char_handle = 0,
				.char_nvs = ""
		},
		{
				/* Service1 -> Random Signed */
				.service_pos = 1, // Service2
				.char_uuid.len = ESP_UUID_LEN_128, // Custom characteristic -> 128bit UUID
				.char_uuid.uuid.uuid128 = GATTS_SERVICE2_RANDOM_SIGNED_CHAR_UUID,
				.char_perm = ESP_GATT_PERM_WRITE_ENCRYPTED,
				.char_property = ESP_GATT_CHAR_PROP_BIT_WRITE,
				.char_val = &gatts_service2_random_signed_val,
				.char_handle = 0,
				.char_nvs = ""
		},
		{
				/* Service1 -> Info */
				.service_pos = 1, // Service2
				.char_uuid.len = ESP_UUID_LEN_128, // Custom characteristic -> 128bit UUID
				.char_uuid.uuid.uuid128 = GATTS_SERVICE2_INFO_CHAR_UUID,
				.char_perm = ESP_GATT_PERM_READ_ENCRYPTED,
				.char_property = ESP_GATT_CHAR_PROP_BIT_READ,
				.char_val = &gatts_service2_info_val,
				.char_handle = 0,
				.char_nvs = ""
		},
};

/* Here we define all the descriptors for all the characteristics.
 * To associate a descriptor to a characteristic, set the .char_pos to the
 * corresponding index in the gl_char array above:
 * 0 = 1st characteristic, 1 = 2nd characteristic, ...
 *
 * All we use here are standard bluetooth descriptors (see
 * https://www.bluetooth.com/specifications/gatt/descriptors) with a 16 bit
 * UUID.
 *
 * The .descr_handle is set automatically by the gatts_check_add_descr()
 * function below, once the descriptor has been added to the characteristic.
 */
struct gatts_descr_inst gatts_descr[GATTS_DESCR_NUM] = {
		//SERVICE 1
		{
				/* Service1 -> Master puclic key */
				.char_pos=0,
				.descr_uuid.len = ESP_UUID_LEN_16,
				.descr_uuid.uuid.uuid16 = ESP_GATT_UUID_CHAR_DESCRIPTION,
				.descr_perm=ESP_GATT_PERM_READ,
				.descr_val = &gatts_service1_master_pubkey_descr_user_val,
				.descr_control=NULL,
				.descr_handle=0
		},
		{
				/* Service1 -> Master certificate */
				.char_pos=1,
				.descr_uuid.len = ESP_UUID_LEN_16,
				.descr_uuid.uuid.uuid16 = ESP_GATT_UUID_CHAR_DESCRIPTION,
				.descr_perm=ESP_GATT_PERM_READ,
				.descr_val = &gatts_service1_master_certificate_descr_user_val,
				.descr_control=NULL,
				.descr_handle=0
		},
		{
				/* Service1 -> Info */
				.char_pos=4,
				.descr_uuid.len = ESP_UUID_LEN_16,
				.descr_uuid.uuid.uuid16 = ESP_GATT_UUID_CHAR_DESCRIPTION,
				.descr_perm=ESP_GATT_PERM_READ,
				.descr_val = &gatts_service1_info_descr_user_val,
				.descr_control=NULL,
				.descr_handle=0
		},

		//SERVICE 2
		{
				/* Service2 -> Master puclic key */
				.char_pos=5,
				.descr_uuid.len = ESP_UUID_LEN_16,
				.descr_uuid.uuid.uuid16 = ESP_GATT_UUID_CHAR_DESCRIPTION,
				.descr_perm=ESP_GATT_PERM_READ,
				.descr_val = &gatts_service2_master_pubkey_descr_user_val,
				.descr_control=NULL,
				.descr_handle=0
		},
		{
				/* Service2 -> Master certificate */
				.char_pos=6,
				.descr_uuid.len = ESP_UUID_LEN_16,
				.descr_uuid.uuid.uuid16 = ESP_GATT_UUID_CHAR_DESCRIPTION,
				.descr_perm=ESP_GATT_PERM_READ,
				.descr_val = &gatts_service2_master_certificate_descr_user_val,
				.descr_control=NULL,
				.descr_handle=0
		},
		{
				/* Service2 -> Slave puclic key */
				.char_pos=9,
				.descr_uuid.len = ESP_UUID_LEN_16,
				.descr_uuid.uuid.uuid16 = ESP_GATT_UUID_CHAR_DESCRIPTION,
				.descr_perm=ESP_GATT_PERM_READ,
				.descr_val = &gatts_service2_slave_pubkey_descr_user_val,
				.descr_control=NULL,
				.descr_handle=0
		},
		{
				/* Service2 -> Slave certificate */
				.char_pos=10,
				.descr_uuid.len = ESP_UUID_LEN_16,
				.descr_uuid.uuid.uuid16 = ESP_GATT_UUID_CHAR_DESCRIPTION,
				.descr_perm=ESP_GATT_PERM_READ,
				.descr_val = &gatts_service2_slave_certificate_descr_user_val,
				.descr_control=NULL,
				.descr_handle=0
		},
		{
				/* Service2 -> Random */
				.char_pos=13,
				.descr_uuid.len = ESP_UUID_LEN_16,
				.descr_uuid.uuid.uuid16 = ESP_GATT_UUID_CHAR_DESCRIPTION,
				.descr_perm=ESP_GATT_PERM_READ,
				.descr_val = &gatts_service2_random_descr_user_val,
				.descr_control=NULL,
				.descr_handle=0
		},
		{
				/* Service2 -> Random signed */
				.char_pos=14,
				.descr_uuid.len = ESP_UUID_LEN_16,
				.descr_uuid.uuid.uuid16 = ESP_GATT_UUID_CHAR_DESCRIPTION,
				.descr_perm=ESP_GATT_PERM_READ,
				.descr_val = &gatts_service2_random_signed_descr_user_val,
				.descr_control=NULL,
				.descr_handle=0
		},
		{
				/* Service2 -> Info */
				.char_pos=15,
				.descr_uuid.len = ESP_UUID_LEN_16,
				.descr_uuid.uuid.uuid16 = ESP_GATT_UUID_CHAR_DESCRIPTION,
				.descr_perm=ESP_GATT_PERM_READ,
				.descr_val = &gatts_service2_info_descr_user_val,
				.descr_control=NULL,
				.descr_handle=0
		},
};



