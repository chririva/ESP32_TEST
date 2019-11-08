/*
 * main_app.c
 *
 * Entry Point
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
#include "esp_gatts_api.h"
#include "esp_bt_defs.h"
#include "esp_bt_main.h"
#include "esp_gatt_common_api.h"
#include "genera_chiave.c"
//#include "genera_chiave_ECDSA.c"
//#include "genera_chiave_rsa.c"
#include "selfsigned_cert_write.h"
#include "master_cert_write.h"
#include "slave_cert_write_DEBUG_TEST.h"
#include "cert_app.h"
#include <time.h>
#include <sys/time.h>


#include "sdkconfig.h"

#define GATTS_TAG "GATTS_DEMO"

///Declare the static function
static void gatts_profile_a_event_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param);

#define GATTS_SERVICE_UUID_TEST_A   0x00FF
#define GATTS_CHAR_UUID_TEST_A      0xFF01
#define GATTS_DESCR_UUID_TEST_A     0x3333
#define GATTS_NUM_HANDLE_TEST_A     4

#define TEST_DEVICE_NAME            "ESP_GATTS_DEMO"
#define TEST_MANUFACTURER_DATA_LEN  17

#define GATTS_DEMO_CHAR_VAL_LEN_MAX 0x40
#define GATT_SERVICE1_NUM_HANDLES 2

#define PREPARE_BUF_MAX_SIZE 1024

//CHIAVI DEL DISPOSITIVO
mbedtls_mpi N_key, P_key, Q_key, D_key, E_key, DP_key, DQ_key, QP_key; //Forse non verranno mai utilizzate
mbedtls_pk_context key_key, master_pub_key,slave_pub_key; //key_key è la chiave della esp. device_pub_key dello smartphone master
mbedtls_pk_context master_priv_key, slave_priv_key; //TODO: DA TOGLIERE, MI SERVE SOLO PER SIMULARLE LA CATENA DI CERTIFICATI
mbedtls_x509_crt self_certificate; //Self certificate della esp
mbedtls_x509_crt master_certificate; //Certificate dello smartphone master
mbedtls_x509_crt slave_certificate; //Certificate dello smartphone slave
unsigned char master_pub_key_string[] =  "-----BEGIN PUBLIC KEY-----\n"\
							    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0/ulB5uTYevMNjbPQNX0\n"\
								"k1GXNvFQDtScRDQA8StKZQ4ZBdpJKiIrlWMtRgpvmx7BJtshSHIzjAOx7EcOegCj\n"\
								"lpgG2KI/dvwaQak9PkZbyR47Uiwx+x4FOa8pM/UWurs/rkyrxXhPvUBftn8j1PQT\n"\
								"R3afl9PE0eKPTwYTEO1WbZbOCMiO3SKaNsaopuHTRcdQpjaT/nSqPGiBCEpfuw2D\n"\
								"snEkuLyh+LAALCLFvO4pXtcaXNzXz+G9h3rcb588Ebolns+ia5xVWM9oRbdXV8d+\n"\
								"uKk7HrG+t/Pk740dwfHa/cHwGqowXSxME6m7W7xfgA7HCG3OsjIY/yYDAIHu/QQM\n"\
								"hQIDAQAB\n"\
								"-----END PUBLIC KEY-----"; //TODO: Ricevere la vera chiave

unsigned char master_priv_key_string[] =  "-----BEGIN RSA PRIVATE KEY-----\n"\
							    "MIIEpAIBAAKCAQEA0/ulB5uTYevMNjbPQNX0k1GXNvFQDtScRDQA8StKZQ4ZBdpJ\n"\
								"KiIrlWMtRgpvmx7BJtshSHIzjAOx7EcOegCjlpgG2KI/dvwaQak9PkZbyR47Uiwx\n"\
								"+x4FOa8pM/UWurs/rkyrxXhPvUBftn8j1PQTR3afl9PE0eKPTwYTEO1WbZbOCMiO\n"\
								"3SKaNsaopuHTRcdQpjaT/nSqPGiBCEpfuw2DsnEkuLyh+LAALCLFvO4pXtcaXNzX\n"\
								"z+G9h3rcb588Ebolns+ia5xVWM9oRbdXV8d+uKk7HrG+t/Pk740dwfHa/cHwGqow\n"\
								"XSxME6m7W7xfgA7HCG3OsjIY/yYDAIHu/QQMhQIDAQABAoIBAQCN/LswWlOgvikd\n"\
								"kx7FJcpZNshbY80k8eHtiQusfjupboTyN6DUGOkqebCkfm787t+fYB1uAhhmyz7M\n"\
								"rVeT/oOUZiYHyr1JvFj17B76bHQkRRyk0Ld1pUkItzuY8qwTzUI9RFu1u/1lHQ4/\n"\
								"Fe/xPr7/GgSR1KW7k847tyzkJKTEZ4pZSuKH/1OVRc34F9YMUxGLWxRHcwMvfU6/\n"\
								"udDi4hSV5YLUYe5YlpKBPIeOfJPd16j5/GOrd4haF3zdecrxUOFTCsTc+zRc1s42\n"\
								"np9OE27RP9ELnfVWhJau2/za6RY9tQlUuO6Tq9hGZ6H4tQkjyZQFTWunN+sPTDvt\n"\
								"RdofLYmNAoGBAP0ih+xPvChwZpHKpRoMbEErOYNhP/Y7b5M9t3cHkXSmJWVXTD2W\n"\
								"KL5JvF8Qem/j3MYXjjyeKziLU+AVxpyXGBStzg7XPOFv7xkZFUE4+Sri4qsl8j58\n"\
								"9eJcij1Ru3es11Pd3O2Bz0OoHh/GqTtZs+dTNPD7bPvSEd0MVHzHv6NzAoGBANZh\n"\
								"39Pa+GB5ZJQSA4AxkE5N5iRgBbxVpdFp1QVay1WApu4NrAYynszIQvNX3EsHYcr0\n"\
								"2VR+5uVFTshNU8V3ixFJNM3J36thvu10I2JqBUmMr/lWteVo9A3PQYkc8KZmnvQl\n"\
								"4ZPYi08NxpyuvBuZ9Im33INu9ZMrmf5M25Cb98InAoGAMNNVRmaG04ICtsJQoDqf\n"\
								"Mt7EhCvg63zBY7Q2zBXAn7BgbDCvev2YtEOCuw9xnl1kOy1V+SlFCu4M6p8opRGb\n"\
								"ynlP0pr/mjg99Shaai80GGqU8BAsrpLp1pSk8XjvYQEMs5eKwqEUOmeWD+kAwXrm\n"\
								"8YqiHo1Qky4M1gdH0J2ywDMCgYEAxa7axnBUOCG4LRGvSLZraslKPqCMqW4QyVnd\n"\
								"pGJkvSM0yq6wwcZLyGmh0uJhsI3OD2hYPyIFp8SRMQKdDKl/AyGOH3TXWyF2/V7q\n"\
								"ggVhesDQRAtBD5oH8fP7aoPVJJvcVyXXLI2xZ+Q8EJ7PtmPwqk1weYIH0P2TsnsM\n"\
								"u/wWKmECgYBOEyb6gggg8pzO0m76v1jFdGgFWTeWiGVyvqn680BaTkl8m9Y8VSCr\n"\
								"vbBDrQdxyXybY1xDVcp5baTTCqBt5ADLHyoipDvT/4SM+jdYp2kM/xgHhupVKYwL\n"\
								"3BONrGy2mLSWFlyF+4C2CdJZM594bBmsrO3bsZni8Z5UhPRkfPkh1g==\n"\
								"-----END RSA PRIVATE KEY-----"; //TODO: Ricevere la vera chiave

unsigned char slave_pub_key_string[] =  "-----BEGIN PUBLIC KEY-----\n"\
							    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhGCqrEfcr4mdhJKqYqDb\n"\
								"Ele6K2hAzShC4NQQb0HTbprIRnQ/5b2FPcU0Rwu+EE6ntuKUvttRCPmdXFR3yrg3\n"\
							    "uPBedwDnBIOaQbH0CEliDu2I1hqsZTCfasdcwtRwNeqtljjQ4Zdn9HQXHJxs/ST9\n"\
								"1k9r2LGWwg8mZJ9CtF+rplFHCH0OhnCIWqqj0XWxh9EsplskfjWwo0vRnyZl9Bp2\n"\
							    "XVBtUhIhgZeeKMoPNodzCXhCZgcZKZB2wMkwJiPbfH/B1PApUvo8YQcUDrDOhwGp\n"\
								"jJfjR9GwQ1ehQgNb2Wk/Fk1GY3Zl363EzDMd79Xaofm2fwW6vG8dZm7agHJrg6km\n"\
							    "4QIDAQAB\n"\
								"-----END PUBLIC KEY-----"; //TODO: Ricevere la vera chiave

unsigned char slave_priv_key_string[] =  "-----BEGIN RSA PRIVATE KEY-----\n"\
							    "MIIEpAIBAAKCAQEAhGCqrEfcr4mdhJKqYqDbEle6K2hAzShC4NQQb0HTbprIRnQ/\n"\
							    "5b2FPcU0Rwu+EE6ntuKUvttRCPmdXFR3yrg3uPBedwDnBIOaQbH0CEliDu2I1hqs\n"\
								"ZTCfasdcwtRwNeqtljjQ4Zdn9HQXHJxs/ST91k9r2LGWwg8mZJ9CtF+rplFHCH0O\n"\
							    "hnCIWqqj0XWxh9EsplskfjWwo0vRnyZl9Bp2XVBtUhIhgZeeKMoPNodzCXhCZgcZ\n"\
								"KZB2wMkwJiPbfH/B1PApUvo8YQcUDrDOhwGpjJfjR9GwQ1ehQgNb2Wk/Fk1GY3Zl\n"\
							    "363EzDMd79Xaofm2fwW6vG8dZm7agHJrg6km4QIDAQABAoIBAAbRs/kL+qJQRHz/\n"\
								"0ScjgiV/v2ddB3mKCWfrhK02ht27u3Vlp6T+Dk8QSZEfWbsdUiZppZ/vTE1aDnEj\n"\
							    "KMiYlMZCG5ulwEDLRrb7o8aJgTOjqNjepuLPjmbBvlWK+/zLCgYjBx+X3RMKp+Yh\n"\
								"aLvhm/HeRX/0Jf/5J9EnIxiHlSAMHLPSRyISERHUl0zoDRDLrL2iPvL7GcH9JXcr\n"\
							    "8dLeCkdQ97ey8TRPgJcSK9P919547s7KeeUkgPQpDHY47FQWqq7rm/MijtBH229j\n"\
								"osaPqtCA1FCA8cftMGPrPvlny+LbaTzH8C3CaZf3CWPTOdL8y6Y+RRlabrsLjgtn\n"\
							    "5T3jcAECgYEAzwMh0x84qbxWVCdpkERB+rtA14m6u/BTIiGQ6MTPMYCJ/zSFMOrs\n"\
								"JcJcw1F/KD5VjT074P8+OTAoR24ViXsqNojCD754PYxgh0ZEvFstaEGDNPMu7PtA\n"\
							    "km5Gj+upMKjQnVq9mnxzPcOfHb+ln+QFWkqTxrS2OS5Db+eXLlsvfVECgYEAo7Ql\n"\
								"BHnu1dR/S+kvxZkJ7A5dSiHSjwFPecd8ip7s2bA+nf0ye5CMxFZx7gFq4YS0gZ3G\n"\
							    "68IZ98Bmn/pgoRgovwtmTKH3iO2fmF25jl1jUQ2IyiJ+MQQ5nLIYySZCsDKyVx+v\n"\
								"UaDorkjVaiHiwig4aBttdA8JkU06f+h7V2lVbJECgYEAsvTjNc7kvh85hhB4OqY3\n"\
							    "X5inKm0/R58vTu8zhXY2I3YaVcvCZJKByPaoGJWIVnLkpG/OJuigkvGlsHJjHfGi\n"\
								"gXhiQxgGfDaxb9/4JdiwfVM9KPYdl/JwVOYOC/bO0Wjux0kdZcK2ISvOjvoRJRMK\n"\
							    "6Y5VB89LRE1RMRlE4Wcku7ECgYEAggy627OCaZ1HA6dcrD3IBB/lPN9hxvnjiXtR\n"\
								"FU7sGoRJOnnLgR50tgV2vP2jS0WBoPcW8HRi7M+Mt8rQuSnYNO15d6e0XrNn9kN/\n"\
							    "BfpqzBlUckC0v3v7yOAzkJk0oYWk6FHjlZWfQ9XYtVf2LQiGxy4C5hCMKUKRFsw6\n"\
								"MFcd5gECgYADC1PZEnGuGDssFFoLL6fC6QdY7BGQbkiffmHRXqM0kzZioc/od5kX\n"\
							    "MWgsI/f1pwoDydVGEegldWHdY/X6EeGB1n9JFPO7XJR/VdOuWUeSUiVIaJW9ROmG\n"\
								"Eu90pcvHiqpfvpbf2950NP0eyUlUvjCeRewspt5buxwo4jKWfVEjbA==\n"\
								"-----END RSA PRIVATE KEY-----"; //TODO: Ricevere la vera chiave

bool wait_cert_app_master;
bool wait_cert_app_slave;
bool master_cert_validity, slave_cert_validity;


static uint8_t char1_str[] = {0x33,0x33,0x33};

static esp_gatt_char_prop_t a_property = 0;

static esp_attr_value_t gatts_demo_char1_val =
{
    .attr_max_len = GATTS_DEMO_CHAR_VAL_LEN_MAX,
    .attr_len     = sizeof(char1_str),
    .attr_value   = char1_str,
};
/*static esp_attr_value_t gatts_demo_char2_val =
{
    .attr_max_len = GATTS_DEMO_CHAR_VAL_LEN_MAX,
    .attr_len     = sizeof(char2_str),
    .attr_value   = char2_str,
};*/

static uint8_t adv_config_done = 0;
#define adv_config_flag      (1 << 0)
#define scan_rsp_config_flag (1 << 1)

#ifdef CONFIG_SET_RAW_ADV_DATA
static uint8_t raw_adv_data[] = {
        0x02, 0x01, 0x06,
        0x02, 0x0a, 0xeb, 0x03, 0x03, 0xab, 0xcd
};
static uint8_t raw_scan_rsp_data[] = {
        0x0f, 0x09, 0x45, 0x53, 0x50, 0x5f, 0x47, 0x41, 0x54, 0x54, 0x53, 0x5f, 0x44,
        0x45, 0x4d, 0x4f
};
#else

static uint8_t adv_service_uuid128[16] = {
    /* LSB <--------------------------------------------------------------------------------> MSB */
    //first uuid, 16bit, [12],[13] is the value
    0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0xEE, 0x00, 0x00, 0x00,
};

// The length of adv data must be less than 31 bytes
//static uint8_t test_manufacturer[TEST_MANUFACTURER_DATA_LEN] =  {0x12, 0x23, 0x45, 0x56};
//adv data
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
    .service_uuid_len = sizeof(adv_service_uuid128),
    .p_service_uuid = adv_service_uuid128,
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
    .service_uuid_len = sizeof(adv_service_uuid128),
    .p_service_uuid = adv_service_uuid128,
    .flag = (ESP_BLE_ADV_FLAG_GEN_DISC | ESP_BLE_ADV_FLAG_BREDR_NOT_SPT),
};

#endif /* CONFIG_SET_RAW_ADV_DATA */

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

#define PROFILE_NUM 1
#define PROFILE_A_APP_ID 0

struct gatts_profile_inst {
    esp_gatts_cb_t gatts_cb;
    uint16_t gatts_if;
    uint16_t app_id;
    uint16_t conn_id;
    uint16_t service_handle;
    esp_gatt_srvc_id_t service_id;
    uint16_t char_handle;
    esp_bt_uuid_t char_uuid;
    esp_gatt_perm_t perm;
    esp_gatt_char_prop_t property;
    uint16_t descr_handle;
    esp_bt_uuid_t descr_uuid;
    uint16_t num_handles; //messo io
};

//Per fare andare 2 applicazioni con profili diversi (sul client)
/* One gatt-based profile one app_id and one gatts_if, this array will store the gatts_if returned by ESP_GATTS_REG_EVT */
static struct gatts_profile_inst gl_profile_tab[PROFILE_NUM] = {
    [PROFILE_A_APP_ID] = {
        .gatts_cb = gatts_profile_a_event_handler,
        .gatts_if = ESP_GATT_IF_NONE,       /* Not get the gatt_if, so initial is ESP_GATT_IF_NONE */
		.num_handles = GATT_SERVICE1_NUM_HANDLES,
    },
};

typedef struct {
    uint8_t                 *prepare_buf;
    int                     prepare_len;
} prepare_type_env_t;

static prepare_type_env_t a_prepare_write_env;

void example_write_event_env(esp_gatt_if_t gatts_if, prepare_type_env_t *prepare_write_env, esp_ble_gatts_cb_param_t *param);
void example_exec_write_event_env(prepare_type_env_t *prepare_write_env, esp_ble_gatts_cb_param_t *param);

static void gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param)
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
    }else{
        ESP_LOGI(GATTS_TAG,"ESP_GATT_PREP_WRITE_CANCEL");
    }
    if (prepare_write_env->prepare_buf) {
        free(prepare_write_env->prepare_buf);
        prepare_write_env->prepare_buf = NULL;
    }
    prepare_write_env->prepare_len = 0;
}

//registering event handler
static void gatts_profile_a_event_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param) {
    switch (event) {
    case ESP_GATTS_REG_EVT:
        ESP_LOGI(GATTS_TAG, "REGISTER_APP_EVT, status %d, app_id %d\n", param->reg.status, param->reg.app_id);
        gl_profile_tab[PROFILE_A_APP_ID].service_id.is_primary = true;
        gl_profile_tab[PROFILE_A_APP_ID].service_id.id.inst_id = 0x00;
        gl_profile_tab[PROFILE_A_APP_ID].service_id.id.uuid.len = ESP_UUID_LEN_16;
        gl_profile_tab[PROFILE_A_APP_ID].service_id.id.uuid.uuid.uuid16 = GATTS_SERVICE_UUID_TEST_A;

        esp_err_t set_dev_name_ret = esp_ble_gap_set_device_name(TEST_DEVICE_NAME);
        if (set_dev_name_ret){
            ESP_LOGE(GATTS_TAG, "set device name failed, error code = %x", set_dev_name_ret);
        }
#ifdef CONFIG_SET_RAW_ADV_DATA
        esp_err_t raw_adv_ret = esp_ble_gap_config_adv_data_raw(raw_adv_data, sizeof(raw_adv_data));
        if (raw_adv_ret){
            ESP_LOGE(GATTS_TAG, "config raw adv data failed, error code = %x ", raw_adv_ret);
        }
        adv_config_done |= adv_config_flag;
        esp_err_t raw_scan_ret = esp_ble_gap_config_scan_rsp_data_raw(raw_scan_rsp_data, sizeof(raw_scan_rsp_data));
        if (raw_scan_ret){
            ESP_LOGE(GATTS_TAG, "config raw scan rsp data failed, error code = %x", raw_scan_ret);
        }
        adv_config_done |= scan_rsp_config_flag;
#else
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

#endif
        esp_ble_gatts_create_service(gatts_if, &gl_profile_tab[PROFILE_A_APP_ID].service_id, GATTS_NUM_HANDLE_TEST_A);
        break;
    case ESP_GATTS_READ_EVT: {
        ESP_LOGI(GATTS_TAG, "GATT_READ_EVT, conn_id %d, trans_id %d, handle %d\n", param->read.conn_id, param->read.trans_id, param->read.handle);
        esp_gatt_rsp_t rsp;
        memset(&rsp, 0, sizeof(esp_gatt_rsp_t));
        rsp.attr_value.handle = param->read.handle;
        rsp.attr_value.len = 4;
        rsp.attr_value.value[0] = 0xde;
        rsp.attr_value.value[1] = 0xed;
        rsp.attr_value.value[2] = 0xbe;
        rsp.attr_value.value[3] = 0xef;
        esp_ble_gatts_send_response(gatts_if, param->read.conn_id, param->read.trans_id,
                                    ESP_GATT_OK, &rsp);
        break;
    }
    case ESP_GATTS_WRITE_EVT: {
        ESP_LOGI(GATTS_TAG, "GATT_WRITE_EVT, conn_id %d, trans_id %d, handle %d", param->write.conn_id, param->write.trans_id, param->write.handle);
        if (!param->write.is_prep){
            ESP_LOGI(GATTS_TAG, "GATT_WRITE_EVT, value len %d, value :", param->write.len);
            esp_log_buffer_hex(GATTS_TAG, param->write.value, param->write.len);
            if (gl_profile_tab[PROFILE_A_APP_ID].descr_handle == param->write.handle && param->write.len == 2){
                uint16_t descr_value = param->write.value[1]<<8 | param->write.value[0];
                if (descr_value == 0x0001){
                    if (a_property & ESP_GATT_CHAR_PROP_BIT_NOTIFY){
                        ESP_LOGI(GATTS_TAG, "notify enable");
                        uint8_t notify_data[15];
                        for (int i = 0; i < sizeof(notify_data); ++i)
                        {
                            notify_data[i] = i%0xff;
                        }
                        //the size of notify_data[] need less than MTU size
                        esp_ble_gatts_send_indicate(gatts_if, param->write.conn_id, gl_profile_tab[PROFILE_A_APP_ID].char_handle,
                                                sizeof(notify_data), notify_data, false);
                    }
                }else if (descr_value == 0x0002){
                    if (a_property & ESP_GATT_CHAR_PROP_BIT_INDICATE){
                        ESP_LOGI(GATTS_TAG, "indicate enable");
                        uint8_t indicate_data[15];
                        for (int i = 0; i < sizeof(indicate_data); ++i)
                        {
                            indicate_data[i] = i%0xff;
                        }
                        //the size of indicate_data[] need less than MTU size
                        esp_ble_gatts_send_indicate(gatts_if, param->write.conn_id, gl_profile_tab[PROFILE_A_APP_ID].char_handle,
                                                sizeof(indicate_data), indicate_data, true);
                    }
                }
                else if (descr_value == 0x0000){
                    ESP_LOGI(GATTS_TAG, "notify/indicate disable ");
                }else{
                    ESP_LOGE(GATTS_TAG, "unknown descr value");
                    esp_log_buffer_hex(GATTS_TAG, param->write.value, param->write.len);
                }

            }
        }
        example_write_event_env(gatts_if, &a_prepare_write_env, param);
        break;
    }
    case ESP_GATTS_EXEC_WRITE_EVT:
        ESP_LOGI(GATTS_TAG,"ESP_GATTS_EXEC_WRITE_EVT");
        esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, ESP_GATT_OK, NULL);
        example_exec_write_event_env(&a_prepare_write_env, param);
        break;
    case ESP_GATTS_MTU_EVT:
        ESP_LOGI(GATTS_TAG, "ESP_GATTS_MTU_EVT, MTU %d", param->mtu.mtu);
        break;
    case ESP_GATTS_UNREG_EVT:
        break;
    case ESP_GATTS_CREATE_EVT:
        ESP_LOGI(GATTS_TAG, "CREATE_SERVICE_EVT, status %d,  service_handle %d\n", param->create.status, param->create.service_handle);
        gl_profile_tab[PROFILE_A_APP_ID].service_handle = param->create.service_handle;
        gl_profile_tab[PROFILE_A_APP_ID].char_uuid.len = ESP_UUID_LEN_16;
        gl_profile_tab[PROFILE_A_APP_ID].char_uuid.uuid.uuid16 = GATTS_CHAR_UUID_TEST_A;

        esp_ble_gatts_start_service(gl_profile_tab[PROFILE_A_APP_ID].service_handle);
        a_property = ESP_GATT_CHAR_PROP_BIT_READ;
        esp_err_t add_char_ret = esp_ble_gatts_add_char(gl_profile_tab[PROFILE_A_APP_ID].service_handle, &gl_profile_tab[PROFILE_A_APP_ID].char_uuid,
                                                        ESP_GATT_PERM_READ,
                                                        a_property,
                                                        &gatts_demo_char1_val, NULL);
        if (add_char_ret){
            ESP_LOGE(GATTS_TAG, "add char failed, error code =%x",add_char_ret);
        }
        ///////////////////////////
        //a_property = ESP_GATT_CHAR_PROP_BIT_READ | ESP_GATT_CHAR_PROP_BIT_WRITE | ESP_GATT_CHAR_PROP_BIT_NOTIFY;
        add_char_ret = esp_ble_gatts_add_char(gl_profile_tab[PROFILE_A_APP_ID].service_handle, &gl_profile_tab[PROFILE_A_APP_ID].char_uuid,
                                                        ESP_GATT_PERM_READ,
                                                        a_property,
                                                        &gatts_demo_char1_val, NULL);
        if (add_char_ret){
            ESP_LOGE(GATTS_TAG, "add char failed, error code =%x",add_char_ret);
        }
        ///////////////////////////

        break;
    case ESP_GATTS_ADD_INCL_SRVC_EVT:
        break;
    case ESP_GATTS_ADD_CHAR_EVT: {
        uint16_t length = 0;
        const uint8_t *prf_char;

        ESP_LOGI(GATTS_TAG, "ADD_CHAR_EVT, status %d,  attr_handle %d, service_handle %d\n",
                param->add_char.status, param->add_char.attr_handle, param->add_char.service_handle);
        gl_profile_tab[PROFILE_A_APP_ID].char_handle = param->add_char.attr_handle;
        gl_profile_tab[PROFILE_A_APP_ID].descr_uuid.len = ESP_UUID_LEN_16;
        gl_profile_tab[PROFILE_A_APP_ID].descr_uuid.uuid.uuid16 = ESP_GATT_UUID_CHAR_CLIENT_CONFIG;
        esp_err_t get_attr_ret = esp_ble_gatts_get_attr_value(param->add_char.attr_handle,  &length, &prf_char);
        if (get_attr_ret == ESP_FAIL){
            ESP_LOGE(GATTS_TAG, "ILLEGAL HANDLE");
        }

        ESP_LOGI(GATTS_TAG, "the gatts demo char length = %x\n", length);
        for(int i = 0; i < length; i++){
            ESP_LOGI(GATTS_TAG, "prf_char[%x] =%x\n",i,prf_char[i]);
        }
        esp_err_t add_descr_ret = esp_ble_gatts_add_char_descr(gl_profile_tab[PROFILE_A_APP_ID].service_handle, &gl_profile_tab[PROFILE_A_APP_ID].descr_uuid,
                                                                ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE, NULL, NULL);
        if (add_descr_ret){
            ESP_LOGE(GATTS_TAG, "add char descr failed, error code =%x", add_descr_ret);
        }
        break;
    }
    case ESP_GATTS_ADD_CHAR_DESCR_EVT:
        gl_profile_tab[PROFILE_A_APP_ID].descr_handle = param->add_char_descr.attr_handle;
        ESP_LOGI(GATTS_TAG, "ADD_DESCR_EVT, status %d, attr_handle %d, service_handle %d\n",
                 param->add_char_descr.status, param->add_char_descr.attr_handle, param->add_char_descr.service_handle);
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
        conn_params.max_int = 0x20;    // max_int = 0x20*1.25ms = 40ms
        conn_params.min_int = 0x10;    // min_int = 0x10*1.25ms = 20ms
        conn_params.timeout = 400;    // timeout = 400*10ms = 4000ms
        ESP_LOGI(GATTS_TAG, "ESP_GATTS_CONNECT_EVT, conn_id %d, remote %02x:%02x:%02x:%02x:%02x:%02x:",
                 param->connect.conn_id,
                 param->connect.remote_bda[0], param->connect.remote_bda[1], param->connect.remote_bda[2],
                 param->connect.remote_bda[3], param->connect.remote_bda[4], param->connect.remote_bda[5]);
        gl_profile_tab[PROFILE_A_APP_ID].conn_id = param->connect.conn_id;
        //start sent the update connection parameters to the peer device.
        esp_ble_gap_update_conn_params(&conn_params);
        break;
    }
    case ESP_GATTS_DISCONNECT_EVT:
        ESP_LOGI(GATTS_TAG, "ESP_GATTS_DISCONNECT_EVT, disconnect reason 0x%x", param->disconnect.reason);
        esp_ble_gap_start_advertising(&adv_params);
        break;
    case ESP_GATTS_CONF_EVT:
        ESP_LOGI(GATTS_TAG, "ESP_GATTS_CONF_EVT, status %d attr_handle %d", param->conf.status, param->conf.handle);
        if (param->conf.status != ESP_GATT_OK){
            esp_log_buffer_hex(GATTS_TAG, param->conf.value, param->conf.len);
        }
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


static void gatts_event_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param)
{
    /* If event is register event, store the gatts_if for each profile */
    if (event == ESP_GATTS_REG_EVT) {
        if (param->reg.status == ESP_GATT_OK) {
            gl_profile_tab[param->reg.app_id].gatts_if = gatts_if;
        } else {
            ESP_LOGI(GATTS_TAG, "Reg app failed, app_id %04x, status %d\n",
                    param->reg.app_id,
                    param->reg.status);
            return;
        }
    }

    /* If the gatts_if equal to profile A, call profile A cb handler,
     * so here call each profile's callback */
    do {
        int idx;
        for (idx = 0; idx < PROFILE_NUM; idx++) {
            if (gatts_if == ESP_GATT_IF_NONE || /* ESP_GATT_IF_NONE, not specify a certain gatt_if, need to call every profile cb function */
                    gatts_if == gl_profile_tab[idx].gatts_if) {
                if (gl_profile_tab[idx].gatts_cb) {
                    gl_profile_tab[idx].gatts_cb(event, gatts_if, param);
                }
            }
        }
    } while (0);
}

void ritardo(int secondi){
	for(;secondi>0;secondi--){
		vTaskDelay(1000 / portTICK_PERIOD_MS);
		printf("\nParto tra %d secondi",secondi);
		fflush(stdout);
	}
}

void print_available_ram(){
    uint freeRAM = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
	printf("\n\n ---> FREE RAM IS: %d.\n\n", freeRAM);
	fflush(stdout);
}

bool carica_chiavi(){
    // Initialize NVS
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // NVS partition was truncated and needs to be erased
        // Retry nvs_flash_init
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK( err );

    // Open
    printf("\n -> Opening Non-Volatile Storage (NVS) handle... ");
    nvs_handle my_handle;
    err = nvs_open("stored_keys", NVS_READONLY, &my_handle);
    if (err != ESP_OK) {
        printf("\n   -> Error (%s) opening NVS handle!\n", esp_err_to_name(err));
        return false;
    } else {
        printf("\n   -> File Aperto con successo.");
        // Read
        size_t n_N,n_E,n_D,n_P,n_Q,n_DP,n_DQ,n_QP,n_key;
        //Mi interessa solo la dimensione per poter creare array dinamici //TODO: sistemare il return, se fallisce qualcosa deve ritornare false
        printf("\n -> Verifico che tutte le chiavi siano in memoria..");
        err = nvs_get_str(my_handle, "N", NULL, &n_N); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "E", NULL, &n_E); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "D", NULL, &n_D); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "P", NULL, &n_P); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "Q", NULL, &n_Q); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "DP", NULL, &n_DP); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "DQ", NULL, &n_DQ); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "QP", NULL, &n_QP); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "KEY", NULL, &n_key); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
        char* N_string=pvPortMalloc(n_N);
        char* E_string=pvPortMalloc(n_E);
		char* D_string=pvPortMalloc(n_D);
		char* P_string=pvPortMalloc(n_P);
		char* Q_string=pvPortMalloc(n_Q);
		char* DP_string=pvPortMalloc(n_DP);
		char* DQ_string=pvPortMalloc(n_DQ);
		char* QP_string=pvPortMalloc(n_QP);
		char* key_string=pvPortMalloc(n_key);
		//Leggo effettivamente il valore
		printf("\n -> Carico le chiavi in formato string");
		err = nvs_get_str(my_handle, "N", N_string, &n_N); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "E", E_string, &n_E); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "D", D_string, &n_D); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "P", P_string, &n_P); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "Q", Q_string, &n_Q); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "DP", DP_string, &n_DP); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "DQ", DQ_string, &n_DQ); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "QP", QP_string, &n_QP); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");
		err = nvs_get_str(my_handle, "KEY", key_string, &n_key); printf((err != ESP_OK) ? "\n     -> Failed!" : "\n     -> Done");

		//Stampo le chiavi a video
		printf("\n\n\t ----- STAMPO LE CHIAVI -----\n");
		printf("\nLA N CARICATA VALE (string): %s\n",N_string);
		printf("\nLA E CARICATA VALE (string) : %s\n",E_string);
		printf("\nLA D CARICATA VALE (string) : %s\n",D_string);
		printf("\nLA P CARICATA VALE (string) : %s\n",P_string);
		printf("\nLA Q CARICATA VALE (string) : %s\n",Q_string);
		printf("\nLA DP CARICATA VALE (string) : %s\n",DP_string);
		printf("\nLA DQ CARICATA VALE (string) : %s\n",DQ_string);
		printf("\nLA QP CARICATA VALE (string) : %s\n",QP_string);
		printf("\n----- CHIAVE PRIVATA DELLA ESP32 -----\n%s\n",key_string);
        // Close
        nvs_close(my_handle);
        printf("\n -> File chiuso.");
        printf("\n -> Converto le chiavi da STRING a MPI.");
        //Converto da STRINGA ad MPI
        //N_key, P_key, Q_key, D_key, E_key, DP_key, DQ_key, QP_key;
        int error;
        error = mbedtls_mpi_read_string(&N_key,16,N_string); printf((error != 0) ? "\n   -> Conversion to MPI Failed!" : "\n   -> Conversion to MPI Done");
        error = mbedtls_mpi_read_string(&E_key,16,E_string); printf((error != 0) ? "\n   -> Conversion to MPI Failed!" : "\n   -> Conversion to MPI Done");
        error = mbedtls_mpi_read_string(&D_key,16,D_string); printf((error != 0) ? "\n   -> Conversion to MPI Failed!" : "\n   -> Conversion to MPI Done");
        error = mbedtls_mpi_read_string(&P_key,16,P_string); printf((error != 0) ? "\n   -> Conversion to MPI Failed!" : "\n   -> Conversion to MPI Done");
        error = mbedtls_mpi_read_string(&Q_key,16,Q_string); printf((error != 0) ? "\n   -> Conversion to MPI Failed!" : "\n   -> Conversion to MPI Done");
        error = mbedtls_mpi_read_string(&DP_key,16,DP_string); printf((error != 0) ? "\n   -> Conversion to MPI Failed!" : "\n   -> Conversion to MPI Done");
        error = mbedtls_mpi_read_string(&DQ_key,16,DQ_string); printf((error != 0) ? "\n   -> Conversion to MPI Failed!" : "\n   -> Conversion to MPI Done");
        error = mbedtls_mpi_read_string(&QP_key,16,QP_string); printf((error != 0) ? "\n   -> Conversion to MPI Failed!" : "\n   -> Conversion to MPI Done");
        mbedtls_pk_init(&key_key);
        printf("\n -> Converto le chiavi da STRING a PK.");
        error = mbedtls_pk_parse_key( &key_key, (unsigned char*)key_string, n_key,NULL,0);
        if(error!=0){
        	printf("\n   -> Conversion to PK Failed!");
        	return false;
        }
        else{
        	printf("\n   -> Conversion to PK Done");
            printf("\n\n\t ----- ESTRAGGO LA CHIAVE PUBBLICA DA QUELLA PRIVATA -----\n");
            unsigned char output_buf[1800];
            //size_t len = 0;
            memset(output_buf, 0, 1800);
    		if( mbedtls_pk_write_pubkey_pem( &key_key, output_buf, 1800 ) != 0 ){
    			printf("\n -> Estrazione fallita.");
    			return false;
    		}
            //len = strlen( (char *) output_buf );
            //printf("\n\nLunghezza Chiave Pubblica: %d",len);
            printf("\n----- CHIAVE PUBBLICA DELLA ESP32 -----\n%s",output_buf);
        }


        //TODO: DA TOGLIERE: EMULO LE CHIAVI PRIVATE E PUBBLICHE! begin
    	printf("\n\n------------------------------------------------------------------------------------------\n");
    	printf("\n\t ----- MI INVENTO DELLE CHIAVI PRIVATE E PUBBLICHE PER MASTER E SLAVE -----\n");
        mbedtls_pk_init(&master_pub_key);
        mbedtls_pk_init(&master_priv_key);
        mbedtls_pk_init(&slave_pub_key);
        mbedtls_pk_init(&slave_priv_key);
        //printf("\n La pub_key pem vale: %s",master_pub_key_string);
        //printf("\n La sua lunghezza vale: %d\n",lung);
        fflush( stdout );
        printf("\n -> Converto le chiavi da STRING a PK.");
        error = mbedtls_pk_parse_public_key( &master_pub_key, (unsigned char*)master_pub_key_string, sizeof(master_pub_key_string)); printf((error != 0) ? "\n   -> Conversion to PK Failed!" : "\n   -> Conversion to PK Done");
        error = mbedtls_pk_parse_key( &master_priv_key, (unsigned char*)master_priv_key_string, sizeof(master_priv_key_string),NULL,0); printf((error != 0) ? "\n   -> Conversion to PK Failed!" : "\n   -> Conversion to PK Done");
        error = mbedtls_pk_parse_public_key( &slave_pub_key, (unsigned char*)slave_pub_key_string, sizeof(slave_pub_key_string)); printf((error != 0) ? "\n   -> Conversion to PK Failed!" : "\n   -> Conversion to PK Done");
        error = mbedtls_pk_parse_key( &slave_priv_key, (unsigned char*)slave_priv_key_string, sizeof(slave_priv_key_string),NULL,0); printf((error != 0) ? "\n   -> Conversion to PK Failed!" : "\n   -> Conversion to PK Done");
        printf("\n -> Verifico la coppia chiave pubblica/privata di master e slave");
        error = mbedtls_pk_check_pair(&master_pub_key, &master_priv_key); printf((error != 0) ? "\n   -> Coppia chiave privata/pubblica NON VALIDA" : "\n   -> Coppia chiave privata/pubblica OK");
        error = mbedtls_pk_check_pair(&slave_pub_key, &slave_priv_key); printf((error != 0) ? "\n   -> Coppia chiave privata/pubblica NON VALIDA" : "\n   -> Coppia chiave privata/pubblica OK");
        //TODO: DA TOGLIERE: EMULO LE CHIAVI PRIVATE E PUBBLICHE! end


        //LIBERO LA MEMORIA
        vPortFree(N_string); vPortFree(E_string); vPortFree(D_string);
        vPortFree(P_string); vPortFree(Q_string); vPortFree(DP_string);
        vPortFree(DQ_string); vPortFree(QP_string); vPortFree(key_string);

    }
    return true;
}

bool cancella_tutto(){
    // Initialize NVS
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // NVS partition was truncated and needs to be erased. Retry nvs_flash_init
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK( err );

    //printf("\nOpening Non-Volatile Storage (NVS) handle... ");
    nvs_handle my_handle;
    err = nvs_open("stored_keys", NVS_READONLY, &my_handle);
    if (err != ESP_OK) {
        //printf("\nError (%s) opening NVS handle!\n", esp_err_to_name(err));
    	printf("\n -> Non c'è niente da cancellare, il file non esiste.");
        nvs_close(my_handle);
        return false;
    }
    ESP_ERROR_CHECK(nvs_flash_erase());
    ESP_ERROR_CHECK(nvs_flash_init());
    return true;
}

void print_date_time(){
	printf("\n\ntime - begin");
	time_t now;
	struct tm timeinfo;
	time(&now);
	char strftime_buf[64];
	tzset();
	localtime_r(&now, &timeinfo);
	strftime(strftime_buf, sizeof(strftime_buf), "%c", &timeinfo);
	printf("\n -> The current date/time is: %s", strftime_buf);
	printf("\ntime - end\n\n");
}
void print_all_certificates(){
	printf("\n\n\t ----- PRINTO TUTTI I CERTIFICATI ----- \n\n");

	unsigned char buf[1024];
	int ret2;
    mbedtls_printf( "  . Peer certificate information    ...\n" );
    ret2 = mbedtls_x509_crt_info( (char *) buf, sizeof( buf ) - 1, "      ", &self_certificate );
    if( ret2 == -1 )
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_info returned %d\n\n", ret2 );
    printf( "\nSELF CERT:\n%s\n", buf );
    ret2 = mbedtls_x509_crt_info( (char *) buf, sizeof( buf ) - 1, "      ", &master_certificate );
    if( ret2 == -1 )
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_info returned %d\n\n", ret2 );
    printf( "\nMASTER CERT:\n%s\n", buf );
    ret2 = mbedtls_x509_crt_info( (char *) buf, sizeof( buf ) - 1, "      ", &slave_certificate );
    if( ret2 == -1 )
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_info returned %d\n\n", ret2 );
    printf( "\nSLAVE CERT:\n%s\n", buf );
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

	vTaskDelay(100 / portTICK_PERIOD_MS);
	//print_all_certificates();
	wait_cert_app_slave=true;
	xTaskCreate(cert_app_slave_certificate,"CertAppSlave",8000,NULL,3,NULL);
	printf("\n -> Attendi, verifica dello Slave Certificate..\n");
	while(wait_cert_app_slave){
		vTaskDelay(100 / portTICK_PERIOD_MS);
	}
	return master_cert_validity & slave_cert_validity; //TODO: sistemare
}

void app_main()
{
	print_available_ram();
	print_date_time();
	ritardo(5); //TODO: debug. da cancellare
	/*if(cancella_tutto()){
		printf("\n\t\t --- HO CANCELLATO TUTTO --- \n");
		for(int i=10;i>0;i--){
			vTaskDelay(1000 / portTICK_PERIOD_MS);
			printf("\nRestart in %d seconds",i);
		}
		esp_restart();
	}
	else
		printf("\n\t\t --- CANCELLAZIONE FALLITA --- \n");
	ritardo(5); //TODO: debug. da cancellare*/

	/*wait_key_gen=true;
	xTaskCreate(genera_chiave,"GeneraChiave",64768,NULL,2,NULL);
	printf("\nAttendo.");
	while(wait_key_gen){
		printf(".");
		vTaskDelay(100 / portTICK_PERIOD_MS);
	}*/

	printf("\n\n------------------------------------------------------------------------------------------\n");

	printf("\n\t ----- TENTO DI CARICARE LE CHIAVI DALLA NVS -----\n");
	if(carica_chiavi())
		printf("\n -> Chiavi caricate con successo \n");
	else{
		printf("\n -> Chiavi non trovate.\n");
		printf("\n\t ----- GENERO LA COPPIA CHIAVE PUBBLICA E PRIVATA ----- \n");
		wait_key_gen=true;
		xTaskCreate(genera_chiave,"GeneraChiave",64768,NULL,2,NULL);
		printf("\n -> Attendo..\n");
		while(wait_key_gen){
			//printf(".");
			vTaskDelay(100 / portTICK_PERIOD_MS);
		}
		printf("\n\t ----- CARICO LE CHIAVI DALLA MEMORIA ----- \n\t(per verificare la corretta scrittura delle chiavi in memoria)");
		if(carica_chiavi()){
			printf("\n -> Chiavi generate, salvate e ricaricate con successo\n");
		}
		else{
			printf("\n -> Ho creato le chiavi, ho tentato di salvarle, e non sono riuscito a ricaricarle. Qualcosa è andato storto..\n");
			printf("\n   ----- RIAVVIO LA ESP -----\n");
			for(int i=8;i>0;i--){
				vTaskDelay(1000 / portTICK_PERIOD_MS);
				printf("\n<Restart in %d seconds>",i);
				fflush(stdout);
			}
			esp_restart();
		}
	}

	printf("\n\n----------------------------------------------------------------------\n");
	print_available_ram();
	//GENERA SELF CERTIFICATE
	printf("\n\n\t --- GENERA SELF CERTIFICATE --- \n\n");
	wait_self_cert_generation=true;
	xTaskCreate(selfsigned_cert_write,"GeneraSelfCert",32768,NULL,2,NULL);
	printf("\n -> Attendo..\n");
	do{
		//printf(".");
		vTaskDelay(100 / portTICK_PERIOD_MS);
	}while(wait_self_cert_generation);

	printf("\n\n----------------------------------------------------------------------\n");
	print_available_ram();
	//MASTER CERT WRITE
	printf("\n\n\t --- GENERA MASTER CERT WRITE --- \n\n");
	wait_master_cert_write=true;
	xTaskCreate(master_cert_write,"MasterCertWrite",32768,NULL,2,NULL);
	printf("\n -> Attendo..\n");
	do{
		//printf(".");
		vTaskDelay(100 / portTICK_PERIOD_MS);
	}while(wait_master_cert_write);

	printf("\n\n----------------------------------------------------------------------\n");
	print_available_ram();
	//SLAVE CERT WRITE
	printf("\n\n\t --- GENERA SLAVE CERT WRITE --- \n\n");
	wait_slave_cert_write=true;
	xTaskCreate(slave_cert_write,"SlaveCertWrite",32768,NULL,2,NULL);
	printf("\n -> Attendo..\n");
	do{
		//printf(".");
		vTaskDelay(100 / portTICK_PERIOD_MS);
	}while(wait_slave_cert_write);

	printf("\n\n----------------------------------------------------------------------\n");
	print_available_ram();
	//VERIFICO LA CATENA.
	//print_all_certificates();

    printf("\n\n----------------------------------------------------------------------\n");

	//VERIFICO LA CATENA.
	printf("\n\n\t ----- VERIFICO CERTIFICATI ----- \n\n");
    if(!verifica_certificati()){
    	printf("\n -> I certificati non sono stati approvati.");
    }
    else{
    	printf("\n -> I certificati sono stati approvati.");
    	printf("\n -> Avvio il Random Challenge");
    }

	printf("\n\n----------------------------------------------------------------------\n");
	print_available_ram();
	printf("\n\t --- AVVIO IL BLUETOOTH E TUTTI I SERVIZI ASSOCIATI --- \n");
    //int exitcode = genera_chiave();
    //printf("\n\t\t EXIT CODE: %d \n",exitcode);
    //ritardo(8);

    esp_err_t ret;
    // Initialize NVS. (Non-volatile storage)
    ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK( ret );

    ESP_ERROR_CHECK(esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT));

    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ret = esp_bt_controller_init(&bt_cfg);
    if (ret) {
        ESP_LOGE(GATTS_TAG, "%s initialize controller failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }

    ret = esp_bt_controller_enable(ESP_BT_MODE_BLE); //Bluetooth parte in modalità solo BLE. ESP_BT_MODE_BTDM: Dual mode (BLE + BT Classic)
    if (ret) {
        ESP_LOGE(GATTS_TAG, "%s enable controller failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }
    ret = esp_bluedroid_init();
    if (ret) {
        ESP_LOGE(GATTS_TAG, "%s init bluetooth failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }
    ret = esp_bluedroid_enable();
    if (ret) {
        ESP_LOGE(GATTS_TAG, "%s enable bluetooth failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }

    ret = esp_ble_gatts_register_callback(gatts_event_handler);
    if (ret){
        ESP_LOGE(GATTS_TAG, "gatts register error, error code = %x", ret);
        return;
    }
    ret = esp_ble_gap_register_callback(gap_event_handler);
    if (ret){
        ESP_LOGE(GATTS_TAG, "gap register error, error code = %x", ret);
        return;
    }
    ret = esp_ble_gatts_app_register(PROFILE_A_APP_ID);
    if (ret){
        ESP_LOGE(GATTS_TAG, "gatts app register error, error code = %x", ret);
        return;
    }
    esp_err_t local_mtu_ret = esp_ble_gatt_set_local_mtu(500);
    if (local_mtu_ret){
        ESP_LOGE(GATTS_TAG, "set local  MTU failed, error code = %x", local_mtu_ret);
    }
    //vTaskDelay(10000 /portTICK_PERIOD_MS);
    printf("\nFINE DEL MAIN.");
    printf("\nHO LANCIATO TUTTI I SERVIZI, PRESTO SARANNO DISPONIBILI");
    return;
}
