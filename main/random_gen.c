/*
 * random_gen.c
 *
 *  Created on: 8 nov 2019
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

#include "esp_bt.h"
#include "esp_gap_ble_api.h"
#include "esp_gatts_api.h"
#include "esp_bt_defs.h"
#include "esp_bt_main.h"
#include "esp_gatt_common_api.h"
#include "ble_server.h"
#include "ble_config.h"
#define RND_LEN 128
extern char rand_challenge_str[GATTS_CHAR_RND_LEN_MAX];
extern esp_attr_value_t gatts_service2_random_val;

void random_string_generator(){
	esp_fill_random(rand_challenge_str, RND_LEN);
	printf("\n\nHO GENERATO RANDOM:\n%s\n\n",rand_challenge_str);

	//aggiorno la caratteristica
	gatts_service2_random_val.attr_len = RND_LEN;
    for(int valpos=0 ; valpos<RND_LEN ; valpos++ )
    	gatts_service2_random_val.attr_value[valpos]=rand_challenge_str[valpos];
    gatts_service2_random_val.attr_value[RND_LEN] = 0; //terminatore stringa

}


