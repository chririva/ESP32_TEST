/*
 * random_challenge_sign_TEST.h
 *
 *  Created on: 8 nov 2019
 *      Author: gaetano
 */

#ifndef MAIN_RANDOM_CHALLENGE_SIGN_TEST_H_
#define MAIN_RANDOM_CHALLENGE_SIGN_TEST_H_

#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"

int random_challenge_sign();

#endif /* MAIN_RANDOM_CHALLENGE_SIGN_TEST_H_ */
