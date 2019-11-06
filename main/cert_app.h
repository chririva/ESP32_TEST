/*
 * cert_app.h
 *
 *
 */

#ifndef MAIN_CERT_APP_H_
#define MAIN_CERT_APP_H_

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include "mbedtls/debug.h"

#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/md.h"
#include "mbedtls/error.h"

extern bool wait_cert_app_master;
extern bool wait_cert_app_slave;

void cert_app_master_certificate(void *param);
void cert_app_slave_certificate(void *param);
//void cert_app(mbedtls_x509_crt *certificate_to_validate);

#endif /* MAIN_CERT_APP_H_ */
