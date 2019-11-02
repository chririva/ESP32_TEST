/*
 * master_cert_write.h
 *
 */

#ifndef MAIN_SLAVE_CERT_WRITE_DEBUG_TEST_H_
#define MAIN_SLAVE_CERT_WRITE_DEBUG_TEST_H_

#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/error.h"

extern bool wait_slave_cert_write;

int write_certificate3( mbedtls_x509write_cert *crt, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );
void slave_cert_write( void *param);

#endif /* MAIN_SLAVE_CERT_WRITE_DEBUG_TEST_H_ */
