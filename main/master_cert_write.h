/*
 * master_cert_write.h
 *
 */

#ifndef MAIN_MASTER_CERT_WRITE_H_
#define MAIN_MASTER_CERT_WRITE_H_

#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/error.h"

extern bool wait_master_cert_write;

int write_certificate2( mbedtls_x509write_cert *crt, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );
void master_cert_write( void *param);

#endif /* MAIN_MASTER_CERT_WRITE_H_ */
