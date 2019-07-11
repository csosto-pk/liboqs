#ifndef __OQS_SIG_SPHINCS_H
#define __OQS_SIG_SPHINCS_H

/* PANOS SPHINCS+ custom parameter testing
   using the testing and the parameter set flag
   These definitions are used in ifndefs in 
   sphincs-sha256-192f-simple and sphincs-sha256-256f-simple */
// Testing SPHINCS custom parameters
#define SPHINCS_CUSTOM_PARAM_TESTING
// Parameter sets. ONLY USE ONE. 
#define H_15_SEC192_W16
#define H_15_SEC192_W256
#define H_15_SEC256_W16
#define H_15_SEC256_W256
#define H_20_SEC192_W16
#define H_20_SEC192_W256
#define H_20_SEC256_W16
#define H_20_SEC256_W256
#define H_35_SEC192_W16
#define H_35_SEC192_W256
#define H_35_SEC256_W16
#define H_35_SEC256_W256


#include <oqs/oqs.h>
#include <oqs/sha2.h>

#ifdef OQS_ENABLE_SIG_SPHINCS_haraka_128s_simple
#define OQS_SIG_SPHINCS_haraka_128s_simple_length_public_key 32
#define OQS_SIG_SPHINCS_haraka_128s_simple_length_secret_key 64
#define OQS_SIG_SPHINCS_haraka_128s_simple_length_signature 8080

OQS_SIG *OQS_SIG_SPHINCS_haraka_128s_simple_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_128s_simple_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_128s_simple_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_128s_simple_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_haraka_128s_robust
#define OQS_SIG_SPHINCS_haraka_128s_robust_length_public_key 32
#define OQS_SIG_SPHINCS_haraka_128s_robust_length_secret_key 64
#define OQS_SIG_SPHINCS_haraka_128s_robust_length_signature 8080

OQS_SIG *OQS_SIG_SPHINCS_haraka_128s_robust_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_128s_robust_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_128s_robust_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_128s_robust_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_haraka_128f_simple
#define OQS_SIG_SPHINCS_haraka_128f_simple_length_public_key 32
#define OQS_SIG_SPHINCS_haraka_128f_simple_length_secret_key 64
#define OQS_SIG_SPHINCS_haraka_128f_simple_length_signature 16976

OQS_SIG *OQS_SIG_SPHINCS_haraka_128f_simple_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_128f_simple_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_128f_simple_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_128f_simple_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_haraka_128f_robust
#define OQS_SIG_SPHINCS_haraka_128f_robust_length_public_key 32
#define OQS_SIG_SPHINCS_haraka_128f_robust_length_secret_key 64
#define OQS_SIG_SPHINCS_haraka_128f_robust_length_signature 16976

OQS_SIG *OQS_SIG_SPHINCS_haraka_128f_robust_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_128f_robust_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_128f_robust_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_128f_robust_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_haraka_192s_simple
#define OQS_SIG_SPHINCS_haraka_192s_simple_length_public_key 48
#define OQS_SIG_SPHINCS_haraka_192s_simple_length_secret_key 96
#define OQS_SIG_SPHINCS_haraka_192s_simple_length_signature 17064

OQS_SIG *OQS_SIG_SPHINCS_haraka_192s_simple_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_192s_simple_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_192s_simple_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_192s_simple_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_haraka_192s_robust
#define OQS_SIG_SPHINCS_haraka_192s_robust_length_public_key 48
#define OQS_SIG_SPHINCS_haraka_192s_robust_length_secret_key 96
#define OQS_SIG_SPHINCS_haraka_192s_robust_length_signature 17064

OQS_SIG *OQS_SIG_SPHINCS_haraka_192s_robust_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_192s_robust_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_192s_robust_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_192s_robust_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_haraka_192f_simple
#define OQS_SIG_SPHINCS_haraka_192f_simple_length_public_key 48
#define OQS_SIG_SPHINCS_haraka_192f_simple_length_secret_key 96
#define OQS_SIG_SPHINCS_haraka_192f_simple_length_signature 35664

OQS_SIG *OQS_SIG_SPHINCS_haraka_192f_simple_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_192f_simple_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_192f_simple_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_192f_simple_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_haraka_192f_robust
#define OQS_SIG_SPHINCS_haraka_192f_robust_length_public_key 48
#define OQS_SIG_SPHINCS_haraka_192f_robust_length_secret_key 96
#define OQS_SIG_SPHINCS_haraka_192f_robust_length_signature 35664

OQS_SIG *OQS_SIG_SPHINCS_haraka_192f_robust_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_192f_robust_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_192f_robust_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_192f_robust_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_haraka_256s_simple
#define OQS_SIG_SPHINCS_haraka_256s_simple_length_public_key 64
#define OQS_SIG_SPHINCS_haraka_256s_simple_length_secret_key 128
#define OQS_SIG_SPHINCS_haraka_256s_simple_length_signature 29792

OQS_SIG *OQS_SIG_SPHINCS_haraka_256s_simple_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_256s_simple_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_256s_simple_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_256s_simple_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_haraka_256s_robust
#define OQS_SIG_SPHINCS_haraka_256s_robust_length_public_key 64
#define OQS_SIG_SPHINCS_haraka_256s_robust_length_secret_key 128
#define OQS_SIG_SPHINCS_haraka_256s_robust_length_signature 29792

OQS_SIG *OQS_SIG_SPHINCS_haraka_256s_robust_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_256s_robust_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_256s_robust_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_256s_robust_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_haraka_256f_simple
#define OQS_SIG_SPHINCS_haraka_256f_simple_length_public_key 64
#define OQS_SIG_SPHINCS_haraka_256f_simple_length_secret_key 128
#define OQS_SIG_SPHINCS_haraka_256f_simple_length_signature 49216

OQS_SIG *OQS_SIG_SPHINCS_haraka_256f_simple_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_256f_simple_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_256f_simple_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_256f_simple_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_haraka_256f_robust
#define OQS_SIG_SPHINCS_haraka_256f_robust_length_public_key 64
#define OQS_SIG_SPHINCS_haraka_256f_robust_length_secret_key 128
#define OQS_SIG_SPHINCS_haraka_256f_robust_length_signature 49216

OQS_SIG *OQS_SIG_SPHINCS_haraka_256f_robust_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_256f_robust_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_256f_robust_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_haraka_256f_robust_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_shake_128s_simple
#define OQS_SIG_SPHINCS_shake_128s_simple_length_public_key 32
#define OQS_SIG_SPHINCS_shake_128s_simple_length_secret_key 64
#define OQS_SIG_SPHINCS_shake_128s_simple_length_signature 8080

OQS_SIG *OQS_SIG_SPHINCS_shake_128s_simple_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_128s_simple_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_128s_simple_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_128s_simple_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_shake_128s_robust
#define OQS_SIG_SPHINCS_shake_128s_robust_length_public_key 32
#define OQS_SIG_SPHINCS_shake_128s_robust_length_secret_key 64
#define OQS_SIG_SPHINCS_shake_128s_robust_length_signature 8080

OQS_SIG *OQS_SIG_SPHINCS_shake_128s_robust_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_128s_robust_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_128s_robust_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_128s_robust_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_shake_128f_simple
#define OQS_SIG_SPHINCS_shake_128f_simple_length_public_key 32
#define OQS_SIG_SPHINCS_shake_128f_simple_length_secret_key 64
#define OQS_SIG_SPHINCS_shake_128f_simple_length_signature 16976

OQS_SIG *OQS_SIG_SPHINCS_shake_128f_simple_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_128f_simple_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_128f_simple_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_128f_simple_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_shake_128f_robust
#define OQS_SIG_SPHINCS_shake_128f_robust_length_public_key 32
#define OQS_SIG_SPHINCS_shake_128f_robust_length_secret_key 64
#define OQS_SIG_SPHINCS_shake_128f_robust_length_signature 16976

OQS_SIG *OQS_SIG_SPHINCS_shake_128f_robust_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_128f_robust_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_128f_robust_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_128f_robust_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_shake_192s_simple
#define OQS_SIG_SPHINCS_shake_192s_simple_length_public_key 48
#define OQS_SIG_SPHINCS_shake_192s_simple_length_secret_key 96
#define OQS_SIG_SPHINCS_shake_192s_simple_length_signature 17064

OQS_SIG *OQS_SIG_SPHINCS_shake_192s_simple_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_192s_simple_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_192s_simple_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_192s_simple_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_shake_192s_robust
#define OQS_SIG_SPHINCS_shake_192s_robust_length_public_key 48
#define OQS_SIG_SPHINCS_shake_192s_robust_length_secret_key 96
#define OQS_SIG_SPHINCS_shake_192s_robust_length_signature 17064

OQS_SIG *OQS_SIG_SPHINCS_shake_192s_robust_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_192s_robust_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_192s_robust_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_192s_robust_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_shake_192f_simple
#define OQS_SIG_SPHINCS_shake_192f_simple_length_public_key 48
#define OQS_SIG_SPHINCS_shake_192f_simple_length_secret_key 96
#define OQS_SIG_SPHINCS_shake_192f_simple_length_signature 35664

OQS_SIG *OQS_SIG_SPHINCS_shake_192f_simple_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_192f_simple_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_192f_simple_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_192f_simple_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_shake_192f_robust
#define OQS_SIG_SPHINCS_shake_192f_robust_length_public_key 48
#define OQS_SIG_SPHINCS_shake_192f_robust_length_secret_key 96
#define OQS_SIG_SPHINCS_shake_192f_robust_length_signature 35664

OQS_SIG *OQS_SIG_SPHINCS_shake_192f_robust_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_192f_robust_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_192f_robust_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_192f_robust_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_shake_256s_simple
#define OQS_SIG_SPHINCS_shake_256s_simple_length_public_key 64
#define OQS_SIG_SPHINCS_shake_256s_simple_length_secret_key 128
#define OQS_SIG_SPHINCS_shake_256s_simple_length_signature 29792

OQS_SIG *OQS_SIG_SPHINCS_shake_256s_simple_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_256s_simple_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_256s_simple_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_256s_simple_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_shake_256s_robust
#define OQS_SIG_SPHINCS_shake_256s_robust_length_public_key 64
#define OQS_SIG_SPHINCS_shake_256s_robust_length_secret_key 128
#define OQS_SIG_SPHINCS_shake_256s_robust_length_signature 29792

OQS_SIG *OQS_SIG_SPHINCS_shake_256s_robust_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_256s_robust_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_256s_robust_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_256s_robust_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_shake_256f_simple
#define OQS_SIG_SPHINCS_shake_256f_simple_length_public_key 64
#define OQS_SIG_SPHINCS_shake_256f_simple_length_secret_key 128
#define OQS_SIG_SPHINCS_shake_256f_simple_length_signature 49216

OQS_SIG *OQS_SIG_SPHINCS_shake_256f_simple_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_256f_simple_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_256f_simple_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_256f_simple_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_shake_256f_robust
#define OQS_SIG_SPHINCS_shake_256f_robust_length_public_key 64
#define OQS_SIG_SPHINCS_shake_256f_robust_length_secret_key 128
#define OQS_SIG_SPHINCS_shake_256f_robust_length_signature 49216

OQS_SIG *OQS_SIG_SPHINCS_shake_256f_robust_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_256f_robust_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_256f_robust_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_shake_256f_robust_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_sha256_128s_simple
#define OQS_SIG_SPHINCS_sha256_128s_simple_length_public_key 32
#define OQS_SIG_SPHINCS_sha256_128s_simple_length_secret_key 64
#define OQS_SIG_SPHINCS_sha256_128s_simple_length_signature 8080

OQS_SIG *OQS_SIG_SPHINCS_sha256_128s_simple_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_128s_simple_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_128s_simple_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_128s_simple_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_sha256_128s_robust
#define OQS_SIG_SPHINCS_sha256_128s_robust_length_public_key 32
#define OQS_SIG_SPHINCS_sha256_128s_robust_length_secret_key 64
#define OQS_SIG_SPHINCS_sha256_128s_robust_length_signature 8080

OQS_SIG *OQS_SIG_SPHINCS_sha256_128s_robust_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_128s_robust_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_128s_robust_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_128s_robust_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_sha256_128f_simple
#define OQS_SIG_SPHINCS_sha256_128f_simple_length_public_key 32
#define OQS_SIG_SPHINCS_sha256_128f_simple_length_secret_key 64
#define OQS_SIG_SPHINCS_sha256_128f_simple_length_signature 16976

OQS_SIG *OQS_SIG_SPHINCS_sha256_128f_simple_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_128f_simple_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_128f_simple_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_128f_simple_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_sha256_128f_robust
#define OQS_SIG_SPHINCS_sha256_128f_robust_length_public_key 32
#define OQS_SIG_SPHINCS_sha256_128f_robust_length_secret_key 64
#define OQS_SIG_SPHINCS_sha256_128f_robust_length_signature 16976

OQS_SIG *OQS_SIG_SPHINCS_sha256_128f_robust_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_128f_robust_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_128f_robust_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_128f_robust_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_sha256_192s_simple
#define OQS_SIG_SPHINCS_sha256_192s_simple_length_public_key 48
#define OQS_SIG_SPHINCS_sha256_192s_simple_length_secret_key 96
#define OQS_SIG_SPHINCS_sha256_192s_simple_length_signature 17064

OQS_SIG *OQS_SIG_SPHINCS_sha256_192s_simple_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_192s_simple_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_192s_simple_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_192s_simple_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_sha256_192s_robust
#define OQS_SIG_SPHINCS_sha256_192s_robust_length_public_key 48
#define OQS_SIG_SPHINCS_sha256_192s_robust_length_secret_key 96
#define OQS_SIG_SPHINCS_sha256_192s_robust_length_signature 17064

OQS_SIG *OQS_SIG_SPHINCS_sha256_192s_robust_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_192s_robust_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_192s_robust_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_192s_robust_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_sha256_192f_simple
#define OQS_SIG_SPHINCS_sha256_192f_simple_length_public_key 48
#define OQS_SIG_SPHINCS_sha256_192f_simple_length_secret_key 96
#define OQS_SIG_SPHINCS_sha256_192f_simple_length_signature 35664

OQS_SIG *OQS_SIG_SPHINCS_sha256_192f_simple_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_192f_simple_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_192f_simple_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_192f_simple_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_sha256_192f_robust
#define OQS_SIG_SPHINCS_sha256_192f_robust_length_public_key 48
#define OQS_SIG_SPHINCS_sha256_192f_robust_length_secret_key 96
#define OQS_SIG_SPHINCS_sha256_192f_robust_length_signature 35664

OQS_SIG *OQS_SIG_SPHINCS_sha256_192f_robust_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_192f_robust_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_192f_robust_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_192f_robust_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_sha256_256s_simple
#define OQS_SIG_SPHINCS_sha256_256s_simple_length_public_key 64
#define OQS_SIG_SPHINCS_sha256_256s_simple_length_secret_key 128
#define OQS_SIG_SPHINCS_sha256_256s_simple_length_signature 29792

OQS_SIG *OQS_SIG_SPHINCS_sha256_256s_simple_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_256s_simple_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_256s_simple_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_256s_simple_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_sha256_256s_robust
#define OQS_SIG_SPHINCS_sha256_256s_robust_length_public_key 64
#define OQS_SIG_SPHINCS_sha256_256s_robust_length_secret_key 128
#define OQS_SIG_SPHINCS_sha256_256s_robust_length_signature 29792

OQS_SIG *OQS_SIG_SPHINCS_sha256_256s_robust_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_256s_robust_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_256s_robust_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_256s_robust_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_sha256_256f_simple
#define OQS_SIG_SPHINCS_sha256_256f_simple_length_public_key 64
#define OQS_SIG_SPHINCS_sha256_256f_simple_length_secret_key 128
#define OQS_SIG_SPHINCS_sha256_256f_simple_length_signature 49216

OQS_SIG *OQS_SIG_SPHINCS_sha256_256f_simple_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_256f_simple_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_256f_simple_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_256f_simple_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif
#ifdef OQS_ENABLE_SIG_SPHINCS_sha256_256f_robust
#define OQS_SIG_SPHINCS_sha256_256f_robust_length_public_key 64
#define OQS_SIG_SPHINCS_sha256_256f_robust_length_secret_key 128
#define OQS_SIG_SPHINCS_sha256_256f_robust_length_signature 49216

OQS_SIG *OQS_SIG_SPHINCS_sha256_256f_robust_new();
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_256f_robust_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_256f_robust_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_SPHINCS_sha256_256f_robust_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif

#endif
