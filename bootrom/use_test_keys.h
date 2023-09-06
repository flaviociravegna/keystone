#include "test_dev_key.h"
memcpy(sanctum_dev_secret_key, _sanctum_dev_secret_key, _sanctum_dev_secret_key_len);
memcpy(sanctum_dev_public_key, _sanctum_dev_public_key, _sanctum_dev_public_key_len);
memcpy(sanctum_cert_root, _sanctum_cert_root, _sanctum_length_cert_root);
memcpy(sanctum_cert_man, _sanctum_cert_man, _sanctum_length_cert_man);


sanctum_length_cert_man= _sanctum_length_cert_man;
sanctum_length_cert_root= _sanctum_length_cert_root;

