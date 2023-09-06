#include <stddef.h>

#define ED25519_NO_SEED 1

//#include "x509custom/x509custom.h"

#include "sha3/sha3.h"
/* Adopted from https://github.com/orlp/ed25519
#include "libsodium_solo_una_dir/crypto_pwhash.h"

  provides:
  - void ed25519_create_keypair(t_pubkey *public_key, t_privkey *private_key, t_seed *seed);
  - void ed25519_sign(t_signature *signature,
                      const unsigned uint8_t *message,
                      size_t message_len,
                      t_pubkey *public_key,
                      t_privkey *private_key);
*/

#include "ed25519/ed25519.h"
/* adopted from
  provides:
  - int sha3_init(sha3_context * md);
  - int sha3_update(sha3_context * md, const unsigned char *in, size_t inlen);
  - int sha3_final(sha3_context * md, unsigned char *out);
  types: sha3_context
*/

#include "string.h"
/*
  provides memcpy, memset
*/

#include "x509custom/x509custom.h"

static const unsigned char sanctum_uds[] = {
  0x40, 0xa0, 0x99, 0x47, 0x8c, 0xce, 0xfa, 0x3a, 0x06, 0x63, 0xab, 0xc9,
  0x5e, 0x7a, 0x1e, 0xc9, 0x54, 0xb4, 0xf5, 0xf6, 0x45, 0xba, 0xd8, 0x04,
  0xdb, 0x13, 0xe7, 0xd7, 0x82, 0x6c, 0x70, 0x73}
;

typedef unsigned char byte;

// Sanctum header fields in DRAM
extern byte sanctum_dev_public_key[32];
extern byte sanctum_dev_secret_key[64];
extern byte sanctum_sm_hash[64];
extern byte sanctum_sm_public_key[32];
extern byte sanctum_sm_secret_key[64];
extern byte sanctum_sm_signature[64];
/**
 * Variables used to pass parameter to the SM
*/
extern byte sanctum_CDI[64];
extern byte sanctum_ECASM_pk[64];
//extern byte sanctum_sm_hash_to_check[64];
extern byte sanctum_device_root_key_pub[64];
extern byte sanctum_cert_sm[512];
extern byte sanctum_cert_root[512];
extern byte sanctum_cert_man[512];
extern int sanctum_length_cert;
extern int sanctum_length_cert_root;
extern int sanctum_length_cert_man;

//extern byte sanctum_sm_key_pub[64];
//extern byte sanctum_sm_signature_drk[64];

// Variable used for testing porpouse to pass data from the boot stage to the sm
extern byte test[64];

unsigned int sanctum_sm_size = 0x1ff000;

/**
 * called (?) by bootloader.S at line 27 (secure boot)
 */

#define DRAM_BASE 0x80000000

/* Update this to generate valid entropy for target platform*/
inline byte random_byte(unsigned int i)
{
#warning Bootloader does not have entropy source, keys are for TESTING ONLY
  return 0xac + (0xdd ^ i);
}
int bootloader()
{

  byte scratchpad[128];
  //byte scratchpad_app[128];
  sha3_ctx_t hash_ctx;

  byte sanctum_device_root_key_priv[64];

  byte sanctum_sm_signature_test[64];

  byte sanctum_sm_sign[64];              // no usefull if there is a file with the sign of the security monitor
  byte sanctum_pub_key_manufacturer[64]; // no usefull if there is a file with the pub key of the manufacturer

  //byte sanctum_eca_key_priv[64];

  //byte sanctum_sm_key_priv[64];

  byte sanctum_ECASM_priv[64];
  
  int ret;

  // TODO: on real device, copy boot image from memory. In simulator, HTIF writes boot image
  // ... SD card to beginning of memory.
  // sd_init();
  // sd_read_from_start(DRAM, 1024);

  /* Gathering high quality entropy during boot on embedded devices is
   * a hard problem. Platforms taking security seriously must provide
   * a high quality entropy source available in hardware. Platforms
   * that do not provide such a source must gather their own
   * entropy. See the Keystone documentation for further
   * discussion. For testing purposes, we have no entropy generation.
   */

  // Create a random seed for keys and nonces from TRNG
  for (unsigned int i = 0; i < 32; i++)
  {
    scratchpad[i] = random_byte(i);
  }

  /* On a real device, the platform must provide a secure root device
     keystore. For testing purposes we hardcode a known private/public
     keypair */
  // TEST Device key

#include "use_test_keys.h"

// Loading of the manufacturer public key and of the digital signature of the security monitor

// #include #"use_sm_sign_and_pk_man.h"
#include "sm_sign_and_pk_man.h"
  //byte private_key_test[64];
  //byte public_key_test[32];
  //byte seed_test[] = {0x00};
  //For testing, create a keypair to simulate that we have already the public key of the manufacturer
  //ed25519_create_keypair(public_key_test, private_key_test, seed_test);

  //char error_buf[100];

  // In the real case the SM measure signed with the private key of the manufacturer is provided
  // For our testing, we suppose that the keypair already provided by the standard keystone implementation is the keypair associated to the man
  // The public key "sanctum_dev_public_key" is also the key inserted in the man cert

  // Measure for the first time the SM to simulate that the signature is provided by the manufacturer
  sha3_init(&hash_ctx, 64);
  sha3_update(&hash_ctx, (void *)DRAM_BASE, sanctum_sm_size);
  sha3_final(sanctum_sm_hash, &hash_ctx);
  ed25519_sign(sanctum_sm_signature_test, sanctum_sm_hash, 64, sanctum_dev_public_key, sanctum_dev_secret_key);
  //--------------------------------------------------------------------------------------------------------------------//

  // Measure SM to verify the signature
  sha3_init(&hash_ctx, 64);
  sha3_update(&hash_ctx, (void *)DRAM_BASE, sanctum_sm_size);
  sha3_final(sanctum_sm_hash, &hash_ctx);
  
  // If the hash is not the correct one, the verification goes wrong
  //sanctum_sm_hash[0] = random_byte(0);

  // Verify the signature of the security monitor provided by the manufacturer

  if ((ed25519_verify(sanctum_sm_signature_test, sanctum_sm_hash, 64, sanctum_dev_public_key)) == 0)
  {
    // The return value of the bootloader function is used to check if the secure boot is gone well or not
    return 0;
  }

  // All ok
  // Combine hash of the security monitor and the device root key to obtain the CDI
  sha3_init(&hash_ctx, 64);
  sha3_update(&hash_ctx, sanctum_uds, sizeof(*sanctum_uds));
  sha3_update(&hash_ctx, sanctum_sm_hash, sizeof(*sanctum_sm_hash));
  sha3_final(sanctum_CDI, &hash_ctx);

  // The device root keys are created from the CDI
  // This keys are certified by the manufacuter and the cert is stored in memory, like the cert of the manufacturer
  ed25519_create_keypair(sanctum_device_root_key_pub, sanctum_device_root_key_priv, sanctum_CDI);

  // The ECA keys are obtained starting from a seed generated hashing the CDI and the measure of the SM
  unsigned char seed_for_ECA_keys[64];

  sha3_init(&hash_ctx, 64);
  sha3_update(&hash_ctx, sanctum_CDI, 64);
  sha3_update(&hash_ctx, sanctum_sm_hash, 64);
  sha3_final(seed_for_ECA_keys, &hash_ctx);
  ed25519_create_keypair(sanctum_ECASM_pk, sanctum_ECASM_priv, seed_for_ECA_keys);
  
  //my_memcpy(test, sanctum_ECASM_priv, 64);

  // Create the certificate structure mbedtls_x509write_cert to release the cert of the security monitor
  mbedtls_x509write_cert cert;
  mbedtls_x509write_crt_init(&cert);

  // Setting the name of the issuer of the cert
  ret = mbedtls_x509write_crt_set_issuer_name_mod(&cert, "O=Root of Trust");
  if (ret != 0)
  {
    return 0;
  }
  
  // Setting the name of the subject of the cert
  ret = mbedtls_x509write_crt_set_subject_name_mod(&cert, "O=Security Monitor");
  if (ret != 0)
  {
    return 0;
  }

  //unsigned char oid_ext2[] = {0x55, 0x1d, 0x13};
  //unsigned char max_path[] = {0x0A};

  // pk context used to embed the keys of the security monitor
  mbedtls_pk_context subj_key;
  mbedtls_pk_init(&subj_key);

  // pk context used to embed the keys of the root of trust
  mbedtls_pk_context issu_key;
  mbedtls_pk_init(&issu_key);
  
  // Parsing the private key of the root of trust that will be used to sign the certificate of the security monitor
  ret = mbedtls_pk_parse_public_key(&issu_key, sanctum_device_root_key_priv, 64, 1);
  if (ret != 0)
  {
    return 0;
  }

  ret = mbedtls_pk_parse_public_key(&issu_key, sanctum_device_root_key_pub, 32, 0);
  if (ret != 0)
  {
    return 0;
  }

  // Parsing the public key of the security monitor that will be inserted in its certificate 
  ret = mbedtls_pk_parse_public_key(&subj_key, sanctum_ECASM_pk, 32, 0);
  if (ret != 0)
  {
    return 0;
  }

  
  // Variable  used to specify the serial of the cert
  unsigned char serial[] = {0x0, 0x0, 0x01};
  
  // The public key of the security monitor is inserted in the structure
  mbedtls_x509write_crt_set_subject_key(&cert, &subj_key);

  // The private key of the embedded CA is used later to sign the cert
  mbedtls_x509write_crt_set_issuer_key(&cert, &issu_key);
  
  // The serial of the cert is setted
  mbedtls_x509write_crt_set_serial_raw(&cert, serial, 3);
  
  // The algoithm used to do the hash for the signature is specified
  mbedtls_x509write_crt_set_md_alg(&cert, KEYSTONE_SHA3);
  
  // The validity of the crt is specified
  ret = mbedtls_x509write_crt_set_validity(&cert, "20230101000000", "20240101000000");
  if (ret != 0)
  {
    return 0;
  }
  
  unsigned char cert_der[1024];
  int effe_len_cert_der;
  size_t len_cert_der_tot = 1024;

  // Variable used to specify the oid of the extension inserted in the cert
  unsigned char oid_ext[] = {0xff, 0x20, 0xff};

  // Adding the measure of the security monitor like extension in its certificate
  //mbedtls_x509write_crt_set_extension(&cert, oid_ext2, 3, 1, max_path, 2);
  mbedtls_x509write_crt_set_extension(&cert, oid_ext, 3, 0, sanctum_sm_hash, 64);
  mbedtls_x509write_crt_set_basic_constraints(&cert, 1, 10);



  // The structure mbedtls_x509write_cert is parsed to create a x509 cert in der format, signed with the private key of the issuer and written in memory
  ret = mbedtls_x509write_crt_der(&cert, cert_der, len_cert_der_tot, NULL, NULL);//, test, &len);
  if (ret != 0)
  {
    effe_len_cert_der = ret;
  }
  else
  {
    return 0;
  }
  
  unsigned char *cert_real = cert_der;
  // effe_len_cert_der stands for the length of the cert, placed starting from the end of the buffer cert_der
  int dif  = 1024-effe_len_cert_der;
  // cert_real points to the starts of the cert in der format
  cert_real += dif;

  /*
  if ((mbedtls_x509_crt_parse_der(&uff_cert, cert_real, effe_len_cert_der)) != 0){
     return 0;
  }
  if(my_memcmp( uff_cert.hash.p_arr, sanctum_sm_hash, 64) != 0)
    return 0;
  //else
    //return 0;
  */

  sanctum_length_cert = effe_len_cert_der;
  memcpy(sanctum_cert_sm, cert_real, effe_len_cert_der);

  //In the real case the cert associated to the device root key is provided by the manufacturer
  //in this scenario it is not possible due to the fact the SM can change, so also its measure can change
  //and if the sm measure change also the CDI and consequently the device root keys will change.
  //So until the sm can change, the cert associated to the device root keys are generated here
  //In this way there will be no problem to check the cert, that otherwise will be associated to a device root key pub wrong
  /***********************************************************************************************************/
  /***********************************************************************************************************/

  
  mbedtls_x509write_cert cert_root;
  mbedtls_x509write_crt_init(&cert_root);

  // Setting the name of the issuer of the cert
  
  ret = mbedtls_x509write_crt_set_issuer_name_mod(&cert_root, "O=Manufacturer");
  if (ret != 0)
  {
    return 0;
  }
  
  // Setting the name of the subject of the cert
  
  ret = mbedtls_x509write_crt_set_subject_name_mod(&cert_root, "O=Root of Trust");
  if (ret != 0)
  {
    return 0;
  }

  // pk context used to embed the keys of the subject of the cert
  mbedtls_pk_context subj_key_test;
  mbedtls_pk_init(&subj_key_test);

  // pk context used to embed the keys of the issuer of the cert
  mbedtls_pk_context issu_key_test;
  mbedtls_pk_init(&issu_key_test);
  
  // Parsing the private key of the embedded CA that will be used to sign the certificate of the security monitor
  ret = mbedtls_pk_parse_public_key(&issu_key_test, sanctum_dev_secret_key, 64, 1);
  if (ret != 0)
  {
    return 0;
  }

  ret = mbedtls_pk_parse_public_key(&issu_key_test, sanctum_dev_public_key, 32, 0);
  if (ret != 0)
  {
    return 0;
  }

  // Parsing the public key of the security monitor that will be inserted in its certificate 
  ret = mbedtls_pk_parse_public_key(&subj_key_test, sanctum_device_root_key_pub, 32, 0);
  if (ret != 0)
  {
    return 0;
  }

  
  // Variable  used to specify the serial of the cert
  unsigned char serial_root[] = {0x00, 0x00, 0x00};
  
  // The public key of the security monitor is inserted in the structure
  mbedtls_x509write_crt_set_subject_key(&cert_root, &subj_key_test);

  // The private key of the embedded CA is used later to sign the cert
  mbedtls_x509write_crt_set_issuer_key(&cert_root, &issu_key_test);
  
  // The serial of the cert is setted
  mbedtls_x509write_crt_set_serial_raw(&cert_root, serial_root, 3);
  
  // The algoithm used to do the hash for the signature is specified
  mbedtls_x509write_crt_set_md_alg(&cert_root, KEYSTONE_SHA3);
  
  // The validity of the crt is specified
  ret = mbedtls_x509write_crt_set_validity(&cert_root, "20230101000000", "20240101000000");
  if (ret != 0)
  {
    return 0;
  }

  // Adding the measure of the security monitor like extension in its certificate
  //mbedtls_x509write_crt_set_extension(&cert_root, oid_ext2, 3, 1, max_path, 2);
  mbedtls_x509write_crt_set_basic_constraints(&cert_root, 1, 10);

  
  unsigned char cert_der_root[1024];
  int effe_len_cert_der_root;

  // The structure mbedtls_x509write_cert is parsed to create a x509 cert in der format, signed and written in memory
  ret = mbedtls_x509write_crt_der(&cert_root, cert_der_root, 1024, NULL, NULL);//, test, &len);
  if (ret != 0)
  {
    effe_len_cert_der_root = ret;
  }
  else
  {
    return 0;
  }

  unsigned char *cert_real_root = cert_der_root;
  // effe_len_cert_der stands for the length of the cert, placed starting from the end of the buffer cert_der
  int dif_root = 1024-effe_len_cert_der_root;
  // cert_real points to the starts of the cert in der format
  cert_real_root += dif_root;

  sanctum_length_cert_root = effe_len_cert_der_root;
  memcpy(sanctum_cert_root, cert_real_root, effe_len_cert_der_root);
  /*****************************************************************************************************************/
  /*****************************************************************************************************************/

  //memcpy(test, sanctum_device_root_key_pub, 64);

  //Test to check the signature
  //////////////////////////////////////////////////////////////////////////////
  /*
  mbedtls_x509_crt uff_cert;
  mbedtls_x509_crt_init(&uff_cert);
  if ((mbedtls_x509_crt_parse_der(&uff_cert, sanctum_cert_sm, sanctum_length_cert)) != 0){
     return 0;
  }
  int flag = 0;

  for(int i = 0; i < 64; i ++){
    if (sanctum_sm_hash[i] != uff_cert.hash.p[i])
      flag = 1;
  }
  */

  /*
  unsigned char app[64];
  sha3_init(&hash_ctx, 64);
  sha3_update(&hash_ctx, uff_cert.tbs.p, uff_cert.tbs.len);
  sha3_final(app, &hash_ctx);

  /* 
  if(my_memcmp(app, test, 64) != 0)
    return 0;
  
  if((ed25519_verify(uff_cert.sig.p, app, 64, sanctum_device_root_key_pub)) == 0){
    return 0;
  }*/
 /*
  if(uff_cert.tbs.len != len)
    return 0;

  if(my_memcmp( uff_cert.tbs.p, test, uff_cert.tbs.len) != 0)
    return 0;

  */
  ///////////////////////////////////////////////////////////////////////////////////////////
  //sanctum_length_cert = effe_len_cert_der;
  
  memset((void *)sanctum_ECASM_priv, 0, sizeof(*sanctum_ECASM_priv));

  // Erase DRK_priv
  memset((void *)sanctum_device_root_key_priv, 0, sizeof(*sanctum_device_root_key_priv));

  // Erase eca_key_priv
  //memset((void *)sanctum_eca_key_priv, 0, sizeof(*sanctum_eca_key_priv));


//------------------------------------------------------------------------------------------------------------------//
  // Derive {SK_D, PK_D} (device keys) from a 32 B random seed
  // ed25519_create_keypair(sanctum_dev_public_key, sanctum_dev_secret_key, scratchpad);

  // Combine SK_D and H_SM via a hash
  // sm_key_seed <-- H(SK_D, H_SM), truncate to 32B
  sha3_init(&hash_ctx, 64);
  sha3_update(&hash_ctx, sanctum_dev_secret_key, sizeof(*sanctum_dev_secret_key));
  sha3_update(&hash_ctx, sanctum_sm_hash, sizeof(*sanctum_sm_hash));
  sha3_final(scratchpad, &hash_ctx);
  // Derive {SK_D, PK_D} (device keys) from the first 32 B of the hash (NIST endorses SHA512 truncation as safe)
  ed25519_create_keypair(sanctum_sm_public_key, sanctum_sm_secret_key, scratchpad);

  // Endorse the SM
  memcpy(scratchpad, sanctum_sm_hash, 64);
  memcpy(scratchpad + 64, sanctum_sm_public_key, 32);


  // Sign (H_SM, PK_SM) with SK_D
  ed25519_sign(sanctum_sm_signature, scratchpad, 64 + 32, sanctum_dev_public_key, sanctum_dev_secret_key);

  // Clean up
  // Erase SK_D
  memset((void *)sanctum_dev_secret_key, 0, sizeof(*sanctum_dev_secret_key));

  return 1; // it SHOULD be put in a0 register

 
}



////////////////////////////////////////////////////////////////////////////////////////////
  

  