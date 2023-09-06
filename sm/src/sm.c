//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "ipi.h"
#include "sm.h"
#include "pmp.h"
#include "crypto.h"
#include "enclave.h"
#include "platform-hook.h"
#include "sm-sbi-opensbi.h"
#include <sbi/sbi_string.h>
#include <sbi/riscv_locks.h>
#include <sbi/riscv_barrier.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_hart.h>
#include "sha3/sha3.h"
#include <sbi/sbi_timer.h>

#include "x509custom.h"
#define DRAM_BASE 0x80000000

static int sm_init_done = 0;
static int sm_region_id = 0, os_region_id = 0;

/* from Sanctum BootROM */
extern byte sanctum_sm_hash[MDSIZE];
extern byte sanctum_sm_signature[SIGNATURE_SIZE];
extern byte sanctum_sm_secret_key[PRIVATE_KEY_SIZE];
extern byte sanctum_sm_public_key[PUBLIC_KEY_SIZE];
extern byte sanctum_dev_public_key[PUBLIC_KEY_SIZE];

// Variable used to pass the all that is needed to the SM to properly work
extern byte sanctum_CDI[64];
extern byte sanctum_cert_sm[512];
extern byte sanctum_cert_root[512];
extern byte sanctum_cert_man[512];
extern int sanctum_length_cert;
extern int sanctum_length_cert_root;
extern int sanctum_length_cert_man;


byte CDI[64] = { 0, };
byte cert_sm[512] = { 0, };
int length_cert;
byte cert_root[512] = { 0, };
int length_cert_root;
byte cert_man[512] = { 0, };
int length_cert_man;

byte ECASM_priv[64];
byte ECASM_pk[64] = { 0, };

mbedtls_x509_crt uff_cert_sm;
mbedtls_x509_crt uff_cert_root;
mbedtls_x509_crt uff_cert_man;

//extern byte sanctum_sm_hash_to_check[64];
//byte device_root_key_pub[64] = {0,};
//extern byte sanctum_device_root_key_pub[64];



// the pk of the ECA is only 32bytes, but according to the alignment of the memory, it has to be of 64 bytes
/*
* Variable used to verify that the public key of the sm created during the boot is the same key obtained after the
* parsing of the certificate in der format
*/
//extern byte sanctum_ECASM_pk[64];



//extern byte sanctum_sm_signature_drk[64];

byte sm_hash[MDSIZE] = { 0, };
byte sm_signature[SIGNATURE_SIZE] = { 0, };
byte sm_public_key[PUBLIC_KEY_SIZE] = { 0, };
byte sm_private_key[PRIVATE_KEY_SIZE] = { 0, };
byte dev_public_key[PUBLIC_KEY_SIZE] = { 0, };

//byte sm_hash_to_check[64] = { 0, };
//byte sm_key_pub[64] = { 0, };
//byte sm_signature_drk[64] = {0,};


byte hash_for_verification[64];
sha3_ctx_t ctx_hash;

// Variable used for testing porpouse to pass data from the boot stage to the sm
extern byte test[64];
byte app_test[64] = {0,};
byte seed_for_ECA_keys[64] = {0,};
unsigned int sanctum_sm_size = 0x1ff000;

u64 init_value;
u64 final_value;


char* validation(mbedtls_x509_crt cert);

int osm_pmp_set(uint8_t perm)
{
  /* in case of OSM, PMP cfg is exactly the opposite.*/
  return pmp_set_keystone(os_region_id, perm);
}

int smm_init()
{
  int region = -1;
  int ret = pmp_region_init_atomic(SMM_BASE, SMM_SIZE, PMP_PRI_TOP, &region, 0);
  if(ret)
    return -1;

  return region;
}

int osm_init()
{
  int region = -1;
  int ret = pmp_region_init_atomic(0, -1UL, PMP_PRI_BOTTOM, &region, 1);
  if(ret)
    return -1;

  return region;
}

void sm_sign(void* signature, const void* data, size_t len)
{
  sign(signature, data, len, sm_public_key, sm_private_key);
}

int sm_derive_sealing_key(unsigned char *key, const unsigned char *key_ident,
                          size_t key_ident_size,
                          const unsigned char *enclave_hash)
{
  unsigned char info[MDSIZE + key_ident_size];

  sbi_memcpy(info, enclave_hash, MDSIZE);
  sbi_memcpy(info + MDSIZE, key_ident, key_ident_size);

  /*
   * The key is derived without a salt because we have no entropy source
   * available to generate the salt.
   */
  return kdf(NULL, 0,
             (const unsigned char *)sm_private_key, PRIVATE_KEY_SIZE,
             info, MDSIZE + key_ident_size, key, SEALING_KEY_SIZE);
}

void sm_copy_key()
{
  sbi_memcpy(sm_hash, sanctum_sm_hash, MDSIZE);
  sbi_memcpy(sm_signature, sanctum_sm_signature, SIGNATURE_SIZE);
  sbi_memcpy(sm_public_key, sanctum_sm_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(sm_private_key, sanctum_sm_secret_key, PRIVATE_KEY_SIZE);
  sbi_memcpy(dev_public_key, sanctum_dev_public_key, PUBLIC_KEY_SIZE);

  // All the variables passed from the boot stage are copied in sm variables
  sbi_memcpy(CDI, sanctum_CDI, 64);
  sbi_memcpy(cert_sm, sanctum_cert_sm, sanctum_length_cert);
  sbi_memcpy(cert_root, sanctum_cert_root, sanctum_length_cert_root);
  sbi_memcpy(cert_man, sanctum_cert_man, sanctum_length_cert_man); 
  length_cert = sanctum_length_cert;
  length_cert_root = sanctum_length_cert_root;
  length_cert_man = sanctum_length_cert_man;


  /*
  sbi_printf("Lunghezza sm: %i\n", length_cert);
  sbi_printf("Lunghezza root: %i\n", length_cert_root);
  sbi_printf("Lunghezza man: %i\n", length_cert_man);
   sbi_printf("cert man der format:\n");
  for(int i = 0; i < length_cert_man; i ++){
    sbi_printf("0x%02x,", cert_man[i]);
  }
  sbi_printf("\n-------------------------------------------------\n");
  sbi_printf("ECASM_pk:\n");
  for(int i = 0; i < 32; i ++){
    sbi_printf("%02x", ECASM_pk[i]);
  }
  sbi_printf("\n-------------------------------------------------\n");
  
  sbi_printf("sm_hash_to_check:\n");
  for(int i = 0; i < 64; i ++){
    sbi_printf("%02x", sm_hash_to_check[i]);
  }
  sbi_printf("\n-------------------------------------------------\n");
  
  sbi_printf("sm_signature_drk:\n");
  for(int i = 0; i < 64; i ++){
    sbi_printf("%02x", sm_signature_drk[i]);
  }
  sbi_printf("\n-------------------------------------------------\n"); */

  // The different certs are parsed if there are no 
  //cert_sm[0] = 0xAF;
  if ((mbedtls_x509_crt_parse_der(&uff_cert_sm, cert_sm, length_cert)) != 0){

      // If there are some problems parsing a cert, all the start process is stopped
      //cambiare printf certificato
      //cambiare sm in verifica successiva
      sbi_printf("\n\n\n[SM] Error parsing the ECA certificate");
      sbi_hart_hang();
  }
  else{
    sbi_printf("\n[SM] The ECA certificate is correctly parsed\n\n");

  }

  if ((mbedtls_x509_crt_parse_der(&uff_cert_root, cert_root, length_cert_root)) != 0){
      sbi_printf("[SM] Error parsing the DRK certificate\n\n");
      sbi_hart_hang();
  }
  else{
    sbi_printf("[SM] The DRK certificate is correctly parsed\n\n");

  }

  if ((mbedtls_x509_crt_parse_der(&uff_cert_man, cert_man, length_cert_man)) != 0){
      sbi_printf("[SM] Error parsing the manufacturer certificate\n\n");
      sbi_hart_hang();
  }
  else{
    sbi_printf("[SM] The manufacturer certificate is correctly parsed\n\n");

  }
  /*
  sbi_printf("device_root_key_pub:\n");
  for(int i = 0; i < 32; i ++){
    sbi_printf("%02x", uff_cert_root.pk.pk_ctx.pub_key[i]);
  }
  sbi_printf("\n-------------------------------------------------\n");
  */
 /*
  sbi_printf("length_cert:");
  sbi_printf("%d", length_cert);
  sbi_printf("\n-------------------------------------------------\n");
  sbi_printf("cert der format:\n");
  for(int i = 0; i < length_cert; i ++){
    sbi_printf("%02x", cert_sm[i]);
  }
  sbi_printf("\n-------------------------------------------------\n");
  sbi_printf("length_cert_root:");
  sbi_printf("%d", length_cert_root);
  sbi_printf("\n-------------------------------------------------\n");
  sbi_printf("cert root der format:\n");
  for(int i = 0; i < length_cert_root; i ++){
    sbi_printf("0x%02x,", cert_root[i]);
  }
  sbi_printf("\n-------------------------------------------------\n");
  sbi_printf("length_cert_man:");
  sbi_printf("%d", length_cert_man);
  sbi_printf("\n-------------------------------------------------\n");
  sbi_printf("cert man der format:\n");
  for(int i = 0; i < length_cert_man; i ++){
    sbi_printf("0x%02x,", cert_man[i]);
  }
  sbi_printf("\n-------------------------------------------------\n");
    sbi_printf("length_cert:");
  sbi_printf("%d", length_cert_man);
  sbi_printf("\n-------------------------------------------------\n");
  sbi_printf("cert man der format:\n");
  for(int i = 0; i < length_cert_man; i ++){
    sbi_printf("0x%02x,", cert_man[i]);
  }
  sbi_printf("\n-------------------------------------------------\n");
*/

  // Check that all the certs in the chain are formally correct
  //uff_cert_sm.valid_from.day = 0;
  char* str_ret = validation(uff_cert_sm);
  if(my_strlen(str_ret) != 0){
    sbi_printf("[SM] Problem with the ECA certificate: %s \n\n", str_ret);
    sbi_hart_hang();

  }
  else 
  {
    str_ret = validation(uff_cert_root);
    if(my_strlen(str_ret) != 0){
      sbi_printf("[SM] Problem with the DRK certificate: %s \n\n", str_ret);
      sbi_hart_hang();

    }
    else {
      str_ret = validation(uff_cert_man);
      if(my_strlen(str_ret) != 0){
        sbi_printf("[SM] Problem with the manufacturer certificate: %s \n\n", str_ret);
        sbi_hart_hang();

      }
      else {
        sbi_printf("[SM] All the certificate chain is formally correct\n\n");
      }
    }
  }

  // If the hash of the field is not the same that is computed in the boot process, the verification of the signature goes wrong
  //hash_for_verification[0] = 0x23;

  /*
  *
  * Test used to check if the hash obtained from parsing the cert in the der format
  * is the same of the hash computed during the creation of the cert in der format to sign it
  * */
 /*  sbi_printf("hash_for_verification: \n");
    for(int i =0; i <64; i ++){
        sbi_printf("%02x",hash_for_verification[i]);//   pk_ctx->pub_key[i]);
    }
  sbi_printf("\n\n\n\n");
  sbi_printf("test: \n");
    for(int i =0; i <64; i ++){
        sbi_printf("%02x",test[i]);//   pk_ctx->pub_key[i]);
    }
  sbi_printf("\n\n\n\n");*/
  /*
   sbi_printf("TBS: \n");
    for(int i =0; i <uff_cert_sm.tbs.len; i ++){
        sbi_printf("%02x",uff_cert_sm.tbs.p[i]);//   pk_ctx->pub_key[i]);
    }
  sbi_printf("\n\n\n\n");
  */
  /**
   * Verifying the signature
   * 
  */

 // Once the cert in der format is parsed, there is a field inserted in the structure that represents the raw data of the cert that is used to compute the hash
  // that later has been signed with the public key of the issuer
  // Using the same field, the sm cane verify the signature inserted in his cert, using the public key of the issuer (in this case the issuer is the root of trust)

  sha3_init(&ctx_hash, 64);
  sha3_update(&ctx_hash, uff_cert_sm.tbs.p, uff_cert_sm.tbs.len);
  sha3_final(hash_for_verification, &ctx_hash);
  sbi_printf("[SM] Verifying the chain signatures of the certificates until the man cert...\n\n");

  if(ed25519_verify(uff_cert_sm.sig.p, hash_for_verification, 64, uff_cert_root.pk.pk_ctx.pub_key) == 0){
    sbi_printf("[SM] Error verifying the signature of the ECA certificate\n\n");
    sbi_hart_hang();
  }
  else{
    // The verification process is also repeated to verify the cert associated to the root of trust, certified with the private key of the manufacturer
    sbi_printf("[SM] The signature of the ECA certificate is ok\n\n");
    sha3_init(&ctx_hash, 64);
    sha3_update(&ctx_hash, uff_cert_root.tbs.p, uff_cert_root.tbs.len);
    sha3_final(hash_for_verification, &ctx_hash);
    //hash_for_verification[0] = 0x0;

    if(ed25519_verify(uff_cert_root.sig.p, hash_for_verification, 64, uff_cert_man.pk.pk_ctx.pub_key) == 0){
      sbi_printf("[SM] Error verifying the signature of the DRK certificate\n\n");
      sbi_hart_hang();
    }
    else{
      sbi_printf("[SM] The signature of the DRK certificate is ok\n\n");

      sbi_printf("[SM] All the chain is verified\n\n");
    }
  }

    // Some informations about the variables obtained are printed to the screen
    /*
  sbi_printf("CDI:\n");
  for(int i = 0; i < 64; i ++){
    sbi_printf("%02x", CDI[i]);
  }
  sbi_printf("\n\n");
  */

  // Checking that the measure inserted in the cert, is itself correct and that the parsing process goes well
  /*
  sbi_printf("Measure of the sm added in the x509 crt der (extension): \n");
    for(int i =0; i <64; i ++){
        sbi_printf("%02x",uff_cert_sm.hash.p[i]);
    }
  sbi_printf("\n\n");
  sbi_printf("sm hash passed by default keystone implementation: \n");
    for(int i =0; i <64; i ++){
        sbi_printf("%02x",sm_hash[i]);
    }
  sbi_printf("\n\n");
  */

  //uff_cert_sm.hash.p[0] = 0x23;
  if(my_memcmp(uff_cert_sm.hash.p, sm_hash, 64) != 0){
    sbi_printf("[SM] Problem with the extension of the ECA certificate");
    sbi_hart_hang();
  }
  else
      sbi_printf("[SM] No differeces between ECA cert extension and value provided by original Keystone implementation\n\n");


  // Printing the signature of the sm cert
  /*
  sbi_printf("Signature of the certificate: \n");
    for(int i =0; i <64; i ++){
        sbi_printf("%02x",uff_cert_sm.sig.p[i]);//   pk_ctx->pub_key[i]);
    }
  sbi_printf("\n\n\n\n");
  */

  /**
   * Checking the measure made by the boot of the SM
   */
    /*
    sha3_init(&ctx_hash, 64);
    sha3_update(&ctx_hash, (void *)DRAM_BASE, sanctum_sm_size);
    sha3_final(hash_for_verification, &ctx_hash);
  */

    /*
    if ((ed25519_verify(sm_signature_drk, sm_hash_to_check, 64, device_root_key_pub)) == 0)
    {
      sbi_printf("[SM] Error verifying the signature of the SM measure made during the boot\n");
      sbi_hart_hang();
    }
    else
    {
      sbi_printf("[SM] The signature of the SM measure made during the boot is correct\n\n");
    }
    */

  // From the CDI and its measure inserted as extension in the ECA keys certificate,
  // the sm can directly obtain the keys associated to the emebedded CA
  // that are used to signed the cert associated to the attestation key of the different enclaves 
  sha3_init(&ctx_hash, 64);
  sha3_update(&ctx_hash, CDI, 64);
  sha3_update(&ctx_hash, uff_cert_sm.hash.p, 64);
  sha3_final(seed_for_ECA_keys, &ctx_hash);

  ed25519_create_keypair(ECASM_pk, ECASM_priv, seed_for_ECA_keys);

  //sbi_printf("Time post operation: %ld\n", sbi_timer_value());
  //INIT timer: 27589412d
  //Time post operation: 27796328d

  /*
  sbi_printf("ECASM_priv: \n");
    for(int i =0; i <64; i ++){
        sbi_printf("%02x",ECASM_priv[i]);//   pk_ctx->pub_key[i]);
    }
  sbi_printf("\n\n\n\n");
  sbi_printf("test: \n");
    for(int i =0; i <64; i ++){
        sbi_printf("%02x",test[i]);//   pk_ctx->pub_key[i]);
    }
  sbi_printf("\n\n\n\n");
  */
  /*
  sbi_printf("length_cert_root:");
  sbi_printf("%d", length_cert_root);
  sbi_printf("\n-------------------------------------------------\n");
  sbi_printf("cert root der format:\n");
  for(int i = 0; i < length_cert_root; i ++){
    sbi_printf("0x%02x,", cert_root[i]);
  }
  sbi_printf("\n-------------------------------------------------\n");
*/

  /*
  * To check that the data read from the certificate is the correct one created in the booting stage
  */
  ///////////////////////////////////////////////////////////////////////////////
  /*
  sbi_printf("-----------------------------------------------------------------------------------------\n");
  sbi_printf("Comparing what is parsed from the cert and what is directly passed from the booting stage\n");
  sbi_printf("-----------------------------------------------------------------------------------------\n");
  sbi_printf("sanctum_sm_key_pub from the booting stage\n");
  for(int i = 0; i < 32; i ++){
    sbi_printf("%02x", ECASM_pk[i]);
  }
  sbi_printf("\n\n");
  sbi_printf("sanctum_sm_key_pub obtained parsing the der format cert\n");
    for(int i =0; i <32; i ++){
        sbi_printf("%02x",uff_cert_sm.pk.pk_ctx.pub_key[i]);//   pk_ctx->pub_key[i]);
    }
  sbi_printf("\n");
  sbi_printf("-----------------------------------------------------------------------------------------\n");
  */
  ////////////////////////////////////////////////////////////////////////////////
}

void sm_print_hash()
{
  for (int i=0; i<MDSIZE; i++)
  {
    sbi_printf("%02x", (char) sm_hash[i]);
  }
  sbi_printf("\n");
}

/*
void sm_print_cert()
{
	int i;

	printm("Booting from Security Monitor\n");
	printm("Size: %d\n", sanctum_sm_size[0]);

	printm("============ PUBKEY =============\n");
	for(i=0; i<8; i+=1)
	{
		printm("%x",*((int*)sanctum_dev_public_key+i));
		if(i%4==3) printm("\n");
	}
	printm("=================================\n");

	printm("=========== SIGNATURE ===========\n");
	for(i=0; i<16; i+=1)
	{
		printm("%x",*((int*)sanctum_sm_signature+i));
		if(i%4==3) printm("\n");
	}
	printm("=================================\n");
}
*/

void sm_init(bool cold_boot)
{
	// initialize SMM
  if (cold_boot) {
    /* only the cold-booting hart will execute these */
    sbi_printf("[SM] Initializing ... hart [%lx]\n", csr_read(mhartid));

    init_value = sbi_timer_value();

    sbi_ecall_register_extension(&ecall_keystone_enclave);

    sm_region_id = smm_init();
    mbedtls_x509_crt_init(&uff_cert_sm);
    mbedtls_x509_crt_init(&uff_cert_root);

    if(sm_region_id < 0) {
      sbi_printf("[SM] intolerable error - failed to initialize SM memory");
      sbi_hart_hang();
    }

    os_region_id = osm_init();
    if(os_region_id < 0) {
      sbi_printf("[SM] intolerable error - failed to initialize OS memory");
      sbi_hart_hang();
    }

    if (platform_init_global_once() != SBI_ERR_SM_ENCLAVE_SUCCESS) {
      sbi_printf("[SM] platform global init fatal error");
      sbi_hart_hang();
    }
    // Copy the keypair from the root of trust
    sm_copy_key();

    // Init the enclave metadata
    enclave_init_metadata();

    sm_init_done = 1;
    mb();
  }

  /* wait until cold-boot hart finishes */
  while (!sm_init_done)
  {
    mb();
  }

  /* below are executed by all harts */
  pmp_init();
  pmp_set_keystone(sm_region_id, PMP_NO_PERM);
  pmp_set_keystone(os_region_id, PMP_ALL_PERM);

  /* Fire platform specific global init */
  if (platform_init_global() != SBI_ERR_SM_ENCLAVE_SUCCESS) {
    sbi_printf("[SM] platform global init fatal error");
    sbi_hart_hang();
  }

  sbi_printf("[SM] Keystone security monitor has been initialized!\n");
  final_value = sbi_timer_value();
  sm_print_hash();

  return;
  // for debug
  // sm_print_cert();
}

char* validation(mbedtls_x509_crt cert){

  //return "Problem with the issuer of the certificate";
  if(cert.ne_issue_arr == 0)
    return "Problem with the issuer of the certificate";
  if(cert.ne_subje_arr == 0)
    return "Problem with the subject of the certificate";
  if(((cert.valid_from.day < 1)&& (cert.valid_from.day > 31)) || ((cert.valid_from.mon < 1)&& (cert.valid_from.mon > 12)) || (cert.valid_from.year == 0))
    return "Problem with the valid_from field of the certificate";
  if(((cert.valid_to.day < 1)&& (cert.valid_to.day > 31)) || ((cert.valid_to.mon < 1)&& (cert.valid_to.mon > 12)) || (cert.valid_to.year == 0))
    return "Problem with the valid_to field of the certificate";
  if(cert.pk.pk_ctx.len != 32)
    return "Problem with the pk length of the certificate";
  if(cert.serial.len == 0)
    return "Problem with the serial length of the certificate";
  if(cert.sig.len == 0)
    return "Problem with the signature length of the certificate";
  return "";

}
