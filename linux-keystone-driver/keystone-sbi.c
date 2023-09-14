#include "keystone-sbi.h"

struct sbiret sbi_sm_create_enclave(struct keystone_sbi_create_t* args) {
  return sbi_ecall(KEYSTONE_SBI_EXT_ID,
      SBI_SM_CREATE_ENCLAVE,
      (unsigned long) args, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_run_enclave(unsigned long eid) {
  return sbi_ecall(KEYSTONE_SBI_EXT_ID,
      SBI_SM_RUN_ENCLAVE,
      eid, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_destroy_enclave(unsigned long eid) {
  return sbi_ecall(KEYSTONE_SBI_EXT_ID,
      SBI_SM_DESTROY_ENCLAVE,
      eid, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_resume_enclave(unsigned long eid) {
  return sbi_ecall(KEYSTONE_SBI_EXT_ID,
      SBI_SM_RESUME_ENCLAVE,
      eid, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_runtime_attestation_enclave(
  struct runtime_report_t *report,
  unsigned char *nonce) {
    return sbi_ecall(KEYSTONE_SBI_EXT_ID,
    SBI_SM_RUNTIME_ATTESTATION,
    (unsigned long) report, (unsigned long) nonce, 0, 0, 0, 0);
}

struct sbiret sbi_sm_get_cert_chain(
  unsigned char *cert_sm,
  unsigned char *cert_root,
  unsigned char *cert_man,
  unsigned char *cert_lak,
  int *lengths,
  unsigned long eid) {
    return sbi_ecall(
      KEYSTONE_SBI_EXT_ID,
      SBI_SM_GET_CERT_CHAIN,
      (unsigned long) cert_sm,
      (unsigned long) cert_root,
      (unsigned long) cert_man,
      (unsigned long) cert_lak,
      (unsigned long) lengths,
      eid);
}
