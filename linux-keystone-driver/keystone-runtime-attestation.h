#define ATTEST_DATA_MAXLEN 1024
#define MDSIZE 64
#define SIGNATURE_SIZE 64
#define PUBLIC_KEY_SIZE 32

typedef unsigned char byte;

/****** Support for attestation at runtime *******/
struct enclave_report_t {
  byte hash[MDSIZE];
  uint64_t data_len;
  byte data[ATTEST_DATA_MAXLEN];
  byte signature[SIGNATURE_SIZE];
};

struct sm_report_t {
  byte hash[MDSIZE];
  byte public_key[PUBLIC_KEY_SIZE];
  byte signature[SIGNATURE_SIZE];
};

struct report_t {
  struct enclave_report_t enclave;
  struct sm_report_t sm;
  byte dev_public_key[PUBLIC_KEY_SIZE];
};

struct keystone_ioctl_runtime_attestation {
  uintptr_t eid;
  uintptr_t error;
  unsigned long nonce;
  unsigned long size;
  struct report_t attestation_report;
};