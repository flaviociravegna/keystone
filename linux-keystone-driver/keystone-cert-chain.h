#define MAX_CERT_LEN 512

struct keystone_ioctl_cert_chain {
    uintptr_t eid;
    unsigned char cert_sm[MAX_CERT_LEN];
    unsigned char cert_root[MAX_CERT_LEN];
    unsigned char cert_man[MAX_CERT_LEN];
    unsigned char cert_lak[MAX_CERT_LEN];
    int lengths[3];
};