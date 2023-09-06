//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "syscall.h"

/* this implementes basic system calls for the enclave */

int
ocall(
    unsigned long call_id, void* data, size_t data_len, void* return_buffer,
    size_t return_len) {
  return SYSCALL_5(
      SYSCALL_OCALL, call_id, data, data_len, return_buffer, return_len);
}

int
copy_from_shared(void* dst, uintptr_t offset, size_t data_len) {
  return SYSCALL_3(SYSCALL_SHAREDCOPY, dst, offset, data_len);
}

int
attest_enclave(void* report, void* data, size_t size) {
  return SYSCALL_3(SYSCALL_ATTEST_ENCLAVE, report, data, size);
}

/* returns sealing key */
int
get_sealing_key(
    struct sealing_key* sealing_key_struct, size_t sealing_key_struct_size,
    void* key_ident, size_t key_ident_size) {
  return SYSCALL_4(
      SYSCALL_GET_SEALING_KEY, sealing_key_struct, sealing_key_struct_size,
      key_ident, key_ident_size);
}

int verify_integrity_rt_eapp() {
    return SYSCALL_0(SYSCALL_VERIFY_INTEGRITY_RT_EAPP);
}

int
create_keypair(void* pk, unsigned long index){
  return CUSTOM_SYSCALL(SYSCALL_CREATE_KEYPAIR, pk, index, 0, 0, 0, 0);
}

int
get_cert_chain(void* cert_1, void* cert_2, void* cert_3, void* size_1, void* size_2, void* size_3){
  return CUSTOM_SYSCALL(SYSCALL_GET_CHAIN, cert_1, cert_2, cert_3, size_1, size_2, size_3);
}

int
crypto_interface(unsigned long flag, void* data, size_t data_len, void* out_buf, size_t* out_buf_len, void* pk){
  return CUSTOM_SYSCALL(SYSCALL_CRYPTO_INTERFACE, flag, data, data_len, out_buf, out_buf_len, pk);
}

int 
rt_print_string(void* string, size_t length){
  return SYSCALL_2(SYSCALL_PRINT_STRING, string, length);
}
