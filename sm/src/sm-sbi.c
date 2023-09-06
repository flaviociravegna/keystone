//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "sm-sbi.h"
#include "pmp.h"
#include "enclave.h"
#include "page.h"
#include "cpu.h"
#include "platform-hook.h"
#include "plugins/plugins.h"
#include <sbi/riscv_asm.h>
#include <sbi/sbi_console.h>

unsigned long sbi_sm_create_enclave(unsigned long* eid, uintptr_t create_args)
{
  struct keystone_sbi_create create_args_local;
  unsigned long ret;

  ret = copy_enclave_create_args(create_args, &create_args_local);

  if (ret)
    return ret;

  ret = create_enclave(eid, create_args_local);
  return ret;
}

unsigned long sbi_sm_destroy_enclave(unsigned long eid)
{
  unsigned long ret;
  ret = destroy_enclave((unsigned int)eid);
  return ret;
}

unsigned long sbi_sm_run_enclave(struct sbi_trap_regs *regs, unsigned long eid)
{
  regs->a0 = run_enclave(regs, (unsigned int) eid);
  regs->mepc += 4;
  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_resume_enclave(struct sbi_trap_regs *regs, unsigned long eid)
{
  unsigned long ret;
  ret = resume_enclave(regs, (unsigned int) eid);
  if (!regs->zero)
    regs->a0 = ret;
  regs->mepc += 4;

  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_exit_enclave(struct sbi_trap_regs *regs, unsigned long retval)
{
  regs->a0 = exit_enclave(regs, cpu_get_enclave_id());
  regs->a1 = retval;
  regs->mepc += 4;
  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_stop_enclave(struct sbi_trap_regs *regs, unsigned long request)
{
  regs->a0 = stop_enclave(regs, request, cpu_get_enclave_id());
  regs->mepc += 4;
  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_runtime_attestation(uintptr_t report, uintptr_t data, uintptr_t size) {
  struct report report_local;
  unsigned long ret = copy_enclave_report_runtime_attestation_into_sm(report, &report_local);  
  
  if (ret) {
    sbi_printf("[SM] Error while copying runtime attestation report\n");
    return ret;
  }
  
  ret = attest_integrity_at_runtime(&report_local, data, size, cpu_get_enclave_id());
  if (ret)
    return ret;

  ret = copy_enclave_report_runtime_attestation_from_sm(&report_local, report);
  if (ret)
    sbi_printf("[SM] Error while copying runtime attestation report\n");
    
  return ret;
}

unsigned long sbi_sm_attest_enclave(uintptr_t report, uintptr_t data, uintptr_t size)
{
  unsigned long ret;
  ret = attest_enclave(report, data, size, cpu_get_enclave_id());
  return ret;
}

unsigned long sbi_sm_get_sealing_key(uintptr_t sealing_key, uintptr_t key_ident,
                       size_t key_ident_size)
{
  unsigned long ret;
  ret = get_sealing_key(sealing_key, key_ident, key_ident_size,
                         cpu_get_enclave_id());
  return ret;
}

unsigned long sbi_sm_random()
{
  return (unsigned long) platform_random();
}

unsigned long sbi_sm_call_plugin(uintptr_t plugin_id, uintptr_t call_id, uintptr_t arg0, uintptr_t arg1)
{
  unsigned long ret;
  ret = call_plugin(cpu_get_enclave_id(), plugin_id, call_id, arg0, arg1);
  return ret;
}

unsigned long sbi_sm_create_keypair(uintptr_t pk, int index)
{
  unsigned long ret;
  ret = create_keypair(cpu_get_enclave_id(), (unsigned char *) pk, index);
  return ret;
}

unsigned long
getting_cert_chain(uintptr_t* certs, int* sizes){
  unsigned long ret;
  ret = get_cert_chain(cpu_get_enclave_id(), (unsigned char **) certs, sizes);
  return ret;
}

unsigned long sbi_do_crypto_op(int flag, unsigned char* data, int data_len, unsigned char *out_buf, int* out_buf_len, uintptr_t pk){
  unsigned long ret;
  ret = do_crypto_op(cpu_get_enclave_id(), flag, data, data_len, out_buf, out_buf_len, (unsigned char *)pk);
  return ret;
}

unsigned long sbi_sm_get_cert_chain_and_lak(unsigned char *cert_sm, unsigned char *cert_root, unsigned char *cert_man, int *lengths) {
  unsigned long ret;
  //unsigned char certs[3][512];    // 512 should be enough for each certificate
  int sizes[3];

  unsigned char temp_cert_sm[512];
  unsigned char temp_cert_root[512];
  unsigned char temp_cert_man[512];

  //ret = get_cert_chain(cpu_get_enclave_id(), (unsigned char **) certs, sizes);
  get_cert(temp_cert_sm, &(sizes[0]), 0);
  //sbi_printf("[SM] Copied SM cert\n");
  get_cert(temp_cert_root, &(sizes[1]), 1);
  //sbi_printf("[SM] Copied ROOT cert\n");
  get_cert(temp_cert_man, &(sizes[2]), 2);
  //sbi_printf("[SM] Copied ROOT cert\n");
  ret = copy_cert_from_sm(temp_cert_sm, (uintptr_t) cert_sm, sizes[0] * sizeof(unsigned char));
  if (ret) {
    sbi_printf("[SM] Error while copying sm certificate from SM\n");
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }

  ret = copy_cert_from_sm(temp_cert_root, (uintptr_t) cert_root, sizes[1] * sizeof(unsigned char));
  if (ret) {
    sbi_printf("[SM] Error while copying root certificate from SM\n");
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }

  ret = copy_cert_from_sm(temp_cert_man, (uintptr_t) cert_root, sizes[2] * sizeof(unsigned char));
  if (ret) {
    sbi_printf("[SM] Error while copying man certificate from SM\n");
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }

  ret = copy_cert_lengths_from_sm(sizes, (uintptr_t) lengths, 3 * sizeof(int));
  if (ret) {
    sbi_printf("[SM] Error while copying the lengths array from SM\n");
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }

  return ret;
}

/***************** NEW SYSCALL *******************/

unsigned long sbi_sm_verify_integrity_rt_eapp() {
    return verify_integrity_rt_eapp(cpu_get_enclave_id());
}
