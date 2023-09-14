//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "enclave.h"
#include "mprv.h"
#include "pmp.h"
#include "page.h"
#include "cpu.h"
#include "platform-hook.h"
#include <sbi/sbi_string.h>
#include <sbi/riscv_asm.h>
#include <sbi/riscv_locks.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_timer.h>
#include "sha3/sha3.h"
#include "sm.h"
#include "ed25519/ed25519.h"
#include "x509custom.h"

#define PRINT_CERTS 0

#define ENCL_MAX  16

struct enclave enclaves[ENCL_MAX];
#define ENCLAVE_EXISTS(eid) (eid >= 0 && eid < ENCL_MAX && enclaves[eid].state >= 0)

static spinlock_t encl_lock = SPIN_LOCK_INITIALIZER;

extern void save_host_regs(void);
extern void restore_host_regs(void);
extern byte dev_public_key[PUBLIC_KEY_SIZE];

extern byte CDI[64];
extern byte ECASM_pk[64];
extern byte ECASM_priv[64];
extern mbedtls_x509_crt uff_cert_sm;
extern byte device_root_key_pub[64];

extern byte cert_sm[512];
extern int length_cert;
extern byte cert_root[512];
extern int length_cert_root;
extern byte cert_man[512];
extern byte length_cert_man;
sha3_ctx_t hash_ctx_to_use;

int print_hex_string(char* name, unsigned char* value, int size){
  sbi_printf("%s: 0x", name);
  for(int i = 0; i< size; i++){
    sbi_printf("%02x", value[i]);
  }
  sbi_printf("\r\n");
  sbi_printf("%s_len: %d\r\n", name, size);
  return 0;
}

int print_mbedtls_asn1_buf_no_arr(char *name, mbedtls_asn1_buf_no_arr buf){
  sbi_printf("%s_tag: %02x\r\n", name, buf.tag);
  print_hex_string(name, buf.p, buf.len);
  return 0;
}

int print_mbedtls_asn1_buf(char *name, mbedtls_asn1_buf buf){
  sbi_printf("%s_tag: %02x\r\n", name, buf.tag);
  print_hex_string(name, buf.p, buf.len);
  print_hex_string(name, buf.p_arr, buf.len);
  return 0;
}

int print_mbedtls_asn1_named_data(char *name, mbedtls_asn1_named_data buf){
  char tmp[128] = {0};
  sbi_sprintf(tmp, "%s_oid", name);
  print_mbedtls_asn1_buf(tmp, buf.oid);
  sbi_sprintf(tmp, "%s_val", name);
  print_mbedtls_asn1_buf(name, buf.val);
  sbi_printf("%s_next: %p\r\n", name, buf.next);
  return 0;
}

int print_mbedtls_x509_time(char *name, mbedtls_x509_time tm){
  sbi_printf("%s:\r\n- year=%d, mon=%d, day=%d\r\n- hour=%d, min=%d, sec=%d\r\n",
    name, tm.year, tm.mon, tm.day, tm.hour, tm.min, tm.sec);
  return 0;
}

int print_mbedtls_pk_context(char *name, mbedtls_pk_context pk){
  char tmp[128] = {0};
  sbi_sprintf(tmp, "%s - pk", name);
  sbi_printf("%s: %s\r\n", name, pk.pk_info->name);
  print_hex_string(tmp, pk.pk_ctx.pub_key, PUBLIC_KEY_SIZE);
  return 0;
}

int print_mbedtls_x509_cert(char *name, mbedtls_x509_crt crt){
  sbi_printf("%s:\r\n", name);
  print_mbedtls_asn1_buf_no_arr("raw", crt.raw);
  print_mbedtls_asn1_buf_no_arr("tbs", crt.tbs);
  sbi_printf("\r\n");
  sbi_printf("version: %d\r\n", crt.version);
  print_mbedtls_asn1_buf_no_arr("serial", crt.serial);
  print_mbedtls_asn1_buf_no_arr("sig_oid", crt.sig_oid);
  sbi_printf("\r\n");
  print_mbedtls_asn1_buf_no_arr("issuer_raw", crt.issuer_raw);
  print_mbedtls_asn1_buf_no_arr("subject_raw", crt.subject_raw);
  sbi_printf("\r\n");
  print_mbedtls_asn1_named_data("issuer", crt.issuer_arr[0]);
  print_mbedtls_asn1_named_data("subject", crt.subject_arr[0]);
  sbi_printf("ne_issue_arr: %d\r\n", crt.ne_issue_arr);
  sbi_printf("ne_subje_arr: %d\r\n", crt.ne_subje_arr);
  sbi_printf("\r\n");
  print_mbedtls_x509_time("valid_from", crt.valid_from);
  print_mbedtls_x509_time("valid_to", crt.valid_to);
  sbi_printf("\r\n");
  print_mbedtls_asn1_buf("pk_raw", crt.pk_raw);
  print_mbedtls_pk_context("pk", crt.pk);
  sbi_printf("\r\n");
  print_mbedtls_asn1_buf("issuer_id", crt.issuer_id);
  print_mbedtls_asn1_buf("subject_id", crt.subject_id);
  print_mbedtls_asn1_buf("v3_ext", crt.v3_ext);
  sbi_printf("\r\n");
  print_mbedtls_asn1_buf("hash", crt.hash);
  sbi_printf("\r\n");
  sbi_printf("ca_istrue: %d\r\n", crt.ca_istrue);
  sbi_printf("max_pathlen: %d\r\n", crt.max_pathlen);
  sbi_printf("\r\n");
  print_mbedtls_asn1_buf("sig", crt.sig);
  sbi_printf("sig_md: %d\r\n", crt.sig_md);
  sbi_printf("sig_pk: %d\r\n", crt.sig_pk);
  sbi_printf("\r\n\r\n");
  return 0;
}

/****************************
 *
 * Enclave utility functions
 * Internal use by SBI calls
 *
 ****************************/

/* Internal function containing the core of the context switching
 * code to the enclave.
 *
 * Used by resume_enclave and run_enclave.
 *
 * Expects that eid has already been valided, and it is OK to run this enclave
*/
static inline void context_switch_to_enclave(struct sbi_trap_regs* regs,
                                                enclave_id eid,
                                                int load_parameters){
  /* save host context */
  swap_prev_state(&enclaves[eid].threads[0], regs, 1);
  swap_prev_mepc(&enclaves[eid].threads[0], regs, regs->mepc);
  swap_prev_mstatus(&enclaves[eid].threads[0], regs, regs->mstatus);

  uintptr_t interrupts = 0;
  csr_write(mideleg, interrupts);

  if(load_parameters) {
    // passing parameters for a first run
    csr_write(sepc, (uintptr_t) enclaves[eid].params.user_entry);
    regs->mepc = (uintptr_t) enclaves[eid].params.runtime_entry - 4; // regs->mepc will be +4 before sbi_ecall_handler return
    regs->mstatus = (1 << MSTATUS_MPP_SHIFT);
    // $a1: (PA) DRAM base,
    regs->a1 = (uintptr_t) enclaves[eid].pa_params.dram_base;
    // $a2: (PA) DRAM size,
    regs->a2 = (uintptr_t) enclaves[eid].pa_params.dram_size;
    // $a3: (PA) kernel location,
    regs->a3 = (uintptr_t) enclaves[eid].pa_params.runtime_base;
    // $a4: (PA) user location,
    regs->a4 = (uintptr_t) enclaves[eid].pa_params.user_base;
    // $a5: (PA) freemem location,
    regs->a5 = (uintptr_t) enclaves[eid].pa_params.free_base;
    // $a6: (VA) utm base,
    regs->a6 = (uintptr_t) enclaves[eid].params.untrusted_ptr;
    // $a7: (size_t) utm size
    regs->a7 = (uintptr_t) enclaves[eid].params.untrusted_size;

    // switch to the initial enclave page table
    csr_write(satp, enclaves[eid].encl_satp);
  }

  switch_vector_enclave();

  // set PMP
  osm_pmp_set(PMP_NO_PERM);
  int memid;
  for(memid=0; memid < ENCLAVE_REGIONS_MAX; memid++) {
    if(enclaves[eid].regions[memid].type != REGION_INVALID) {
      pmp_set_keystone(enclaves[eid].regions[memid].pmp_rid, PMP_ALL_PERM);
    }
  }

  // Setup any platform specific defenses
  platform_switch_to_enclave(&(enclaves[eid]));
  cpu_enter_enclave_context(eid);
}

static inline void context_switch_to_host(struct sbi_trap_regs *regs,
    enclave_id eid,
    int return_on_resume){

  // set PMP
  int memid;
  for(memid=0; memid < ENCLAVE_REGIONS_MAX; memid++) {
    if(enclaves[eid].regions[memid].type != REGION_INVALID) {
      pmp_set_keystone(enclaves[eid].regions[memid].pmp_rid, PMP_NO_PERM);
    }
  }
  osm_pmp_set(PMP_ALL_PERM);

  uintptr_t interrupts = MIP_SSIP | MIP_STIP | MIP_SEIP;
  csr_write(mideleg, interrupts);

  /* restore host context */
  swap_prev_state(&enclaves[eid].threads[0], regs, return_on_resume);
  swap_prev_mepc(&enclaves[eid].threads[0], regs, regs->mepc);
  swap_prev_mstatus(&enclaves[eid].threads[0], regs, regs->mstatus);

  switch_vector_host();

  uintptr_t pending = csr_read(mip);

  if (pending & MIP_MTIP) {
    csr_clear(mip, MIP_MTIP);
    csr_set(mip, MIP_STIP);
  }
  if (pending & MIP_MSIP) {
    csr_clear(mip, MIP_MSIP);
    csr_set(mip, MIP_SSIP);
  }
  if (pending & MIP_MEIP) {
    csr_clear(mip, MIP_MEIP);
    csr_set(mip, MIP_SEIP);
  }

  // Reconfigure platform specific defenses
  platform_switch_from_enclave(&(enclaves[eid]));

  cpu_exit_enclave_context();

  return;
}


// TODO: This function is externally used.
// refactoring needed
/*
 * Init all metadata as needed for keeping track of enclaves
 * Called once by the SM on startup
 */
void enclave_init_metadata(){
  enclave_id eid;
  int i=0;

  /* Assumes eids are incrementing values, which they are for now */
  for(eid=0; eid < ENCL_MAX; eid++){
    enclaves[eid].state = INVALID;

    // Clear out regions
    for(i=0; i < ENCLAVE_REGIONS_MAX; i++){
      enclaves[eid].regions[i].type = REGION_INVALID;
    }
    /* Fire all platform specific init for each enclave */
    platform_init_enclave(&(enclaves[eid]));
  }

}

static unsigned long clean_enclave_memory(uintptr_t utbase, uintptr_t utsize)
{

  // This function is quite temporary. See issue #38

  // Zero out the untrusted memory region, since it may be in
  // indeterminate state.
  sbi_memset((void*)utbase, 0, utsize);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static unsigned long encl_alloc_eid(enclave_id* _eid)
{
  enclave_id eid;

  spin_lock(&encl_lock);

  for(eid=0; eid<ENCL_MAX; eid++)
  {
    if(enclaves[eid].state == INVALID){
      break;
    }
  }
  if(eid != ENCL_MAX)
    enclaves[eid].state = ALLOCATED;

  spin_unlock(&encl_lock);

  if(eid != ENCL_MAX){
    *_eid = eid;
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  }
  else{
    return SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
  }
}

static unsigned long encl_free_eid(enclave_id eid)
{
  spin_lock(&encl_lock);
  enclaves[eid].state = INVALID;
  spin_unlock(&encl_lock);
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

int get_enclave_region_index(enclave_id eid, enum enclave_region_type type){
  size_t i;
  for(i = 0;i < ENCLAVE_REGIONS_MAX; i++){
    if(enclaves[eid].regions[i].type == type){
      return i;
    }
  }
  // No such region for this enclave
  return -1;
}

uintptr_t get_enclave_region_size(enclave_id eid, int memid)
{
  if (0 <= memid && memid < ENCLAVE_REGIONS_MAX)
    return pmp_region_get_size(enclaves[eid].regions[memid].pmp_rid);

  return 0;
}

uintptr_t get_enclave_region_base(enclave_id eid, int memid)
{
  if (0 <= memid && memid < ENCLAVE_REGIONS_MAX)
    return pmp_region_get_addr(enclaves[eid].regions[memid].pmp_rid);

  return 0;
}

// TODO: This function is externally used by sm-sbi.c.
// Change it to be internal (remove from the enclave.h and make static)
/* Internal function enforcing a copy source is from the untrusted world.
 * Does NOT do verification of dest, assumes caller knows what that is.
 * Dest should be inside the SM memory.
 */
unsigned long copy_enclave_create_args(uintptr_t src, struct keystone_sbi_create* dest){

  int region_overlap = copy_to_sm(dest, src, sizeof(struct keystone_sbi_create));

  if (region_overlap)
    return SBI_ERR_SM_ENCLAVE_REGION_OVERLAPS;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

/* copies data from enclave, source must be inside EPM */
static unsigned long copy_enclave_data(struct enclave* enclave,
                                          void* dest, uintptr_t source, size_t size) {

  int illegal = copy_to_sm(dest, source, size);

  if(illegal)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

/* copies data into enclave, destination must be inside EPM */
static unsigned long copy_enclave_report(struct enclave* enclave,
                                            uintptr_t dest, struct report* source) {

  int illegal = copy_from_sm(dest, source, sizeof(struct report));

  if(illegal)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long copy_enclave_report_runtime_attestation_into_sm(uintptr_t src, struct runtime_report* dest) {
  if (copy_to_sm(dest, src, sizeof(struct runtime_report)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long copy_enclave_report_runtime_attestation_from_sm(struct runtime_report* src, uintptr_t dest) {
  if (copy_from_sm(dest, src, sizeof(struct runtime_report)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long copy_nonce_into_sm(uintptr_t src, unsigned char* dest) {
  if (copy_to_sm(dest, src, 32 * sizeof(unsigned char)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long copy_cert_from_sm(unsigned char *src_cert, uintptr_t dest_cert, int size) {
  if (copy_from_sm(dest_cert, src_cert, size))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long copy_cert_lengths_from_sm(int *src_lengths_array, uintptr_t dest_lengths_array, int size) {
  if (copy_from_sm(dest_lengths_array, src_lengths_array, size))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static int is_create_args_valid(struct keystone_sbi_create* args)
{
  uintptr_t epm_start, epm_end;

  /* printm("[create args info]: \r\n\tepm_addr: %llx\r\n\tepmsize: %llx\r\n\tutm_addr: %llx\r\n\tutmsize: %llx\r\n\truntime_addr: %llx\r\n\tuser_addr: %llx\r\n\tfree_addr: %llx\r\n", */
  /*        args->epm_region.paddr, */
  /*        args->epm_region.size, */
  /*        args->utm_region.paddr, */
  /*        args->utm_region.size, */
  /*        args->runtime_paddr, */
  /*        args->user_paddr, */
  /*        args->free_paddr); */

  // check if physical addresses are valid
  if (args->epm_region.size <= 0)
    return 0;

  // check if overflow
  if (args->epm_region.paddr >=
      args->epm_region.paddr + args->epm_region.size)
    return 0;
  if (args->utm_region.paddr >=
      args->utm_region.paddr + args->utm_region.size)
    return 0;

  epm_start = args->epm_region.paddr;
  epm_end = args->epm_region.paddr + args->epm_region.size;

  // check if physical addresses are in the range
  if (args->runtime_paddr < epm_start ||
      args->runtime_paddr >= epm_end)
    return 0;
  if (args->user_paddr < epm_start ||
      args->user_paddr >= epm_end)
    return 0;
  if (args->free_paddr < epm_start ||
      args->free_paddr > epm_end)
      // note: free_paddr == epm_end if there's no free memory
    return 0;

  // check the order of physical addresses
  if (args->runtime_paddr > args->user_paddr)
    return 0;
  if (args->user_paddr > args->free_paddr)
    return 0;

  return 1;
}

/*********************************
 *
 * Enclave SBI functions
 * These are exposed to S-mode via the sm-sbi interface
 *
 *********************************/


/* This handles creation of a new enclave, based on arguments provided
 * by the untrusted host.
 *
 * This may fail if: it cannot allocate PMP regions, EIDs, etc
 */
unsigned long create_enclave(unsigned long *eidptr, struct keystone_sbi_create create_args)
{
  /* EPM and UTM parameters */
  uintptr_t base = create_args.epm_region.paddr;
  size_t size = create_args.epm_region.size;
  uintptr_t utbase = create_args.utm_region.paddr;
  size_t utsize = create_args.utm_region.size;

  enclave_id eid;
  unsigned long ret;
  int region, shared_region;
  //u64 init_value;
  //u64 final_value;
  //init_value = sbi_timer_value();

  /* Runtime parameters */
  if(!is_create_args_valid(&create_args)){
    #if SM_DICE_DEBUG
    sbi_printf("[create_enclave - 1] ret: ILLEGAL_ARGUMENT\r\n");
    #endif
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }

  /* set va params */
  struct runtime_va_params_t params = create_args.params;
  struct runtime_pa_params pa_params;
  pa_params.dram_base = base;
  pa_params.dram_size = size;
  pa_params.runtime_base = create_args.runtime_paddr;
  pa_params.user_base = create_args.user_paddr;
  pa_params.free_base = create_args.free_paddr;


  // allocate eid
  ret = SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
  if (encl_alloc_eid(&eid) != SBI_ERR_SM_ENCLAVE_SUCCESS){
    #if SM_DICE_DEBUG
    sbi_printf("[create_enclave - goto 1] ret: NO_FREE_RESOURCE\r\n");
    #endif
    goto error;
  }


  // create a PMP region bound to the enclave
  ret = SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
  if(pmp_region_init_atomic(base, size, PMP_PRI_ANY, &region, 0)){
    #if SM_DICE_DEBUG
    sbi_printf("[create_enclave - goto 2] ret: PMP_FAILURE\r\n");
    #endif
    goto free_encl_idx;
  }

  // create PMP region for shared memory
  if(pmp_region_init_atomic(utbase, utsize, PMP_PRI_BOTTOM, &shared_region, 0)){
    #if SM_DICE_DEBUG
    sbi_printf("[create_enclave - goto 3] ret: NO_FREE_RESOURCE\r\n");
    #endif
    goto free_region;
  }

  // set pmp registers for private region (not shared)
  if(pmp_set_global(region, PMP_NO_PERM)){
    #if SM_DICE_DEBUG
    sbi_printf("[create_enclave - goto 4] ret: NO_FREE_RESOURCE\r\n");
    #endif
    goto free_shared_region;
  }

  // cleanup some memory regions for sanity See issue #38
  clean_enclave_memory(utbase, utsize);


  // initialize enclave metadata
  enclaves[eid].eid = eid;

  enclaves[eid].regions[0].pmp_rid = region;
  enclaves[eid].regions[0].type = REGION_EPM;
  enclaves[eid].regions[1].pmp_rid = shared_region;
  enclaves[eid].regions[1].type = REGION_UTM;
#if __riscv_xlen == 32
  enclaves[eid].encl_satp = ((base >> RISCV_PGSHIFT) | (SATP_MODE_SV32 << HGATP_MODE_SHIFT));
#else
  enclaves[eid].encl_satp = ((base >> RISCV_PGSHIFT) | (SATP_MODE_SV39 << HGATP_MODE_SHIFT));
#endif
  enclaves[eid].n_thread = 0;
  enclaves[eid].params = params;
  enclaves[eid].pa_params = pa_params;

  /* Init enclave state (regs etc) */
  clean_state(&enclaves[eid].threads[0]);

  /* Platform create happens as the last thing before hashing/etc since
     it may modify the enclave struct */
  ret = platform_create_enclave(&enclaves[eid]);
  if (ret){
    #if SM_DICE_DEBUG
    sbi_printf("[create_enclave - goto 5] ret: %lu\r\n", ret);
    #endif
    goto unset_region;
  }

  /* Validate memory, prepare hash and signature for attestation */
  spin_lock(&encl_lock); // FIXME This should error for second enter.

  ret = validate_and_hash_enclave(&enclaves[eid]);

  // The CDI of the sm is combined with the measure of the enclaves to obtain the CDI of the enclave
  sha3_init(&hash_ctx_to_use, 64);
  sha3_update(&hash_ctx_to_use, CDI, 64);
  sha3_update(&hash_ctx_to_use, enclaves[eid].hash, 64);
  sha3_final(enclaves[eid].CDI, &hash_ctx_to_use);

  unsigned char seed_for_local_att_key[32];

  for(int i = 0; i < 32; i ++)
    seed_for_local_att_key[i] = enclaves[eid].CDI[i];

  // The CDI of the enclave is used to create the local attestation keys of the enclave
  ed25519_create_keypair(enclaves[eid].local_att_pub, enclaves[eid].local_att_priv, seed_for_local_att_key);

  // Associated to the local attestation keys of the enclaves, a new 509 cert is created 
  mbedtls_x509write_crt_init(&enclaves[eid].crt_local_att);

  // Setting the name of the issuer of the cert
  ret = mbedtls_x509write_crt_set_issuer_name_mod(&enclaves[eid].crt_local_att, "O=Security Monitor");
  if (ret != 0)
  {
    #if SM_DICE_DEBUG
    sbi_printf("[create_enclave - 2] DICE\r\n");
    #endif
    return 0;
  }

  // Setting the name of the subject of the cert
  ret = mbedtls_x509write_crt_set_subject_name_mod(&enclaves[eid].crt_local_att, "O=Enclave" );
  if (ret != 0)
  {
    #if SM_DICE_DEBUG
    sbi_printf("[create_enclave - 3] DICE\r\n");
    #endif
    return 0;
  }

  // pk context used to embed the keys of the security monitor
  mbedtls_pk_context subj_key;
  mbedtls_pk_init(&subj_key);

  // pk context used to embed the keys of the embedded CA
  mbedtls_pk_context issu_key;
  mbedtls_pk_init(&issu_key);


  // The keys of the embedded CA are used to sign the different certs associated to the local attestation keys of the different enclaves  
  ret = mbedtls_pk_parse_public_key(&issu_key, ECASM_priv, 64, 1);
  if (ret != 0)
  {
    #if SM_DICE_DEBUG
    sbi_printf("[create_enclave - 4] DICE\r\n");
    #endif
    return 0;
  }
  ret = mbedtls_pk_parse_public_key(&issu_key, ECASM_pk, 32, 0);
  if (ret != 0)
  {
    #if SM_DICE_DEBUG
    sbi_printf("[create_enclave - 5] DICE\r\n");
    #endif
    return 0;
  }

  // Parsing the public key of the enclave that will be inserted in its certificate 
  ret = mbedtls_pk_parse_public_key(&subj_key, enclaves[eid].local_att_pub, 32, 0);
  if (ret != 0)
  {
    #if SM_DICE_DEBUG
    sbi_printf("[create_enclave - 6] DICE\r\n");
    #endif
    return 0;
  }

  // Variable  used to specify the serial of the cert
  unsigned char serial[] = {0x0, 0x0, 0x0};
  serial[2] = eid;

  // The public key of the enclave is inserted in the structure
  mbedtls_x509write_crt_set_subject_key(&enclaves[eid].crt_local_att, &subj_key);

  // The private key of the embedded CA is used later to sign the cert
  mbedtls_x509write_crt_set_issuer_key(&enclaves[eid].crt_local_att, &issu_key);

  // The serial of the cert is setted
  mbedtls_x509write_crt_set_serial_raw(&enclaves[eid].crt_local_att, serial, 3);

  // The algoithm used to do the hash for the signature is specified
  mbedtls_x509write_crt_set_md_alg(&enclaves[eid].crt_local_att, KEYSTONE_SHA3);

  // The validity of the crt is specified
  ret = mbedtls_x509write_crt_set_validity(&enclaves[eid].crt_local_att, "20230101000000", "20240101000000");
  if (ret != 0)
  {
    #if SM_DICE_DEBUG
    sbi_printf("[create_enclave - 7] DICE\r\n");
    #endif
    return 0;
  }
  const char oid_ext[] = {0xff, 0x20, 0xff};
  //const char oid_ext2[] = {0x55, 0x1d, 0x13};
  //unsigned char max_path[] = {0x0A};
  unsigned char app[64];
  my_memcpy(app, enclaves[eid].hash, 64);

  // The measure of the enclave is inserted as extension in the cert created for his local attestation keys
  mbedtls_x509write_crt_set_extension(&enclaves[eid].crt_local_att, oid_ext, 3, 0, app, 64);
  //mbedtls_x509write_crt_set_extension(&enclaves[eid].crt_local_att, oid_ext2, 3, 1, max_path, 2);
  //mbedtls_x509write_crt_set_basic_constraints(&enclaves[eid].crt_local_att, 1, 10);

  unsigned char cert_der[1024];
  int effe_len_cert_der = 0;
  size_t len_cert_der_tot = 1024;
  ret = mbedtls_x509write_crt_der(&enclaves[eid].crt_local_att, cert_der, len_cert_der_tot, NULL, NULL);
  if (ret != 0)
  {
    #if SM_DICE_DEBUG
    sbi_printf("[create_enclave - err 1] ret: %lu\r\n", ret);
    #endif
    effe_len_cert_der = ret;
    ret = 0;
  }
  unsigned char *cert_real = cert_der;
  int dif  = 0;
  dif= 1024-effe_len_cert_der;
  cert_real += dif;

  // The der format of the cert and its length are stored in the specific variables of the enclave structure
  enclaves[eid].crt_local_att_der_length = effe_len_cert_der;
  my_memcpy(enclaves[eid].crt_local_att_der, cert_real, effe_len_cert_der);

  // The number of the keypair associated to the created enclave that are not the local attestation keys is set to 0
  enclaves[eid].n_keypair = 0;

  /*
  enclaves[eid].SM_attes_key = uff_cert_sm;
  for(int i = 0; i <32; i ++)
    enclaves[eid].dev_root_key_pub[i] = dev_public_key[i];
  */

  /* The enclave is fresh if it has been validated and hashed but not run yet. */
  if (ret){
    #if SM_DICE_DEBUG
    sbi_printf("[create_enclave - goto 6] ret: %lu\r\n", ret);
    #endif
    goto unlock;
  }

  enclaves[eid].state = FRESH;
  //final_value = sbi_timer_value();
  //sbi_printf("Ticks needed for the creation of the enclave: %ld\r\n", final_value - init_value);

  /* EIDs are unsigned int in size, copy via simple copy */
  *eidptr = eid;
 
  spin_unlock(&encl_lock);
  #if SM_DICE_DEBUG
  sbi_printf("[create_enclave - 8] ret: SUCCESS\r\n");
  #endif
  return SBI_ERR_SM_ENCLAVE_SUCCESS;

unlock:
  spin_unlock(&encl_lock);
// free_platform:
  platform_destroy_enclave(&enclaves[eid]);
unset_region:
  pmp_unset_global(region);
free_shared_region:
  pmp_region_free_atomic(shared_region);
free_region:
  pmp_region_free_atomic(region);
free_encl_idx:
  encl_free_eid(eid);
error:
  #if SM_DICE_DEBUG
  sbi_printf("[create_enclave - E] ret: %lu\r\n", ret);
  #endif
  return ret;
}

/*
 * Fully destroys an enclave
 * Deallocates EID, clears epm, etc
 * Fails only if the enclave isn't running.
 */
unsigned long destroy_enclave(enclave_id eid)
{
  int destroyable;

  spin_lock(&encl_lock);
  destroyable = (ENCLAVE_EXISTS(eid)
                 && enclaves[eid].state <= STOPPED);
  /* update the enclave state first so that
   * no SM can run the enclave any longer */
  if(destroyable)
    enclaves[eid].state = DESTROYING;
  spin_unlock(&encl_lock);

  if(!destroyable)
    return SBI_ERR_SM_ENCLAVE_NOT_DESTROYABLE;


  // 0. Let the platform specifics do cleanup/modifications
  platform_destroy_enclave(&enclaves[eid]);


  // 1. clear all the data in the enclave pages
  // requires no lock (single runner)
  int i;
  void* base;
  size_t size;
  region_id rid;
  for(i = 0; i < ENCLAVE_REGIONS_MAX; i++){
    if(enclaves[eid].regions[i].type == REGION_INVALID ||
       enclaves[eid].regions[i].type == REGION_UTM)
      continue;
    //1.a Clear all pages
    rid = enclaves[eid].regions[i].pmp_rid;
    base = (void*) pmp_region_get_addr(rid);
    size = (size_t) pmp_region_get_size(rid);
    sbi_memset((void*) base, 0, size);

    //1.b free pmp region
    pmp_unset_global(rid);
    pmp_region_free_atomic(rid);
  }

  // 2. free pmp region for UTM
  rid = get_enclave_region_index(eid, REGION_UTM);
  if(rid != -1)
    pmp_region_free_atomic(enclaves[eid].regions[rid].pmp_rid);

  enclaves[eid].encl_satp = 0;
  enclaves[eid].n_thread = 0;
  enclaves[eid].params = (struct runtime_va_params_t) {0};
  enclaves[eid].pa_params = (struct runtime_pa_params) {0};
  for(i=0; i < ENCLAVE_REGIONS_MAX; i++){
    enclaves[eid].regions[i].type = REGION_INVALID;
  }

  // 3. release eid
  encl_free_eid(eid);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}


unsigned long run_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
  int runable;

  spin_lock(&encl_lock);
  runable = (ENCLAVE_EXISTS(eid)
            && enclaves[eid].state == FRESH);
  if(runable) {
    enclaves[eid].state = RUNNING;
    enclaves[eid].n_thread++;
  }
  spin_unlock(&encl_lock);

  if(!runable) {
    return SBI_ERR_SM_ENCLAVE_NOT_FRESH;
  }

  // Enclave is OK to run, context switch to it
  context_switch_to_enclave(regs, eid, 1);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long exit_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
  int exitable;

  spin_lock(&encl_lock);
  exitable = enclaves[eid].state == RUNNING;
  if (exitable) {
    enclaves[eid].n_thread--;
    if(enclaves[eid].n_thread == 0)
      enclaves[eid].state = STOPPED;
  }
  spin_unlock(&encl_lock);

  if(!exitable)
    return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;

  context_switch_to_host(regs, eid, 0);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long stop_enclave(struct sbi_trap_regs *regs, uint64_t request, enclave_id eid)
{
  int stoppable;

  spin_lock(&encl_lock);

  stoppable = enclaves[eid].state == RUNNING;
  if (stoppable) {
    // Keep track of the remapped root page table, assigned at Eyrie Boot.
    // This operation must be performed AFTER the enclave is launched, in
    // order to retrieve the new satp value
    if (cpu_is_enclave_context())
      enclaves[eid].encl_satp_remap = csr_read(satp);

    //sbi_printf("[SM] SATP: %lu\n", csr_read(satp));

    enclaves[eid].n_thread--;
    if(enclaves[eid].n_thread == 0)
      enclaves[eid].state = STOPPED;
  }
  spin_unlock(&encl_lock);

  if(!stoppable)
    return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;

  context_switch_to_host(regs, eid, request == STOP_EDGE_CALL_HOST);

  switch(request) {
    case(STOP_TIMER_INTERRUPT):
      return SBI_ERR_SM_ENCLAVE_INTERRUPTED;
    case(STOP_EDGE_CALL_HOST):
      return SBI_ERR_SM_ENCLAVE_EDGE_CALL_HOST;
    default:
      return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
  }
}

unsigned long resume_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
  int resumable;

  spin_lock(&encl_lock);
  resumable = (ENCLAVE_EXISTS(eid)
               && (enclaves[eid].state == RUNNING || enclaves[eid].state == STOPPED)
               && enclaves[eid].n_thread < MAX_ENCL_THREADS);

  if(!resumable) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NOT_RESUMABLE;
  } else {
    enclaves[eid].n_thread++;
    enclaves[eid].state = RUNNING;
  }
  spin_unlock(&encl_lock);

  // Enclave is OK to resume, context switch to it
  context_switch_to_enclave(regs, eid, 0);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long attest_enclave(uintptr_t report_ptr, uintptr_t data, uintptr_t size, enclave_id eid)
{
  int attestable;
  struct report report;
  int ret;

  if (size > ATTEST_DATA_MAXLEN)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  spin_lock(&encl_lock);
  attestable = (ENCLAVE_EXISTS(eid)
                && (enclaves[eid].state >= FRESH));

  if(!attestable) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_INITIALIZED;
    goto err_unlock;
  }

  /* copy data to be signed */
  ret = copy_enclave_data(&enclaves[eid], report.enclave.data,
      data, size);
  report.enclave.data_len = size;

  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto err_unlock;
  }

  spin_unlock(&encl_lock); // Don't need to wait while signing, which might take some time

  sbi_memcpy(report.dev_public_key, dev_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(report.sm.hash, sm_hash, MDSIZE);
  sbi_memcpy(report.sm.public_key, sm_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(report.sm.signature, sm_signature, SIGNATURE_SIZE);
  sbi_memcpy(report.enclave.hash, enclaves[eid].hash, MDSIZE);
  sm_sign(report.enclave.signature,
      &report.enclave,
      sizeof(struct enclave_report)
      - SIGNATURE_SIZE
      - ATTEST_DATA_MAXLEN + size);

  spin_lock(&encl_lock);

  /* copy report to the enclave */
  ret = copy_enclave_report(&enclaves[eid],
      report_ptr,
      &report);

  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto err_unlock;
  }

  ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

err_unlock:
  spin_unlock(&encl_lock);
  return ret;
}

unsigned long get_sealing_key(uintptr_t sealing_key, uintptr_t key_ident,
                                 size_t key_ident_size, enclave_id eid)
{
  struct sealing_key *key_struct = (struct sealing_key *)sealing_key;
  int ret;

  /* derive key */
  ret = sm_derive_sealing_key((unsigned char *)key_struct->key,
                              (const unsigned char *)key_ident, key_ident_size,
                              (const unsigned char *)enclaves[eid].hash);
  if (ret)
    return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;

  /* sign derived key */
  sm_sign((void *)key_struct->signature, (void *)key_struct->key,
          SEALING_KEY_SIZE);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long verify_integrity_rt_eapp(int eid) { return 0; }

unsigned long create_keypair(enclave_id eid, unsigned char* pk, int seed_enc){

  unsigned char seed[PRIVATE_KEY_SIZE];
  unsigned char pk_app[PUBLIC_KEY_SIZE];
  unsigned char sk_app[PRIVATE_KEY_SIZE];

  unsigned char app[65];
  //cambiare nome indice con seed

  // The new keypair is obtained adding at the end of the CDI of the enclave an index, provided by the enclave itself
  my_memcpy(app, enclaves[eid].CDI, 64);
  app[64] = seed_enc + '0';

  #if SM_DICE_DEBUG
  sbi_printf("SM - Create keypair: %d\r\n", seed_enc);
  #endif

  sha3_ctx_t ctx_hash;

  // The hash function is used to provide the seed for the keys generation
  sha3_init(&ctx_hash, 64);
  sha3_update(&ctx_hash, app, 65);
  sha3_final(seed, &ctx_hash);

  ed25519_create_keypair(pk_app, sk_app, seed);

  // The new keypair is stored in the relatives arrays
  for(int i = 0; i < PUBLIC_KEY_SIZE; i ++)
    enclaves[eid].pk_array[enclaves[eid].n_keypair][i] = pk_app[i];
  for(int i = 0; i < PRIVATE_KEY_SIZE; i ++)
    enclaves[eid].sk_array[enclaves[eid].n_keypair][i] = sk_app[i];

  // The first keypair that is asked to be created is the Local Device Keys, that is inserted in the relative variables
  if(enclaves[eid].n_keypair == 0){
    my_memcpy(enclaves[eid].sk_ldev, sk_app, PRIVATE_KEY_SIZE );
    my_memcpy(enclaves[eid].pk_ldev, pk_app, PUBLIC_KEY_SIZE);
  }

  enclaves[eid].n_keypair +=1;

  #if SM_DICE_DEBUG
  print_hex_string("SM - Create keypair", pk_app, PUBLIC_KEY_SIZE);
  #endif

  my_memcpy(pk, pk_app, PUBLIC_KEY_SIZE);

  // The location in memoty of the private key of the keypair created is clean
  my_memset(sk_app, 0, 64);

  return 0;
}

void get_cert(enclave_id eid, unsigned char* dest_cert_buffer, int *dest_size, int cert_num) {
  if (cert_num > 3)
    sbi_printf("[SM] Invalid ID %d (0: man, 1: root, 2: SM, 3: lak)", cert_num);

  switch (cert_num) {
    case 0:
      my_memcpy(dest_cert_buffer, cert_man, length_cert_man);
      *dest_size = length_cert_man;
      break;
    case 1:
      my_memcpy(dest_cert_buffer, cert_root, length_cert_root);
      *dest_size = length_cert_root;
      break;
    case 2:
      my_memcpy(dest_cert_buffer, cert_sm, length_cert);
      *dest_size = length_cert;
      break;
    case 3:
      my_memcpy(dest_cert_buffer, enclaves[eid].crt_local_att_der, enclaves[eid].crt_local_att_der_length);
      *dest_size = enclaves[eid].crt_local_att_der_length;
      break;
    default:
      break;
  }
}

unsigned long get_cert_chain(enclave_id eid, unsigned char** certs, int* sizes){

  #if PRINT_CERTS
  unsigned char test_sm[512], test_root[512], test_man[512];
  my_memcpy(test_sm, cert_sm, length_cert);
  my_memcpy(test_root, cert_root, length_cert_root);
  my_memcpy(test_man, cert_man, length_cert_man);
  int ret;
  mbedtls_x509_crt cert_sm_p, cert_root_p, cert_man_p;
  mbedtls_x509_crt_init(&cert_sm_p);
  mbedtls_x509_crt_init(&cert_root_p);
  mbedtls_x509_crt_init(&cert_man_p);
  ret = mbedtls_x509_crt_parse_der(&cert_sm_p, test_sm, length_cert);
  sbi_printf("SM - cert_sm - ret: %d\r\n", ret);
  ret = mbedtls_x509_crt_parse_der(&cert_root_p, test_root, length_cert_root);
  sbi_printf("SM - cert_root - ret: %d\r\n", ret);
  ret = mbedtls_x509_crt_parse_der(&cert_man_p, test_man, length_cert_man);
  sbi_printf("SM - cert_man - ret: %d\r\n", ret);
  sbi_printf("\r\n");
  print_mbedtls_x509_cert("SM - cert_sm", cert_sm_p);
  print_mbedtls_x509_cert("SM - cert_root", cert_root_p);
  print_mbedtls_x509_cert("SM - cert_man", cert_man_p);
  #endif

  //my_memcpy(certs[0], enclaves[eid].crt_local_att_der, enclaves[eid].crt_local_att_der_length);
  //sizes[0] = enclaves[eid].crt_local_att_der_length;
  #if SM_DICE_DEBUG
  print_hex_string("SM - Get certs - cert_sm", cert_sm, length_cert);
  #endif

  // Providing the X509 cert in der format of the ECA and its length
  my_memcpy(certs[0], cert_sm, length_cert);
  sbi_printf(", now copying len cert 1...");
  sizes[0] = length_cert;

  #if SM_DICE_DEBUG
  print_hex_string("SM - Get certs - cert_root", cert_root, length_cert_root);
  #endif

  // Providing the X509 cert in der format of the Device Root Key and its length
  my_memcpy(certs[1], cert_root, length_cert_root);
  sizes[1] = length_cert_root;

  #if SM_DICE_DEBUG
  print_hex_string("SM - Get certs - cert_man", cert_man, length_cert_man);
  #endif

  // Providing the X509 cert in der format of the manufacturer key and its length
  my_memcpy(certs[2], cert_man, length_cert_man);
  sizes[2] = length_cert_man;

  return 0;
}

unsigned long do_crypto_op(enclave_id eid, int flag, unsigned char* data, int data_len, unsigned char* out_data, int* len_out_data, unsigned char* pk){

  sha3_ctx_t ctx_hash;
  unsigned char fin_hash[64];
  unsigned char sign[64];
  int pos = -1;

  #if SM_DICE_DEBUG
  sbi_printf("SM - Do crypto op: flag=%d\r\n", flag);
  print_hex_string("SM - Do crypto op - pk", pk, PUBLIC_KEY_SIZE);
  #endif

  switch (flag){
    // Sign of TCI|pk_lDev with the private key of the attestation keypair of the enclave.
    // The sign is placed in out_data. The attestation pk can be obtained calling the get_chain_cert method
    case 1:
      sha3_init(&ctx_hash, 64);
      sha3_update(&ctx_hash, data, data_len);
      sha3_update(&ctx_hash, enclaves[eid].hash, 64);
      sha3_update(&ctx_hash, enclaves[eid].pk_ldev, 32);
      sha3_final(fin_hash, &ctx_hash);

      #if SM_DICE_DEBUG
      print_hex_string("fin_hash", fin_hash, 64);
      #endif

      //ed25519_sign(sign, fin_hash, 64, enclaves[eid].local_att_pub, enclaves[eid].local_att_priv);
      ed25519_sign(sign, fin_hash, 64, ECASM_pk, ECASM_priv);
      #if SM_DICE_DEBUG
      print_hex_string("SM - Do crypto op", sign, 64);
      #endif
      my_memcpy(out_data, sign, 64);
      *len_out_data = 64;
      return 0;
    break;
    /*
    case 2:
      // Sign of generic data with a specific private key.
      // The pk associated with the private key that has to be used is passed by the enclave
      #if SM_DICE_DEBUG
      sbi_printf("comparing: %d\r\n", my_memcmp(enclaves[eid].pk_array[0], pk, 32));
      #endif
      // Finding the private key associated to the public key passed
      for(int i = 0;  i < enclaves[eid].n_keypair; i ++)
        if(my_memcmp(enclaves[eid].pk_array[i], pk, 32) == 0){
          pos = i;
          break;
        }
      #if SM_DICE_DEBUG
      sbi_printf("SM - Do crypto op - pos: %d\r\n", pos);
      #endif
      if (pos == -1)
        return -1;
      // Making the signature
      sha3_init(&ctx_hash, 64);
      sha3_update(&ctx_hash, data, data_len);
      sha3_final(fin_hash, &ctx_hash);
      #if SM_DICE_DEBUG
      print_hex_string("SM - Do crypto op - encl.pk", enclaves[eid].pk_array[pos], 32);
      print_hex_string("SM - Do crypto op - encl.sk", enclaves[eid].sk_array[pos], 64);
      print_hex_string("SM - Do crypto op - hash", fin_hash, 64);
      #endif
      ed25519_sign(sign, fin_hash, 64, enclaves[eid].pk_array[pos], enclaves[eid].sk_array[pos]);
     
      #if SM_DICE_DEBUG
      print_hex_string("SM - Do crypto op", sign, 64);
      #endif
      // Providing the signature
      my_memcpy(out_data, sign, 64);
      *len_out_data = 64;
      return 0;
    break;
  */
    case 2:
      // Sign of generic data with a specific private key.
      // In this case the enclave provides directly the hash of the data that have to be signed

      // Finding the private key associated to the public key passed
      for(int i = 0;  i < enclaves[eid].n_keypair; i ++)
        if(my_memcmp(enclaves[eid].pk_array[i], pk, 32) == 0){
          pos = i;
          break;
        }
      if (pos == -1)
        return -1;

      ed25519_sign(sign, data, data_len, enclaves[eid].pk_array[pos], enclaves[eid].sk_array[pos]);

      // Providing the signature
      my_memcpy(out_data, sign, 64);
      *len_out_data = 64;
      return 0;
    break;

    default:
      return -1;
    break;
  }
  return 0;
}

unsigned long attest_integrity_at_runtime(
    struct runtime_report *report,
    unsigned char *nonce,
    enclave_id eid) {
  int ret = 0;
  spin_lock(&encl_lock);

  if(!(ENCLAVE_EXISTS(eid) && (enclaves[eid].state == STOPPED || enclaves[eid].state == RUNNING))) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_EXECUTION_TIME;
    goto err_unlock;
  }

  /* compute hash of the read only enclave pages
     and save it in the associated enclave struct */
  compute_eapp_hash(&enclaves[eid], 1);

  sbi_memcpy(report->dev_public_key, dev_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(report->sm.hash, sm_hash, MDSIZE);
  sbi_memcpy(report->sm.public_key, sm_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(report->sm.signature, sm_signature, SIGNATURE_SIZE);
  sbi_memcpy(report->enclave.hash, enclaves[eid].hash_rt_eapp_actual, MDSIZE);
  sbi_memcpy(report->enclave.nonce, (byte *) nonce, NONCE_LEN);
  ed25519_sign(report->enclave.signature, report->enclave.hash, MDSIZE, enclaves[eid].local_att_pub, enclaves[eid].local_att_priv);
  //sm_sign(report->enclave.signature, report->enclave.hash, MDSIZE);

  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto err_unlock;
  }

  ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

err_unlock:
  spin_unlock(&encl_lock);
  
  return ret;
}
