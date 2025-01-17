//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#pragma once

#include <assert.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <functional>
#include <iostream>

#include <thread>
#include <mutex>
#include <condition_variable>

#include "./common.h"
extern "C" {
#include "common/sha3.h"
}
#include "ElfFile.hpp"
#include "Error.hpp"
#include "KeystoneDevice.hpp"
#include "Memory.hpp"
#include "Params.hpp"

namespace Keystone {

typedef std::function<void(void*)> OcallFunc;

class Enclave {
 private:
  Params params;
  ElfFile* runtimeFile;
  ElfFile* enclaveFile;
  Memory* pMemory;
  KeystoneDevice* pDevice;
  char hash[MDSIZE];
  hash_ctx_t hash_ctx;
  uintptr_t runtime_stk_sz;
  void* shared_buffer;
  size_t shared_buffer_size;
  runtime_report_t* runtime_attestation_report;

  OcallFunc oFuncDispatch;
  bool mapUntrusted(size_t size);
  bool allocPage(uintptr_t va, uintptr_t src, unsigned int mode);
  bool initStack(uintptr_t start, size_t size, bool is_rt);
  Error loadUntrusted();
  bool mapElf(ElfFile* file);
  Error loadElf(ElfFile* file);
  Error validate_and_hash_enclave(struct runtime_params_t args);

  bool initFiles(const char*, const char*);
  bool initDevice();
  bool prepareEnclave(uintptr_t alternatePhysAddr);
  bool initMemory();

 public:
  Enclave();
  ~Enclave();
  const char* getHash();
  void* getSharedBuffer();
  size_t getSharedBufferSize();
  runtime_report_t* getRuntimeAttestationReport();
  Error registerOcallDispatch(OcallFunc func);
  Error init(const char* filepath, const char* runtime, Params parameters);
  Error init(
      const char* eapppath, const char* runtimepath, Params _params,
      uintptr_t alternatePhysAddr);
  Error destroy();
  Error run(uintptr_t* ret = nullptr);
  Error run_with_runtime_attestation_support(uintptr_t* retval);
  void requestRuntimeAttestation(unsigned char *nonce, unsigned char *buffer_for_report, int *report_size);
  void requestCertChain(unsigned char *cert_sm, unsigned char *cert_root, unsigned char *cert_man, unsigned char *cert_lak, int *lengths);
};

uint64_t
calculate_required_pages(
    uint64_t eapp_sz, uint64_t eapp_stack_sz, uint64_t rt_sz,
    uint64_t rt_stack_sz);

}  // namespace Keystone
