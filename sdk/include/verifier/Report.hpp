//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#pragma once

#include <iostream>
#include <string>
#include "Keys.hpp"
#include "common/sha3.h"
#include "ed25519/ed25519.h"
#include "verifier/json11.h"

#define NONCE_LEN 32

struct enclave_report_t {
  byte hash[MDSIZE];
  uint64_t data_len;
  byte data[ATTEST_DATA_MAXLEN];
  byte signature[SIGNATURE_SIZE];
};

/* runtime enclave attestation report */
struct enclave_runtime_report_t
{
  byte hash[MDSIZE];
  byte nonce[NONCE_LEN];
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

/* runtime attestation report */
struct runtime_report_t {
  struct enclave_runtime_report_t enclave;
  struct sm_report_t sm;
  byte dev_public_key[PUBLIC_KEY_SIZE];
};


class Report {
 private:
  struct report_t report;
  struct runtime_report_t runtime_report;

 public:
  std::string BytesToHex(byte* bytes, size_t len);
  void HexToBytes(byte* bytes, size_t len, std::string hexstr);
  void fromJson(std::string json);
  void fromBytes(byte* bin);
  std::string stringfy();
  void printJson();
  void printPretty();
  int verify(
      const byte* expected_enclave_hash, const byte* expected_sm_hash,
      const byte* dev_public_key);
  int checkSignaturesOnly(const byte* dev_public_key);
  void* getDataSection();
  size_t getDataSize();
  byte* getEnclaveHash();
  byte* getSmHash();

  /****** runtime attestation functions ******/
  void fromBytesRuntime(byte* bin);
  int verifyRuntimeReport(
    const byte* expected_enclave_runtime_hash,
    const byte* expected_sm_hash,
    const byte* dev_public_key,
    const byte* lak_pub);
  int checkSignaturesOnlyRuntime(const byte* dev_public_key, const byte* lak_pub);
  void* getNonceRuntime();
  byte* getEnclaveRuntimeHash();
};
