//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "eapp_utils.h"
#include "string.h"
#include "edge_call.h"
#include <syscall.h>

#define OCALL_PRINT_STRING 1
#define OCALL_VERIFY_INTEGRITY 2

unsigned long ocall_print_string(char* string);

int main(){
  int i;
  int temp[1024*10];
  //ocall_print_string("Hello World");
  for (i = 0; i < 5; i++) {
      verify_integrity_rt_eapp();
      temp[i] = i;
      temp[i]++;
  }

  EAPP_RETURN(0);
}

/****************************************/

unsigned long ocall_print_string(char* string){
  unsigned long retval;
  ocall(OCALL_PRINT_STRING, string, strlen(string)+1, &retval ,sizeof(unsigned long));
  return retval;
}
