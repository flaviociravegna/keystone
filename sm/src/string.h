
#ifndef __STRING_H__
#define __STRING_H__

#include <stdint.h>
#include <stddef.h>
unsigned int my_strlen(const char *s);
int my_strncmp( const char * s1, const char * s2, size_t n );
char* my_strncpy(char* destination, const char* source, size_t num);
void * my_memmove(void* dest, const void* src, unsigned int n);
int my_memcmp (const void *str1, const void *str2, size_t count);
void* my_memset(void* dest, int byte, size_t len);
void* my_memcpy(void* dest, const void* src, size_t len);

#endif

/*
#ifndef __STRING_H__
#define __STRING_H__


#include <stddef.h>
#include <stdint.h>

void* memcpy(void* dest, const void* src, size_t len)
{
  const char* s = src;
  char *d = dest;

  if ((((uintptr_t)dest | (uintptr_t)src) & (sizeof(uintptr_t)-1)) == 0) {
    while ((void*)d < (dest + len - (sizeof(uintptr_t)-1))) {
      *(uintptr_t*)d = *(const uintptr_t*)s;
      d += sizeof(uintptr_t);
      s += sizeof(uintptr_t);
    }
  }

  while (d < (char*)(dest + len))
    *d++ = *s++;

  return dest;
}

void* memset(void* dest, int byte, size_t len)
{
  if ((((uintptr_t)dest | len) & (sizeof(uintptr_t)-1)) == 0) {
    uintptr_t word = byte & 0xFF;
    word |= word << 8;
    word |= word << 16;
    word |= word << 16 << 16;

    uintptr_t *d = dest;
    while (d < (uintptr_t*)(dest + len))
      *d++ = word;
  } else {
    char *d = dest;
    while (d < (char*)(dest + len))
      *d++ = byte;
  }
  return dest;
}

#endif
*/
