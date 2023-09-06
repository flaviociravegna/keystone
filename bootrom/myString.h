#ifndef __MYSTRING_H__
#define __MYSTRING_H__

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