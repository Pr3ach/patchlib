#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

void reachable(void);
void unreachable(void);

int main(void)
{
  reachable();

  getchar();

  return 0;
}

void reachable(void)
{
  puts("[-] Reachable function");
}

void unreachable(void)
{
  puts("[*] Unreachable function");
}
