#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "../src/patchlib.h"

void test_raw(void);
void test_load(void);
void test_open(void);

int main(int argc, char *argv[])
{
  if(argc !=  2)
  {
    printf("Usage: %s <raw|load|open>\n", *argv);
    exit(-1);
  }

  if(!stricmp(argv[1], "raw"))
    test_raw();
  else if(!stricmp(argv[1], "load"))
    test_load();
  else if(!stricmp(argv[1], "open"))
    test_open();
  else
    printf("Usage: %s <raw|load|open>\n", *argv);

  return 0;
}

void test_raw(void)
{
  char *filename = "target.exe";
  uint32_t offset = 0x24f;
  uint8_t bytes[9] = {0x80, 0x70, 0x60, 0xff, 0x1, 0x00, 0x97};

  if(!patch_raw(filename, offset, bytes, 8))
      puts("Fail: patch_raw");
  else
      puts("Success: patch_raw");

  return;
}

void test_load(void)
{
  char *name = "target.exe";
  void *addr = (void *)0x4010f9;
  uint8_t bytes[3] = {0x67, 0x2};

  if(!patch_load(name, addr, bytes, 2))
      puts("Fail: patch_load");
  else
      puts("Success: patch_load");

  return;
}

void test_open(void)
{
  char *name = "target.exe";
  void *addr = (void *)0x4010f9;
  uint8_t bytes[3] = {0x67, 0x2};
  STARTUPINFO si;
  PROCESS_INFORMATION pi;

  if(!CreateProcess(name, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
  {
    puts("[!] Error starting the target");
    exit(-1);
  }

  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);

  if(!patch_open(name, addr, bytes, 2))
      puts("Fail: patch_open");
  else
      puts("Success: patch_open");

  return;
}
