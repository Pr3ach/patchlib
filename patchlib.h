#if !defined(H_PATCHLIB)

#define H_PATCHLIB

// simple offset patch
int patch_raw(int8_t *fileName, uint32_t offset, uint8_t *bytes, int count);

// load suspended target with CreateProcess() to perform patch
int patch_load(char *target, void *addr, void *bytes, int count);

// open a process, suspend its main thread and apply patch
int patch_open(int8_t *name, void *addr, void *bytes,int count);

int SetPrivilege(LPCTSTR lpszPrivilege); // get a handle on any process
int get_TID(int PID); 								   // return thread id of process id
int get_PID(int8_t *name);						   // return PID of process name

#endif // H_PATCHLIB

