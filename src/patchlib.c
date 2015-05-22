/*
 * This file is part of patchlib.
 * Copyright (C) 2015, Preacher
 * All rights reserved.
 *
 * patchlib is a free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * patchlib is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with patchlib.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _WIN32_WINNT 0x0501
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <conio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "patchlib.h"

int patch_raw(int8_t *file_name, long int offset, void *patch, SIZE_T patch_sz){
	FILE *fd = NULL;
	SIZE_T file_sz = 0;
	uint32_t i = 0;

	if(!(fd = fopen(file_name, "rb+")))
		return -1;

	fseek(fd, 0, SEEK_END);
	file_sz = ftell(fd);

	if(patch_sz+(SIZE_T)offset > file_sz)
		return -1;

	fseek(fd, offset, SEEK_SET);

	for(i; i < (uint32_t)patch_sz; i++){
		if(fwrite(patch+i, 1, 1, fd) != 1){
			fclose(fd);
			return -1;
		}
	}

	fclose(fd);

	return 0;
}

int patch_load(int8_t *path, void *addr, void *patch, SIZE_T patch_sz){
	PROCESS_INFORMATION pi = {0};
	STARTUPINFO si = {0};
	MEMORY_BASIC_INFORMATION mbi = {0};
	SIZE_T actually_written = 0;
	DWORD old_prot = 0;

	set_privilege(SE_DEBUG_NAME);

	if(!CreateProcess(path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
		return -1;

	if(!VirtualQueryEx(pi.hProcess, addr, &mbi, sizeof(MEMORY_BASIC_INFORMATION))){
		ResumeThread(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return -1;
	}

	/* 0x40 == rwx */
	if(mbi.Protect != 0x40){
		if(!VirtualProtectEx(pi.hProcess, addr, patch_sz, 0x40, &old_prot)){
			ResumeThread(pi.hThread);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			return -1;
		}
	}

	if(!WriteProcessMemory(pi.hProcess, addr, patch, patch_sz, &actually_written)){
		ResumeThread(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return -1;
	}

	if(actually_written != patch_sz){
		ResumeThread(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return -1;
	}

	/* eventually restore mem protection */
	if(mbi.Protect != 0x40){
		if(!VirtualProtectEx(pi.hProcess, addr, patch_sz, mbi.Protect, &old_prot)){
			ResumeThread(pi.hThread);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			return -1;
		}
	}

	if(!FlushInstructionCache(pi.hProcess, addr, patch_sz)){
		ResumeThread(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return -1;
	}

	if(ResumeThread(pi.hThread) == -1){
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return -1;
	}

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return 0;
}

int patch_open(int8_t *pname, void *addr, void *patch, SIZE_T patch_sz){
	HANDLE process = NULL;
	HANDLE thread = NULL;
	SIZE_T actually_written = 0;
	DWORD old_prot = 0;
	MEMORY_BASIC_INFORMATION mbi = {0};
	int pid = 0;

	if((pid = pname2pid(pname)) < 0)
		return -1;

	set_privilege(SE_DEBUG_NAME);

	if(!(process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)))
		return -1;

	if(!(thread = OpenThread(THREAD_ALL_ACCESS, FALSE, pid2tid(pid)))){
		CloseHandle(process);
		return -1;
	}

	if(SuspendThread(thread) == -1){
		CloseHandle(thread);
		CloseHandle(process);
		return -1;
	}

	if(!VirtualQueryEx(process, addr, &mbi, sizeof(MEMORY_BASIC_INFORMATION))){
		ResumeThread(thread);
		CloseHandle(process);
		CloseHandle(thread);
		return -1;
	}

	if(mbi.Protect != 0x40){
		if(!VirtualProtectEx(process, addr, patch_sz, 0x40, &old_prot)){
			ResumeThread(thread);
			CloseHandle(process);
			CloseHandle(thread);
			return -1;
		}
	}

	if(!WriteProcessMemory(process, addr, patch, patch_sz, &actually_written)){
		ResumeThread(thread);
		CloseHandle(process);
		CloseHandle(thread);
		return -1;
	}

	if(actually_written != patch_sz){
		ResumeThread(thread);
		CloseHandle(process);
		CloseHandle(thread);
		return -1;
	}
	/* eventually restore mem protection */
	if(mbi.Protect != 0x40){
		if(!VirtualProtectEx(process, addr, patch_sz, mbi.Protect, &old_prot)){
			ResumeThread(thread);
			CloseHandle(process);
			CloseHandle(thread);
			return -1;
		}
	}

	if(!FlushInstructionCache(process, addr, patch_sz)){
		ResumeThread(thread);
		CloseHandle(process);
		CloseHandle(thread);
		return -1;
	}

	if(ResumeThread(thread) == -1){
		TerminateProcess(process, 0);
		CloseHandle(process);
		CloseHandle(thread);
		return -1;
	}

	return 0;
}

unsigned long int patch_raw_replace(int8_t *file_name, uint8_t *s, uint8_t *r, SIZE_T s_sz, SIZE_T r_sz, int global){
	FILE *fd = NULL;
	SIZE_T file_sz = 0;
	long int pos = 0;
	uint8_t buf[4096] = {0};
	unsigned long int ret = 0;

	if(s_sz <= 0 || s_sz > 4095)
		return 0;

	if(r_sz <= 0 || r_sz > 4095)
		return 0;

	if(!(fd = fopen(file_name, "rb+")))
		return 0;

	fseek(fd, 0, SEEK_END);
	file_sz = ftell(fd);

	for(pos = 0; (pos + (long int)r_sz) <= file_sz; pos++){
		memset(&buf[0], 0, 4096);

		if(fseek(fd, pos, SEEK_SET)){
			fclose(fd);
			return 0;
		}

		if(fread(&buf[0], 1, s_sz, fd) != s_sz){
			fclose(fd);
			return 0;
		}

		/* search sequence found */
		if(!arraycmp(buf, s, s_sz)){
			ret++;
			if(!global){
				if(!patch_raw(file_name, pos, r, r_sz)){
					fclose(fd);
					return 0;
				}

				fclose(fd);
				return ret;
			}

			if(!patch_raw(file_name, pos, r, r_sz)){
				fclose(fd);
				return 0;
			}
		}
	}

	fclose(fd);

	return ret;
}

unsigned long int patch_load_replace(int8_t *path, uint8_t *s, uint8_t *r, SIZE_T s_sz, SIZE_T r_sz, int global){
	PROCESS_INFORMATION pi = {0};
	STARTUPINFO si = {0};
	SIZE_T actually_written = 0;
	SIZE_T actually_read = 0;
	DWORD old_prot = 0;
	process_info_t *pinfo = NULL;
	void *pos = NULL;
	uint8_t buf[4096] = {0};
	unsigned long int ret = 0;
	MEMORY_BASIC_INFORMATION mbi = {0};

	if(s_sz <= 0 || s_sz > 4095)
		return 0;

	if(r_sz <= 0 || r_sz > 4095)
		return 0;

	set_privilege(SE_DEBUG_NAME);

	if(!CreateProcess(path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
		return 0;

	pinfo = malloc(sizeof(process_info_t));
	memset(pinfo, 0, sizeof(process_info_t));

	if(get_process_info(pi.hProcess, pinfo) < 0){
		free(pinfo);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return 0;
	}

	for(pos = (void *)pinfo->base_addr; pos+r_sz <= (pinfo->base_addr + (unsigned long long int)pinfo->image_sz); pos++){
		memset(&mbi, 0, sizeof(MEMORY_BASIC_INFORMATION));
		memset(&buf[0], 0, 4096);
		actually_read = 0;
		actually_written = 0;

		VirtualQueryEx(pi.hProcess, (LPVOID)pos, &mbi, sizeof(MEMORY_BASIC_INFORMATION));

		/* 0x04 == rw */
		if(mbi.Protect < 0x04)
			if(!VirtualProtectEx(pi.hProcess, (LPVOID)pos, (SIZE_T)MAX(r_sz, s_sz), (DWORD)0x04, (PDWORD)&old_prot))
				continue;

		if(!ReadProcessMemory(pi.hProcess, (LPVOID)pos, &buf[0], s_sz, &actually_read)){
			if(mbi.Protect != 0x04)
				VirtualProtectEx(pi.hProcess, (LPVOID)pos, (SIZE_T)MAX(r_sz, s_sz), mbi.Protect, (PDWORD)&old_prot);
			free(pinfo);
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			return 0;
		}

		if(s_sz != actually_read){
			if(mbi.Protect != 0x04)
				VirtualProtectEx(pi.hProcess, (LPVOID)pos, (SIZE_T)MAX(r_sz, s_sz), mbi.Protect, (PDWORD)&old_prot);
			continue;
		}

		if(!arraycmp(buf, s, s_sz)){
			if(!global){
				if(!WriteProcessMemory(pi.hProcess, (LPVOID)pos, r, r_sz, &actually_written)){
					if(mbi.Protect != 0x04)
						VirtualProtectEx(pi.hProcess, (LPVOID)pos, (SIZE_T)MAX(r_sz, s_sz), mbi.Protect, (PDWORD)&old_prot);
					free(pinfo);
					CloseHandle(pi.hThread);
					CloseHandle(pi.hProcess);
					return 0;
				}

				if(mbi.Protect != 0x04)
					VirtualProtectEx(pi.hProcess, (LPVOID)pos, (SIZE_T)MAX(r_sz, s_sz), mbi.Protect, (PDWORD)&old_prot);

				if(actually_written != r_sz){
					free(pinfo);
					CloseHandle(pi.hThread);
					CloseHandle(pi.hProcess);
					return 0;
				}	

				FlushInstructionCache(pi.hProcess, pos, r_sz);
				free(pinfo);
				CloseHandle(pi.hThread);
				CloseHandle(pi.hProcess);
				return 1;
			}

			if(!WriteProcessMemory(pi.hProcess, (LPVOID)pos, r, r_sz, &actually_written)){
				if(mbi.Protect != 0x04)
					VirtualProtectEx(pi.hProcess, (LPVOID)pos, (SIZE_T)MAX(r_sz, s_sz), mbi.Protect, (PDWORD)&old_prot);
				free(pinfo);
				CloseHandle(pi.hThread);
				CloseHandle(pi.hProcess);
				return ret;
			}

			if(mbi.Protect != 0x04)
				VirtualProtectEx(pi.hProcess, (LPVOID)pos, (SIZE_T)MAX(r_sz, s_sz), mbi.Protect, (PDWORD)&old_prot);

			if(actually_written != r_sz){
				free(pinfo);
				CloseHandle(pi.hThread);
				CloseHandle(pi.hProcess);
				return ret;
			}

			ret++;
			FlushInstructionCache(pi.hProcess, pos, r_sz);
		}
	}

	free(pinfo);
	return ret;
}

unsigned long int patch_open_replace(int8_t *pname, uint8_t *s, uint8_t *r, SIZE_T s_sz, SIZE_T r_sz, int global){
	HANDLE process = NULL;
	SIZE_T actually_written = 0;
	SIZE_T actually_read = 0;
	DWORD old_prot = 0;
	process_info_t *pinfo = NULL;
	void *pos = NULL;
	uint8_t buf[4096] = {0};
	unsigned long int ret = 0;
	MEMORY_BASIC_INFORMATION mbi = {0};
	int pid = 0;

	if(s_sz <= 0 || s_sz > 4095)
		return 0;

	if(r_sz <= 0 || r_sz > 4095)
		return 0;

	set_privilege(SE_DEBUG_NAME);

	if((pid = pname2pid(pname)) < 0)
		return 0;

	if(!(process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)))
		return 0;

	pinfo = malloc(sizeof(process_info_t));
	memset(pinfo, 0, sizeof(process_info_t));

	if(get_process_info(process, pinfo) < 0){
		free(pinfo);
		CloseHandle(process);
		return 0;
	}

	for(pos = (void *)pinfo->base_addr; pos+r_sz <= (pinfo->base_addr + (unsigned long long int)pinfo->image_sz); pos++){
		memset(&mbi, 0, sizeof(MEMORY_BASIC_INFORMATION));
		memset(&buf[0], 0, 4096);
		actually_read = 0;
		actually_written = 0;

		VirtualQueryEx(process, (LPVOID)pos, &mbi, sizeof(MEMORY_BASIC_INFORMATION));

		/* 0x04 == rw */
		if(mbi.Protect < 0x04)
			if(!VirtualProtectEx(process, (LPVOID)pos, (SIZE_T)MAX(r_sz, s_sz), (DWORD)0x04, (PDWORD)&old_prot))
				continue;

		if(!ReadProcessMemory(process, (LPVOID)pos, &buf[0], s_sz, &actually_read)){
			if(mbi.Protect != 0x04)
				VirtualProtectEx(process, (LPVOID)pos, (SIZE_T)MAX(r_sz, s_sz), mbi.Protect, (PDWORD)&old_prot);
			free(pinfo);
			CloseHandle(process);
			return 0;
		}

		if(s_sz != actually_read){
			if(mbi.Protect != 0x04)
				VirtualProtectEx(process, (LPVOID)pos, (SIZE_T)MAX(r_sz, s_sz), mbi.Protect, (PDWORD)&old_prot);
			continue;
		}

		if(!arraycmp(buf, s, s_sz)){
			if(!global){
				if(!WriteProcessMemory(process, (LPVOID)pos, r, r_sz, &actually_written)){
					if(mbi.Protect != 0x04)
						VirtualProtectEx(process, (LPVOID)pos, (SIZE_T)MAX(r_sz, s_sz), mbi.Protect, (PDWORD)&old_prot);
					free(pinfo);
					CloseHandle(process);
					return 0;
				}

				if(mbi.Protect != 0x04)
					VirtualProtectEx(process, (LPVOID)pos, (SIZE_T)MAX(r_sz, s_sz), mbi.Protect, (PDWORD)&old_prot);

				if(actually_written != r_sz){
					free(pinfo);
					CloseHandle(process);
					return 0;
				}	

				FlushInstructionCache(process, pos, r_sz);
				free(pinfo);
				CloseHandle(process);
				return 1;
			}

			if(!WriteProcessMemory(process, (LPVOID)pos, r, r_sz, &actually_written)){
				if(mbi.Protect != 0x04)
					VirtualProtectEx(process, (LPVOID)pos, (SIZE_T)MAX(r_sz, s_sz), mbi.Protect, (PDWORD)&old_prot);
				free(pinfo);
				CloseHandle(process);
				return ret;
			}

			if(mbi.Protect != 0x04)
				VirtualProtectEx(process, (LPVOID)pos, (SIZE_T)MAX(r_sz, s_sz), mbi.Protect, (PDWORD)&old_prot);

			if(actually_written != r_sz){
				free(pinfo);
				CloseHandle(process);
				return ret;
			}

			ret++;
			FlushInstructionCache(process, pos, r_sz);
		}
	}

	free(pinfo);
	return ret;
}

int patch_backup(int8_t *src, int8_t *dest){
	FILE *fd_src = NULL;
	FILE *fd_dest = NULL;
	SIZE_T src_sz = 0;
	uint8_t *buf = NULL;

	/* File already exists ? */
	if(fd_dest = fopen(dest, "r")){
		fclose(fd_dest);
		return -1;
	}

	fd_dest = NULL;

	if(!(fd_dest = fopen(dest, "wb")))
		return -1;

	if(!(fd_src = fopen(src, "rb"))){
		fclose(fd_dest);
		return -1;
	}

	src_sz = get_file_size(fd_src);

	if(!src_sz){
		fclose(fd_dest);
		fclose(fd_src);
		return -1;
	}

	buf = malloc(src_sz * sizeof(uint8_t) + 1);

	if(fread(buf, 1, src_sz, fd_src) != src_sz){
		fclose(fd_dest);
		fclose(fd_src);
		remove(dest);
		return -1;
	}
	
	if(fwrite(buf, 1, src_sz, fd_dest) != src_sz){
		fclose(fd_dest);
		fclose(fd_src);
		remove(dest);
		return -1;
	}

	fclose(fd_dest);
	fclose(fd_src);
	free(buf);

	return 0;
}


int set_privilege(const char *privilege){
	TOKEN_PRIVILEGES tp;
	LUID luid;
	HANDLE token = NULL;

	if(!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &token)){
		if (GetLastError() == ERROR_NO_TOKEN){
			if (!ImpersonateSelf(SecurityImpersonation))
				return -1;

			if(!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &token))
				return -1;
		}

		else
			return -1;
	}

	if (!LookupPrivilegeValue(NULL, privilege, &luid))
		return -1;

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(token, 0, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
		return -1;

	CloseHandle(token);

	return -(GetLastError() == ERROR_NOT_ALL_ASSIGNED);
}

int pid2tid(int pid){
	HANDLE snap = NULL;
	THREADENTRY32 th32 = {0};

	th32.dwSize = sizeof(THREADENTRY32);

	if(!(snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)))
		return -1;

	if(!Thread32First(snap, &th32)){
		CloseHandle(snap);
		return -1;
	}

	do
	{
		if(th32.th32OwnerProcessID == pid){
			CloseHandle(snap);
			return th32.th32ThreadID;
		}
	}while(Thread32Next(snap, &th32));

	CloseHandle(snap);

	return -1;
}

int pname2pid(int8_t *pname){
	PROCESSENTRY32 pe32 = {0};
	HANDLE snap = NULL;

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if(!(snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)))
		return -1;

	if(!Process32First(snap, &pe32)){
		CloseHandle(snap);
		return -1;
	}

	do
	{
		if(!stricmp(pe32.szExeFile, pname)){
			CloseHandle(snap);
			return pe32.th32ProcessID;
		}
	}while(Process32Next(snap, &pe32));

	CloseHandle(snap);

	return -1;
}

int arraycmp(uint8_t *a1, uint8_t *a2, SIZE_T sz){
	uint32_t i = 0;

	for(i = 0; i < (uint32_t)sz; i++)
		if(a1[i] != a2[i])
			return -1;

	return 0;
}

int get_process_info(HANDLE process, process_info_t *pinfo){
	HMODULE mods[256] = {NULL};
	MODULEINFO modinfo = {0};
	DWORD needed = 0;

	if(!EnumProcessModulesEx(process, &mods[0], 256 * sizeof(HMODULE), &needed, LIST_MODULES_ALL))
		return -1;

	if(!mods[0])
		return -1;

	if(!GetModuleInformation(process, mods[0], &modinfo, sizeof(MODULEINFO)))
		return -1;

	pinfo->base_addr = (unsigned long long int)mods[0];
	pinfo->entry_point = ((unsigned long int)modinfo.EntryPoint - (unsigned long int)mods[0]);
	pinfo->image_sz = (unsigned long int)modinfo.SizeOfImage;

	return 0;
}

SIZE_T get_file_size(FILE *fd){
	long int pos = 0;
	SIZE_T sz = 0;

	if(!fd)
		return 0;

	pos = ftell(fd);

	fseek(fd, 0, SEEK_END);
	sz = ftell(fd);
	fseek(fd, pos, SEEK_SET);

	return sz;
}
