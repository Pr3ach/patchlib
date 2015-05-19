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
#include "patchlib.h"

int patch_raw(int8_t *fileName, void offset, void *bytes, SIZE_T count)
{
	FILE *fd = NULL;
	SIZE_T fileSize = 0;
	int i = 0;

	if(!(fd = fopen(fileName,"rb+")))
		return 0;

	fseek(fd, 0, SEEK_END);
	fileSize = ftell(fd);

	if(count+(SIZE_T)offset > fileSize)
		return 0;

	fseek(fd, offset, SEEK_SET);

	for(i; i < count; i++)
	{
		if(!fwrite(bytes+i, 1, 1, fd))
		{
			fclose(fd);
			return 0;
		}
	}

	fclose(fd);

	return 1;
}

int patch_load(char *target, void *addr, void *bytes, SIZE_T count)
{
	PROCESS_INFORMATION pi = {0};
	STARTUPINFO si = {0};
	MEMORY_BASIC_INFORMATION mbi = {0};
	SIZE_T countWrite = 0;
	DWORD oldProtect = 0;

	SetPrivilege(SE_DEBUG_NAME);

	if(!CreateProcess(target, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
		return 0;

	if(!VirtualQueryEx(pi.hProcess, addr, &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		ResumeThread(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return 0;
	}

	/* 0x40 == rwx */
	if(mbi.Protect != 0x40)
	{
		if(!VirtualProtectEx(pi.hProcess, addr, count, 0x40, &oldProtect))
		{
			ResumeThread(pi.hThread);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			return 0;
		}
	}

	if(!WriteProcessMemory(pi.hProcess, addr, bytes, count, &countWrite))
	{
		ResumeThread(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return 0;
	}

	if(countWrite != count)
	{
		ResumeThread(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return 0;
	}

	/* eventually restore mem protection */
	if(mbi.Protect != 0x40)
	{
		if(!VirtualProtectEx(pi.hProcess, addr, count, mbi.Protect, &oldProtect))
		{
			ResumeThread(pi.hThread);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			return 0;
		}
	}

	if(!FlushInstructionCache(pi.hProcess, addr, count))
	{
		ResumeThread(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return 0;
	}

	if(ResumeThread(pi.hThread) == -1)
	{
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return 0;
	}

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return 1;
}

int patch_open(int8_t *name, void *addr, void *bytes, SIZE_T count)
{
	HANDLE hProc = NULL;
	HANDLE hThread = NULL;
	SIZE_T countWrite = 0;
	DWORD oldProtect = 0;
	MEMORY_BASIC_INFORMATION mbi = {0};
	int PID = 0;

	if(!(PID = get_PID(name)))
		return 0;

	SetPrivilege(SE_DEBUG_NAME);

	if(!(hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID)))
		return 0;

	if(!(hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, get_TID(PID))))
	{
		CloseHandle(hProc);
		return 0;
	}

	if(SuspendThread(hThread) == -1)
	{
		CloseHandle(hThread);
		CloseHandle(hProc);
		return 0;
	}

	if(!VirtualQueryEx(hProc, addr, &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		ResumeThread(hThread);
		CloseHandle(hProc);
		CloseHandle(hThread);
		return 0;
	}

	if(mbi.Protect != 0x40)
	{
		if(!VirtualProtectEx(hProc, addr, count, 0x40, &oldProtect))
		{
			ResumeThread(hThread);
			CloseHandle(hProc);
			CloseHandle(hThread);
			return 0;
		}
	}

	if(!WriteProcessMemory(hProc, addr, bytes, count, &countWrite))
	{
		ResumeThread(hThread);
		CloseHandle(hProc);
		CloseHandle(hThread);
		return 0;
	}

	if(countWrite != count)
	{
		ResumeThread(hThread);
		CloseHandle(hProc);
		CloseHandle(hThread);
		return 0;
	}
	/* eventually restore mem protection */
	if(mbi.Protect != 0x40)
	{
		if(!VirtualProtectEx(hProc, addr, count, mbi.Protect, &oldProtect))
		{
			ResumeThread(hThread);
			CloseHandle(hProc);
			CloseHandle(hThread);
			return 0;
		}
	}

	if(!FlushInstructionCache(hProc, addr, count))
	{
		ResumeThread(hThread);
		CloseHandle(hProc);
		CloseHandle(hThread);
		return 0;
	}

	if(ResumeThread(hThread) == -1)
	{
		TerminateProcess(hProc, 0);
		CloseHandle(hProc);
		CloseHandle(hThread);
		return 0;
	}

	return 1;
}

int SetPrivilege(LPCTSTR lpszPrivilege)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	HANDLE hToken = NULL;

	if(!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
	{
		if (GetLastError() == ERROR_NO_TOKEN)
		{
			if (!ImpersonateSelf(SecurityImpersonation))
				return 0;

			if(!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
				return 0;
		}

		else
			return 0;
	}

	if (!LookupPrivilegeValue(NULL,lpszPrivilege,&luid ))
		return 0;

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, 0, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES) NULL, (PDWORD) NULL))
		return 0;

	return !(GetLastError() == ERROR_NOT_ALL_ASSIGNED);
}

int get_TID(int PID)
{
	HANDLE hSnap = NULL;
	THREADENTRY32 th32 = {0};

	th32.dwSize = sizeof(THREADENTRY32);

	if(!(hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)))
		return 0;

	if(!Thread32First(hSnap, &th32))
	{
		CloseHandle(hSnap);
		return 0;
	}

	do
	{
		if(th32.th32OwnerProcessID == PID)
		{
			CloseHandle(hSnap);
			return th32.th32ThreadID;
		}
	}while(Thread32Next(hSnap, &th32));

	CloseHandle(hSnap);

	return 0;
}

int get_PID(int8_t *name)
{
	PROCESSENTRY32 pe32 = {0};
	HANDLE hSnap = NULL;

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if(!(hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)))
		return 0;

	if(!Process32First(hSnap, &pe32))
	{
		CloseHandle(hSnap);
		return 0;
	}

	do
	{
		if(!stricmp(pe32.szExeFile, name))
		{
			CloseHandle(hSnap);
			return pe32.th32ProcessID;
		}
	}while(Process32Next(hSnap, &pe32));

	CloseHandle(hSnap);

	return 0;
}
