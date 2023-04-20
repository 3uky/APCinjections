#include "ALWinApi.h"

#include <Windows.h>
#include <TlHelp32.h>
#include <optional>
#include <string>

bool ALWinApi::IsProcessRunning(std::wstring_view ProcessName)
{
	return GetProcessEntry(ProcessName).has_value() ? true : false;
}

void ALWinApi::KillProcess(std::wstring_view ProcessName)
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

std::optional<PROCESSENTRY32> ALWinApi::GetProcessEntry(std::wstring_view ProcessName)
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
