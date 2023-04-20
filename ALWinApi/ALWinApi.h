#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <optional>
#include <string>

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