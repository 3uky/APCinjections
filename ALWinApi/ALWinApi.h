#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <optional>
#include <string>
#include "IALWinApi.h"

class ALWinApi : IALWinApi
{
public:
	bool IsProcessRunning(std::wstring_view ProcessName) override;
	void KillProcess(std::wstring_view ProcessName) override;

private:
	std::optional<PROCESSENTRY32> GetProcessEntry(std::wstring_view ProcessName);
};