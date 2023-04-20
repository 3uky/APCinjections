#pragma once

#include <string>

class IALWinApi
{
public:
	virtual bool IsProcessRunning(std::wstring_view ProcessName) = 0;
	virtual void KillProcess(std::wstring_view ProcessName) = 0;
};