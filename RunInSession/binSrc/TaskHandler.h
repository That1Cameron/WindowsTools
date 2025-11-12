#pragma once

#define _WIN32_DCOM

#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <comdef.h>
#include <wincred.h>
#include <libloaderapi.h>
#include <strsafe.h>
#include <sstream>
#include <fstream>
#include <mutex>
#include <taskschd.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "ole32.lib")

bool registerTask(DWORD id, std::string path);
void initLogFile(std::wstring);
void logMsg(const std::wstring&);
void closeLogfile();
std::wofstream globalLog;