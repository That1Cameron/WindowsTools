#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <filesystem>
#include <Windows.h>
#include <Wtsapi32.h>
#include <TCHAR.H>
#include <fstream>
#include <winbase.h>
#include <userenv.h>
#include "TaskHandler.h"

#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "userenv.lib")

#define ALL_SESSIONS -1


void showHelp() {
    std::cout << "Usage: RunInSession -path <executable_path> [options]\n\n"
        << "Options:\n"
        << "  -h               Show this help message\n"
        << "  -a               Run in all sessions\n"
        << "  -id <sessionID>      Specify a Session ID to run in\n"
        << "  -path <path>     (Required) Specify the path to the executable\n"
        << "\n";
}

// takes in a string and converts it to widestring with mbstowcs_s
std::wstring stringToWide(const std::string& str) {
    std::wstring wstr;
    size_t size;
    wstr.resize(str.length());
    mbstowcs_s(&size, &wstr[0], wstr.size() + 1, str.c_str(), str.size());
    return wstr;
}

void reportError(const std::wstring& msg) {
    DWORD err = GetLastError();
    logMsg(msg + L", error: " + std::to_wstring(err) + L"\n");
}

bool enablePrivileges(HANDLE token) {
    TOKEN_PRIVILEGES tp = {};
    LUID luid;

    // required to increase the mem quota assigned to a proc
    if (!LookupPrivilegeValue(NULL, SE_INCREASE_QUOTA_NAME, &luid)) { return false; }
    
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        reportError(L"Could not gain SE_INCREASE_QUOTA_NAME");
        return false; 
    }

    // required to assign the primary token of a proc
    if (!LookupPrivilegeValue(NULL, SE_ASSIGNPRIMARYTOKEN_NAME, &luid)) { return false; }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL)) { 
        reportError(L"Could not gain SE_ASSIGNPRIMARYTOKEN_NAME");
        return false;
    }

    return true;
}

// checks if this was ran as system
// takes the id and path to specify in the task scheduled to run as system
bool checkIfSystem(DWORD id, std::string path) {
    // check if system
    TCHAR username[256 + 1];
    DWORD username_len = 256 + 1;
    GetUserName(username, &username_len);

    // if not ran as system schedule a task to re-run this as system
    if (_tcscmp(username, _T("SYSTEM")) != 0) {
        std::wcout << "Ran as:" << username << " not system, registering scheduled task to run this as system" << "\n";
        bool res = registerTask(id, path);

        // print tasks log
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);
        std::wstring logPath = path;
        size_t pos = logPath.find_last_of(L"\\/");
        if (pos != std::wstring::npos)
            logPath = logPath.substr(0, pos + 1);
        logPath += L"registerTask.log";

        // output log
        std::wifstream log(logPath);
        std::wcout << log.rdbuf();
        //DeleteFile(L"C:\\Temp\\TaskSchedule.log");

        if (!res) {
            std::cout << "Error while registering task";
            return false;
        }
        
        std::cout << "registered as SYSTEM task" << "\n";
        return true;
    }

    // already system
    return true;
}

// main work segment
// takes a session id and path of executable to run
bool runInSession(DWORD id, std::string path) {

    // check if running as system, if isnt make it so
    if (!checkIfSystem(id, path)) {
        return false;
    }

    logMsg(L"enumerating sessions...");
    PWTS_SESSION_INFO sessions = NULL;
    DWORD sessionCount = NULL;
    //get session handles
    if (!WTSEnumerateSessions(NULL, 0, 1, &sessions, &sessionCount)) {
        reportError(L"Failed to enumerate sessions");
        return false; 
    }

    logMsg(L"Enumerated sessions");

    logMsg(L"iterating through found sessions...");
    bool processFound = false;
    for (DWORD i = 0; i < sessionCount; i++) {
        WTS_SESSION_INFO *session = &(sessions[i]);
        logMsg(L"Looking for session: " + std::to_wstring(id) + L"\n" + L"Currently on session: " + std::to_wstring(session->SessionId));

        // check if active, all flag, or just specificed session
        if (session->State == WTSActive && (id == ALL_SESSIONS || id == session->SessionId)) {
            processFound = true;
            logMsg(L"Found session:" + std::to_wstring(id));

            // get handle to user token
            HANDLE token = NULL;
            if (!WTSQueryUserToken(id, &token)) {
                reportError(L"Could not get token for session: " + std::to_wstring(id));
                WTSFreeMemory(sessions);
                return false;
            }
            
            logMsg(L"Got token: " + std::to_wstring((uintptr_t)token) + L" for session " + std::to_wstring(id));

            // copy token (functionize return newToken handle)
            HANDLE newToken = NULL;
            SECURITY_ATTRIBUTES sa = {};
            sa.nLength = sizeof(SECURITY_ATTRIBUTES);
            sa.bInheritHandle = FALSE;
            sa.lpSecurityDescriptor = NULL;
            DWORD dwAccess = TOKEN_ALL_ACCESS;
            if (!DuplicateTokenEx(token, dwAccess, &sa, SecurityImpersonation, TokenPrimary, &newToken)) {
                reportError(L"Could not duplicate token for user session: " + std::to_wstring(id));
                CloseHandle(token);
                WTSFreeMemory(sessions);
                return false;
            }
            
            logMsg(L"Duplicated token: " + std::to_wstring((uintptr_t)newToken) + L" for user with session " + std::to_wstring(id));

            if (!enablePrivileges(newToken)) {
                logMsg(L"Failed to enable required privileges on token");
                CloseHandle(newToken);
                CloseHandle(token);
                WTSFreeMemory(sessions);
                return false;
            }

            // use copy to make proc
            STARTUPINFOA si;
            si.cb = sizeof(si);
            si.lpDesktop = (LPSTR)"winsta0\\default";
            PROCESS_INFORMATION pi = {};
            DWORD dwFlags = CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT;
            logMsg(L"trying to create process...");
            if (!CreateProcessAsUserA(newToken, NULL, path.data(), NULL, NULL, false, dwFlags, NULL, NULL, &si, &pi)) {
                reportError(L"Could not create process in user session: " + std::to_wstring(id));
                CloseHandle(newToken);
                CloseHandle(token);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                WTSFreeMemory(sessions);
                return false;
            }
            logMsg(L"Created process");
            logMsg(L"Ran process: " + stringToWide(path) + L" in session " + std::to_wstring(id));

            // cleanup
            CloseHandle(newToken);
            CloseHandle(token);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
    // cleanup
    WTSFreeMemory(sessions);
    return processFound;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        showHelp();
        return 1;
    }

    // parse args
    std::unordered_map<std::string, std::string> args;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h") {
            showHelp();
            return 0;

        }else if (arg == "-a") {
            args["-a"] = "true";

        }else if (arg == "-id") {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                args["-id"] = argv[++i];

            }else {
                std::cerr << "Error: Missing value for -id\n";
                return 1;

            }
        }else if (arg == "-path") {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                args["-path"] = argv[++i];

            }else {
                std::cerr << "Error: Missing value for -path\n";
                return 1;

            }
        }else {
            std::cerr << "Unknown option: " << arg << "\n";
            showHelp();
            return 1;

        }
    }

    if (!args.count("-path")) {
        std::cerr << "Error: -path is required.\n\n";
        showHelp();
        return 1;
    }

    if (!args.count("-a") && !args.count("-id")) {
        std::cerr << "Error: select either all sessions (-a) or provide a specific session (-id)\n\n";
        showHelp();
        return 1;
    }

    // validate path
    std::string path = args["-path"];
    if (!std::filesystem::exists(path)) {
        std::cerr << "Error: The specified path does not exist. Provided path:" << path << "\n";
        return 1;
    }

    if (args.count("-a")) {
        std::cout << "Getting handle to all sessions" << "\n";
        runInSession(ALL_SESSIONS, path);
    }

    if (args.count("-id")) {
        
        DWORD id = std::atoi(args["-id"].c_str());
        if (id < 0 || id > 50 ) {
            std::cout << "Invalid Session ID" << args["-id"] << "\n";
            return 1;
        }

        // start main program logic
        initLogFile(L"RunInSession");
        logMsg(L"Starting log...");
        logMsg(L"Attempting to run in session(s)");
        if (!runInSession(id, path)) {
            std::cout << "RunInSession failed";
            closeLogfile();
            return 1;
        }
    }

    closeLogfile();
    return 0;
}
