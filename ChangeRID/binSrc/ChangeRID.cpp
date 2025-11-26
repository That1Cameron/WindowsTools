// ChangeRID.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <filesystem>
#include <Windows.h>
#include <Wtsapi32.h>
#include <TCHAR.H>
#include <fstream>
#include "TaskHandler.h"

bool checkIfSystem(u_int rid) {
    // check if system
    TCHAR username[256 + 1];
    DWORD username_len = 256 + 1;
    GetUserName(username, &username_len);

    // if not ran as system schedule a task to re-run this as system
    if (_tcscmp(username, _T("SYSTEM")) != 0) {
        std::wcout << "Ran as:" << username << " not system, registering scheduled task to run this as system" << "\n";
        bool res = registerTask(rid);

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

void reportError(const std::wstring& msg) {
    DWORD err = GetLastError();
    logMsg(msg + L", error: " + std::to_wstring(err) + L"\n");
}



// resolves an RID from a username then modifies that users RID
bool resolveRID(std::wstring uname) {
    // check if running as system, if isnt make it so
    /*if (!checkIfSystem(rid)) {
        return false;
    }*/

    logMsg(L"getting SAM keys...");
    // Computer\HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users

    LONG lResult;
    HKEY hKey;
    lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SAM\\SAM\\Domains\\Account\\Users\\Names"), 0, KEY_ALL_ACCESS, &hKey);

    if (lResult != ERROR_SUCCESS){
        reportError(L"Could not open key");
        return false;
    }

    DWORD index = 0;
    wchar_t subKeyName[256];
    DWORD subKeyNameLen;
    bool found = false;
    // search through users to find their RID (if uname was provided)
    while (lResult != ERROR_NO_MORE_ITEMS && !found) {
        subKeyNameLen = 256;

        lResult = RegEnumKeyExW(hKey, index, subKeyName, &subKeyNameLen, nullptr, nullptr, nullptr, nullptr);

        if (lResult != ERROR_SUCCESS) {
            reportError(L"RegEnumKeyEx failed");
            return false;
        }
        
        // check uname
        if (uname != subKeyName) {
            index++;
            continue;
        }
        // get rid from uname

        // use rid value as target
        //changeRID();

    }
}


bool changeRID(u_int rid) {
    // check if running as system, if isnt make it so
    if (!checkIfSystem(rid)) {
        return false;
    }

    logMsg(L"getting SAM keys...");
    // Computer\HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users

    LONG lResult;
    HKEY hKey;
    lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SAM\\SAM\\Domains\\Account\\Users"), 0, KEY_ALL_ACCESS, &hKey);

    if (lResult != ERROR_SUCCESS) {
        reportError(L"Could not open key");
        return false;
    }

    DWORD index = 0;
    wchar_t subKeyName[256];
    DWORD subKeyNameLen;
    bool found = false;
    // search through users to find their RID (if uname was provided)
    while (lResult != ERROR_NO_MORE_ITEMS && !found) {
        subKeyNameLen = 256;

        lResult = RegEnumKeyExW(hKey, index, subKeyName, &subKeyNameLen, nullptr, nullptr, nullptr, nullptr);

        if (lResult != ERROR_SUCCESS) {
            reportError(L"RegEnumKeyEx failed");
            return false;
        }

        // find rid subkey

        // modify F value with new RID


    }
}

void showHelp() {
    std::cout << "Usage: ChangeRID -u <User Name>\n\n"
        << "Options:\n"
        << "  -h               Show this help message\n"
        << "  -r <RID>         (Required or -u) Specify the RID in decimal of the user to modify\n"
        << "  -u <username>    (Required or -r) Specify the name of the user to modify\n"
        << "\n";
}


int main(int argc, char* argv[]){
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

        }else if (arg == "-r") {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                args["-r"] = argv[++i];

            }
            else {
                std::cerr << "Error: Missing value for -r\n";
                return 1;

            }
        }
        else if (arg == "-u") {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                args["-u"] = argv[++i];

            }
            else {
                std::cerr << "Error: Missing value for -u\n";
                return 1;

            }
        }
        else {
            std::cerr << "Unknown option: " << arg << "\n";
            showHelp();
            return 1;

        }
    }

    if (!args.count("-u") && !args.count("-r") || args.count("-u") && args.count("-r")) {
        std::cerr << "Error: select either a username (-u) or an RID (-r) to modify\n\n";
        showHelp();
        return 1;
    }

    // modify all users?
    if (args.count("-a")) {
        std::cout << "" << "\n";
    }

    if (args.count("-r")) {

        DWORD rid = std::atoi(args["-r"].c_str());
        if (rid > 1000) {
            std::cout << "Invalid user RID (users have RIDs above 1000)" << args["-id"] << "\n";
            return 1;
        }

        // start main program logic
        initLogFile(L"ChangeRID");
        logMsg(L"Starting log...");
        logMsg(L"Attempting to modify RID");
        if (!changeRID(rid)) {
            std::cout << "ChangeRID failed";
            closeLogfile();
            return 1;
        }
    }

    closeLogfile();
    return 0;
}
