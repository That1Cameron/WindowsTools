#include "TaskHandler.h"
/*
static std::wofstream globalTaskLog;
// set up log file
static void initLogFile() {
    if (!globalTaskLog.is_open()) {
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);

        std::wstring logPath = path;
        size_t pos = logPath.find_last_of(L"\\/");
        if (pos != std::wstring::npos)
            logPath = logPath.substr(0, pos + 1);
        logPath += L"registerTask.log";

        globalTaskLog.open(logPath, std::ios::app);
        if (globalTaskLog.is_open()) {
            globalTaskLog << L"\n---- New run ----\n";
        }
    }
}

// pritify log msg and write to file
static void logMsg(const std::wstring& msg) {
    if (!globalTaskLog.is_open()) { initLogFile(); }
    SYSTEMTIME st;
    GetLocalTime(&st);
    globalTaskLog << L"[" << st.wHour << L":" << st.wMinute << L":" << st.wSecond << L"] " << msg << std::endl;
}*/

void initLogFile(std::wstring name) {
    if (!globalLog.is_open()) {
        // get path to self
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);

        // clean path
        std::wstring logPath = path;
        size_t pos = logPath.find_last_of(L"\\/");
        if (pos != std::wstring::npos) { logPath = logPath.substr(0, pos + 1); }
        logPath +=(name+ L".log");

        // open file
        globalLog.open(logPath, std::ios::app);
        if (globalLog.is_open()) {
            globalLog << L"\n=== New run ===\n";
        }
    }
}

// close current logfile
void closeLogfile() {
    if (!globalLog.is_open()) {
        return;
    }
    globalLog.close();
    return;
}

// pritify log msg and write to file
void logMsg(const std::wstring& msg) {
    if (!globalLog.is_open()) { initLogFile(L"miscLog"); }
    SYSTEMTIME st;
    GetLocalTime(&st);
    globalLog << L"[" << st.wHour << L":" << st.wMinute << L":" << st.wSecond << L"] " << msg << std::endl;
}

// handle COM error printing
static void printComError(HRESULT hr, const char* msg) {
    _com_error err(hr);
    std::wstringstream strStream;
    strStream << L"COM-ERROR: " << msg << L" HRESULT=0x" << std::hex << hr << L" (" << err.ErrorMessage() << L")";
    logMsg(strStream.str());
}

// register self as SYSTEM task
// this is ugly and mostly setting up, calling, and checking COM taskmanager APIs
bool registerTask(DWORD id, std::string path) {
    initLogFile(L"registerTask");
    logMsg(L"Starting registerTask() log...");
    LPCWSTR taskName = L"RunInSession";
    TCHAR rawPath[MAX_PATH];
    TCHAR exePath[MAX_PATH];
    if (!GetModuleFileNameW(NULL, rawPath, MAX_PATH)) {
        DWORD err = GetLastError();
        logMsg(L"Failed to get host path, error:" + std::to_wstring(err) + L'\n');
    }

    // quote the path
    StringCbPrintf(exePath, MAX_PATH, TEXT("\"%s\""), rawPath);

    // a refresher when I look back at this
    //https://learn.microsoft.com/en-us/windows/win32/taskschd/registration-trigger-example--c---

    logMsg(L"CoInitializeEx...");
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        printComError(hr, "CoInitializeEx failed");
        return 1;
    }

    // create Task Service
    logMsg(L"CoCreateInstance...");
    ITaskService* pService = nullptr;
    hr = CoCreateInstance(CLSID_TaskScheduler,
        NULL,
        CLSCTX_INPROC_SERVER,
        IID_ITaskService,
        (void**)&pService);

    if (FAILED(hr)) {
        printComError(hr, "CoCreateInstance(ITaskService) failed");
        CoUninitialize();
        return 1;
    }

    logMsg(L"Connecting to COM...");
    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) {
        printComError(hr, "TaskService->Connect failed");
        pService->Release();
        CoUninitialize();
        return 1;
    }

    // Get the root folder
    ITaskFolder* pRootFolder = nullptr;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr)) {
        printComError(hr, "Cannot get Root Folder pointer");
        pService->Release();
        CoUninitialize();
        return 1;
    }

    // If a task with the same name exists, delete it (overwrite behavior)
    IRegisteredTask* pExisting = nullptr;
    hr = pRootFolder->GetTask(_bstr_t(path.c_str()), &pExisting);
    if (SUCCEEDED(hr) && pExisting) {
        hr = pRootFolder->DeleteTask(_bstr_t(path.c_str()), 0);
        if (FAILED(hr)) {
            printComError(hr, "Failed to delete existing task");
            pExisting->Release();
            pRootFolder->Release();
            pService->Release();
            CoUninitialize();
            return 1;
        }
        pExisting->Release();
    }

    // create task definition
    logMsg(L"Creating task...");
    ITaskDefinition* pTask = nullptr;
    hr = pService->NewTask(0, &pTask);
    if (FAILED(hr)) {
        printComError(hr, "NewTask failed");
        pRootFolder->Release();
        pService->Release();
        CoUninitialize();
        return 1;
    }

    // registration info (author, etc.)
    IRegistrationInfo* pRegInfo = nullptr;
    hr = pTask->get_RegistrationInfo(&pRegInfo);
    if (SUCCEEDED(hr) && pRegInfo) {
        pRegInfo->put_Author(_bstr_t(L"RegisterSystemTask"));
        pRegInfo->Release();
    }

    // principal: set to run as SERVICE account (SYSTEM) with highest privileges
    IPrincipal* pPrincipal = nullptr;
    hr = pTask->get_Principal(&pPrincipal);
    if (FAILED(hr)) {
        printComError(hr, "get_Principal failed");
        pTask->Release();
        pRootFolder->Release();
        pService->Release();
        CoUninitialize();
        return 1;
    }

    // LogonType: TASK_LOGON_SERVICE_ACCOUNT
    hr = pPrincipal->put_LogonType(TASK_LOGON_SERVICE_ACCOUNT);
    if (FAILED(hr)) {
        printComError(hr, "put_LogonType failed");
        pPrincipal->Release();
        pTask->Release();
        pRootFolder->Release();
        pService->Release();
        CoUninitialize();
        return 1;
    }

    // set the user ID to the well-known SYSTEM SID "S-1-5-18"
    hr = pPrincipal->put_UserId(_bstr_t(L"S-1-5-18"));
    if (FAILED(hr)) {
        printComError(hr, "put_UserId failed");
        pPrincipal->Release();
        pTask->Release();
        pRootFolder->Release();
        pService->Release();
        CoUninitialize();
        return 1;
    }

    // run with highest privileges
    hr = pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
    if (FAILED(hr)) {
        printComError(hr, "put_RunLevel failed");
        pPrincipal->Release();
        pTask->Release();
        pRootFolder->Release();
        pService->Release();
        CoUninitialize();
        return 1;
    }
    pPrincipal->Release();

    // Settings
    ITaskSettings* pSettings = nullptr;
    hr = pTask->get_Settings(&pSettings);
    if (SUCCEEDED(hr) && pSettings) {
        // Do not run if battery or network unavailable, etc. Tweak as needed.
        pSettings->put_StartWhenAvailable(VARIANT_TRUE);
        pSettings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
        pSettings->Release();
    }

    // create action (Exec)
    IActionCollection* pActionCollection = nullptr;
    hr = pTask->get_Actions(&pActionCollection);
    if (FAILED(hr)) {
        printComError(hr, "get_Actions failed");
        pTask->Release();
        pRootFolder->Release();
        pService->Release();
        CoUninitialize();
        return 1;
    }

    IAction* pAction = nullptr;
    hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
    if (FAILED(hr)) {
        printComError(hr, "Create action failed");
        pActionCollection->Release();
        pTask->Release();
        pRootFolder->Release();
        pService->Release();
        CoUninitialize();
        return 1;
    }

    IExecAction* pExecAction = nullptr;
    hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
    if (FAILED(hr)) {
        printComError(hr, "QueryInterface(IExecAction) failed");
        pAction->Release();
        pActionCollection->Release();
        pTask->Release();
        pRootFolder->Release();
        pService->Release();
        CoUninitialize();
        return false;
    }

    // set executable and arguments
    hr = pExecAction->put_Path(_bstr_t(exePath));
    if (FAILED(hr)) {
        printComError(hr, "put_Path failed");
    }

    // build argument string using input parameters
    std::wstringstream argStream;
    argStream << "-id " << id << " -path " << L" \"" << std::wstring(path.begin(), path.end()) << L"\"";
    std::wstring args = argStream.str();

    // set arguments
    hr = pExecAction->put_Arguments(_bstr_t(args.c_str()));
    if (FAILED(hr)) {
        printComError(hr, "put_Arguments failed");
    }

    // clean up action objects
    pExecAction->Release();
    pAction->Release();
    pActionCollection->Release();

    // register task in root folder.
    IRegisteredTask* pRegisteredTask = nullptr;
    VARIANT vPassword; VariantInit(&vPassword); // no password neeeded
    // use TASK_LOGON_SERVICE_ACCOUNT as logon type for registering
    hr = pRootFolder->RegisterTaskDefinition(
        _bstr_t(taskName),
        pTask,
        TASK_CREATE_OR_UPDATE, // create or overwrite 
        _variant_t(), // userId: empty = use principal.UserId
        vPassword,    // password: empty
        TASK_LOGON_SERVICE_ACCOUNT,
        _variant_t(L""), // sddl: empty
        &pRegisteredTask);

    if (FAILED(hr)) {
        printComError(hr, "RegisterTaskDefinition failed");
        pTask->Release();
        pRootFolder->Release();
        pService->Release();
        CoUninitialize();
        return false;
    }

    logMsg(L"Task registered successfully (runs as SYSTEM).\n");

    // run it now
    IRunningTask *pRunning = nullptr;
    hr = pRegisteredTask->Run(_variant_t(), &pRunning);
    if (SUCCEEDED(hr)) {
        logMsg(L"Task started successfully.\n");
        if (pRunning) pRunning->Release();
    } else {
        printComError(hr, "Failed to start task");
    }


    // cleanup
    if (pRegisteredTask) pRegisteredTask->Release();
    pTask->Release();
    pRootFolder->Release();
    pService->Release();
    CoUninitialize();
    logMsg(L"COM cleaned up");
    return true;
}