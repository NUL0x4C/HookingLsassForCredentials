#include <Windows.h>
#include <tlhelp32.h>

#include "Structs.h"
#include "HardwareBreakingLib.h"
#include "Log.h"

//---------------------------------------------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------------------------------------------

#pragma section(".text")
__declspec(allocate(".text")) const unsigned char ucRet[] = { 0xC3 };

VOID BLOCK_REAL(IN PCONTEXT pThreadCtx) 
{
	pThreadCtx->Rip = (ULONG_PTR)&ucRet;
}

//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------------------------------------------------------------


PBYTE GetFunctionArgument(IN PCONTEXT pThreadCtx, IN DWORD dwParmIndex) {

	// The first 4 arguments in x64 are in the "RCX - RDX - R8 - R9" registers
	switch (dwParmIndex) {
		case 0x01:
			return (ULONG_PTR)pThreadCtx->Rcx;
		case 0x02:
			return (ULONG_PTR)pThreadCtx->Rdx;
		case 0x03:
			return (ULONG_PTR)pThreadCtx->R8;
		case 0x04:
			return (ULONG_PTR)pThreadCtx->R9;
		default:
			break;
	}

	// Else more arguments are pushed to the stack
	return *(ULONG_PTR*)(pThreadCtx->Rsp + (dwParmIndex * sizeof(PVOID)));
}

VOID SetFunctionArgument(IN PCONTEXT pThreadCtx, IN ULONG_PTR uValue, IN DWORD dwParmIndex) {

	// The first 4 arguments in x64 are in the "RCX - RDX - R8 - R9" registers
	switch (dwParmIndex) {
		case 0x01:
			(ULONG_PTR)pThreadCtx->Rcx = uValue; return;
		case 0x02:
			(ULONG_PTR)pThreadCtx->Rdx = uValue; return;
		case 0x03:
			(ULONG_PTR)pThreadCtx->R8 = uValue; return;
		case 0x04:
			(ULONG_PTR)pThreadCtx->R9 = uValue; return;
		default:
			break;
	}

	// Else more arguments are pushed to the stack
	*(ULONG_PTR*)(pThreadCtx->Rsp + (dwParmIndex * sizeof(PVOID))) = uValue;
}

//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//													HELPER FUNCTIONS

DWORD _GetCurrentProcessId() 
{
	return (DWORD)(__readgsdword(0x40));
}

DWORD _GetCurrentThreadId() 
{
	return (DWORD)(__readgsdword(0x48));
}

HANDLE _GetProcessHeap() 
{
	PPEB pPeb = (PPEB)(__readgsqword(0x60));
	return (HANDLE)pPeb->ProcessHeap;
}


unsigned long long SetDr7Bits(unsigned long long CurrentDr7Register, int StartingBitPosition, int NmbrOfBitsToModify, unsigned long long NewBitValue) 
{
	unsigned long long mask = (1UL << NmbrOfBitsToModify) - 1UL;
	unsigned long long NewDr7Register = (CurrentDr7Register & ~(mask << StartingBitPosition)) | (NewBitValue << StartingBitPosition);
	return NewDr7Register;
}


//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//												GLOBAL VARIABLES


CRITICAL_SECTION						g_HookingCriticalSection				= { 0 };
HARDWARE_ENGINE_INIT_SETTINGS_GLOBAL	GlobalHardwareBreakpointObject			= { 0 };
DESCRIPTOR_ENTRY*						g_Head									= NULL;


//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//												PRIVATE FUNCTIONS PROTOTYPES

BOOL SetHardwareBreakpoint(IN DWORD ThreadId, IN PUINT_VAR_T Address, IN DRX Drx, IN BOOL bInitializeHWBP);
LONG ExceptionHandlerCallbackRoutine(IN PEXCEPTION_POINTERS ExceptionInfo);
BOOL SnapshotInsertHardwareBreakpointHookIntoTargetThread(IN PUINT_VAR_T Address, IN DRX Drx, IN BOOL bInitializeHWBP, IN DWORD ThreadId);

//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------------------------------------------------------------


BOOL InitHardwareBreakpointHooking() 
{

	if (GlobalHardwareBreakpointObject.IsInit)
		return TRUE;

	RtlSecureZeroMemory(&GlobalHardwareBreakpointObject, sizeof(HARDWARE_ENGINE_INIT_SETTINGS_GLOBAL));
	RtlSecureZeroMemory(&g_HookingCriticalSection, sizeof(CRITICAL_SECTION));

	GlobalHardwareBreakpointObject.HandlerObject = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)ExceptionHandlerCallbackRoutine);
	if (!GlobalHardwareBreakpointObject.HandlerObject) {
		DBGPRINTF(L"[!] AddVectoredExceptionHandler Failed: %d\n", GetLastError());
		return FALSE;
	}

	InitializeCriticalSection(&g_HookingCriticalSection);

	GlobalHardwareBreakpointObject.IsInit = TRUE;

	return TRUE;
}


BOOL CleapUpHardwareBreakpointHooking() 
{

	DESCRIPTOR_ENTRY* TempObject = NULL;

	if (!GlobalHardwareBreakpointObject.IsInit)
		return TRUE;

	EnterCriticalSection(&g_HookingCriticalSection);

	TempObject = g_Head;

	while (TempObject != NULL)
	{
		RemoveHardwareBreakingPntHook(TempObject->Address, TempObject->ThreadId);
		TempObject = TempObject->Next;
	}

	LeaveCriticalSection(&g_HookingCriticalSection);

	if (GlobalHardwareBreakpointObject.HandlerObject)
		RemoveVectoredExceptionHandler(GlobalHardwareBreakpointObject.HandlerObject);

	DeleteCriticalSection(&g_HookingCriticalSection);

	GlobalHardwareBreakpointObject.IsInit = FALSE;

	return TRUE;
}


//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------------------------------------------------------------

LONG ExceptionHandlerCallbackRoutine(IN PEXCEPTION_POINTERS ExceptionInfo)
{
    DESCRIPTOR_ENTRY*	TempObject	= { 0 };
    BOOL				bResolved	= FALSE;

    if (ExceptionInfo->ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP)
        goto EXIT_ROUTINE;

    EnterCriticalSection(&g_HookingCriticalSection);

    TempObject = g_Head;

    while (TempObject != NULL){

		if (TempObject->Address == ExceptionInfo->ContextRecord->Rip && !TempObject->Processed) {

			if (TempObject->ThreadId != 0 && TempObject->ThreadId != _GetCurrentThreadId())
			{
				TempObject->Processed = TRUE;
				continue;
			}

			// 1. Disable hw breakpoint 
            if (!SetHardwareBreakpoint(_GetCurrentThreadId(), TempObject->Address, TempObject->Drx, FALSE))
				goto EXIT_ROUTINE;

			// 2. Execute the callback (detour function)
			VOID(*fnHookFunc)(PCONTEXT) = TempObject->CallbackFunction;
			fnHookFunc(ExceptionInfo->ContextRecord);

			// 3. Enable the hw breakpoint again
            if (!SetHardwareBreakpoint(_GetCurrentThreadId(), TempObject->Address, TempObject->Drx, TRUE))
				goto EXIT_ROUTINE;

			TempObject->Processed = TRUE;
        }

		TempObject->Processed	= FALSE;
        TempObject				= TempObject->Next;
    }

    LeaveCriticalSection(&g_HookingCriticalSection);

    bResolved = TRUE;

EXIT_ROUTINE:

    return (bResolved ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH);
}



//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------------------------------------------------------------

BOOL SetHardwareBreakpoint(IN DWORD ThreadId, IN PUINT_VAR_T Address, IN DRX Drx, IN BOOL bInitializeHWBP)
{
	CONTEXT		Context				= { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
	HANDLE		hThread				= INVALID_HANDLE_VALUE;
	BOOL		bSuspendedThread	= FALSE;
	BOOL		bReturn				= FALSE;


	if (ThreadId != _GetCurrentThreadId())
	{
		if ((hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, ThreadId)) == NULL)
		{
			DBGPRINTF(L"[!] OpenThread [%ld] Failed: %d\n", __LINE__, GetLastError());
			goto EXIT_ROUTINE;
		}
	}
	else
		hThread = ((HANDLE)-2);


	if (hThread != ((HANDLE)-2)) 
	{
		if (SuspendThread(hThread) == ((DWORD)-1))
		{
			DBGPRINTF(L"[!] SuspendThread [%ld] Failed: %d\n", __LINE__, GetLastError());
			goto EXIT_ROUTINE;
		}

		bSuspendedThread = TRUE;
	}

	if (!GetThreadContext(hThread, &Context)) 
	{
		DBGPRINTF(L"[!] GetThreadContext [%ld] Failed: %d\n", __LINE__, GetLastError());
		goto EXIT_ROUTINE;
	}

	if (bInitializeHWBP) 
	{
		(&Context.Dr0)[Drx] = Address;
		Context.Dr7			= SetDr7Bits(Context.Dr7, (Drx * 2), 1, 1);
	}
	else 
	{
		if ((&Context.Dr0)[Drx] == Address){
			(&Context.Dr0)[Drx] = 0ull;
			Context.Dr7			= SetDr7Bits(Context.Dr7, (Drx * 2), 1, 0);
		}
	}

	if (!SetThreadContext(hThread, &Context)) 
	{
		DBGPRINTF(L"[!] SetThreadContext [%ld] Failed: %d\n", __LINE__, GetLastError());
		goto EXIT_ROUTINE;
	}
	
	bReturn = TRUE;

EXIT_ROUTINE:
	if (bSuspendedThread)
	{
		if (ResumeThread(hThread) == ((DWORD)-1))
			DBGPRINTF(L"[!] ResumeThread [%ld] Failed: %d\n", __LINE__, GetLastError());
	}
	if (hThread && hThread != ((HANDLE)-2))
		CloseHandle(hThread);
	return bReturn;
}


//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------------------------------------------------------------


#define STATUS_SUCCESS              0x00000000
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

typedef NTSTATUS(WINAPI* fnNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);


BOOL SnapshotInsertHardwareBreakpointHookIntoTargetThread(IN PUINT_VAR_T Address, IN DRX Drx, IN BOOL bInitializeHWBP, IN DWORD ThreadId)
{
	
	fnNtQuerySystemInformation		pNtQuerySystemInformation	= NULL;
	ULONG							uReturnLen1					= NULL,
									uReturnLen2					= NULL;
	PSYSTEM_PROCESS_INFORMATION		SystemProcInfo				= NULL;
	DWORD64							dw64AllocatedSize			= INITIAL_ALLOCATION_SIZE;
	PVOID							pValueToFree				= NULL;
	NTSTATUS						STATUS						= NULL;
	BOOL							bResult						= FALSE;

	pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQuerySystemInformation");
	if (pNtQuerySystemInformation == NULL) {
		DBGPRINTF(L"[!] GetProcAddress [%ld] Failed: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}


	do {
	
		if (SystemProcInfo) 
		{
			HeapFree(GetProcessHeap(), 0x00, SystemProcInfo);
			SystemProcInfo = NULL;
		}
	
		if (!(SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(_GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)dw64AllocatedSize))) 
		{
			DBGPRINTF(L"[!] HeapAlloc [%ld] Failed: %d\n", __LINE__, GetLastError());
			goto _END_OF_FUNC;
		}

		if ((STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, dw64AllocatedSize, &uReturnLen1)) != STATUS_SUCCESS && STATUS != STATUS_INFO_LENGTH_MISMATCH) {
			DBGPRINTF(L"[!] NtQuerySystemInformation Failed (1): 0x%0.8X\n", STATUS);
			goto _END_OF_FUNC;
		}

		dw64AllocatedSize *= 2;

	} while (STATUS == STATUS_INFO_LENGTH_MISMATCH);

	
	pValueToFree = SystemProcInfo;
	
	while (TRUE) {

		
		if (SystemProcInfo->UniqueProcessId == _GetCurrentProcessId()) {
		
			PSYSTEM_THREAD_INFORMATION      SystemThreadInfo	= (PSYSTEM_THREAD_INFORMATION)SystemProcInfo->Threads;

			for (DWORD i = 0; i < SystemProcInfo->NumberOfThreads; i++) {
				
				if (ThreadId != ALL_THREADS && ThreadId != SystemThreadInfo[i].ClientId.UniqueThread)
					continue;

				if (!SetHardwareBreakpoint(SystemThreadInfo[i].ClientId.UniqueThread, Address, Drx, bInitializeHWBP)) 
				{
					DBGPRINTF(L"[!] SetHardwareBreakpoint Failed On Thread: %ld\n", SystemThreadInfo[i].ClientId.UniqueThread);
					// Ignore the error and continue
					//\
					goto _END_OF_FUNC;
				}
			}

			break;
		}

		if (!SystemProcInfo->NextEntryOffset)
			break;

		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (pValueToFree)
		HeapFree(_GetProcessHeap(), 0, pValueToFree);
	return bResult;
}


//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------------------------------------------------------------


BOOL InstallHardwareBreakingPntHook(IN PUINT_VAR_T Address, IN DRX Drx, IN PVOID CallbackRoutine, IN DWORD ThreadId)
{
	DESCRIPTOR_ENTRY*	NewEntry	= NULL;

	if ((NewEntry = (DESCRIPTOR_ENTRY*)HeapAlloc(_GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DESCRIPTOR_ENTRY))) == NULL) 
	{
		DBGPRINTF(L"[!] HeapAlloc [%ld] Failed: %d\n", __LINE__, GetLastError());
		return FALSE;
	}
	
	EnterCriticalSection(&g_HookingCriticalSection);

	NewEntry->Address								= Address;
	NewEntry->Drx									= Drx;
	NewEntry->ThreadId								= ThreadId;
	NewEntry->CallbackFunction						= CallbackRoutine;
	NewEntry->Next									= g_Head;
	NewEntry->Previous								= NULL;

	if (g_Head != NULL)
		g_Head->Previous = NewEntry;

	g_Head = NewEntry;

	LeaveCriticalSection(&g_HookingCriticalSection);

	return SnapshotInsertHardwareBreakpointHookIntoTargetThread(Address, Drx, TRUE, ThreadId);
}


BOOL RemoveHardwareBreakingPntHook(IN PUINT_VAR_T Address, IN DWORD ThreadId)
{
	DESCRIPTOR_ENTRY*	TempObject	= NULL;
	enum DRX			Drx			= -1;
	BOOL				bResult		= FALSE,
						Found		= FALSE;

	EnterCriticalSection(&g_HookingCriticalSection);

	TempObject = g_Head;

	while (TempObject != NULL)
	{
		if (TempObject->Address == Address && TempObject->ThreadId == ThreadId)
		{
			Found = TRUE;

			Drx = TempObject->Drx;

			if (g_Head == TempObject)
				g_Head = TempObject->Next;

			if (TempObject->Next != NULL)
				TempObject->Next->Previous = TempObject->Previous;

			if (TempObject->Previous != NULL)
				TempObject->Previous->Next = TempObject->Next;

			//if (TempObject)
			//	HeapFree(_GetProcessHeap(), HEAP_ZERO_MEMORY, TempObject);
		}

		if (TempObject)
			TempObject = TempObject->Next;
	}

	LeaveCriticalSection(&g_HookingCriticalSection);

	if (Found)
		bResult = SnapshotInsertHardwareBreakpointHookIntoTargetThread(Address, Drx, FALSE, ThreadId);

	return bResult;
}



//------------------------------------------------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------------------------------------------------
