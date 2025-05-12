#include <Windows.h>

#ifndef HARDWARE_BP
#define HARDWARE_BP


//---------------------------------------------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------------------------------------------
//	PRIVATE

#define INITIAL_ALLOCATION_SIZE 0x1000							// 4KB
#define ALL_THREADS				0x00


typedef uintptr_t PUINT_VAR_T;

typedef struct __HARDWARE_ENGINE_INIT_SETTINGS_GLOBAL {
	PVOID	HandlerObject;
	BOOL	IsInit;
}HARDWARE_ENGINE_INIT_SETTINGS_GLOBAL, * PHARDWARE_ENGINE_INIT_SETTINGS_GLOBAL;

typedef enum _DRX
{
	Dr0,
	Dr1,
	Dr2,
	Dr3

}DRX, * PDRX;


typedef struct DESCRIPTOR_ENTRY {
	PUINT_VAR_T					Address;		
	enum DRX					Drx;			
	DWORD						ThreadId;		
	VOID(*CallbackFunction)(PCONTEXT);			
	BOOL						Processed;		
	struct DESCRIPTOR_ENTRY*	Next;			
	struct DESCRIPTOR_ENTRY*	Previous;		
}DESCRIPTOR_ENTRY, * PDESCRIPTOR_ENTRY;

PBYTE	GetFunctionArgument(IN PCONTEXT pThreadCtx, IN DWORD dwParmIndex);
VOID	SetFunctionArgument(IN PCONTEXT pThreadCtx, IN ULONG_PTR uValue, IN DWORD dwParmIndex);

//---------------------------------------------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------------------------------------------

// Resume the execution of the original function
// This should always be called from the detour function
#define CONTINUE_EXECUTION(CTX)(CTX->EFlags = CTX->EFlags | (1 << 16))

// Set a return value
#define RETURN_VALUE(CTX, VALUE)((ULONG_PTR)CTX->Rax = (ULONG_PTR)VALUE)

// Block the execution of the original function
VOID BLOCK_REAL(IN PCONTEXT pThreadCtx);

// Get Parameters
#define GETPARM_1(CTX)(GetFunctionArgument(CTX, 0x1))	
#define GETPARM_2(CTX)(GetFunctionArgument(CTX, 0x2))
#define GETPARM_3(CTX)(GetFunctionArgument(CTX, 0x3))
#define GETPARM_4(CTX)(GetFunctionArgument(CTX, 0x4))
#define GETPARM_5(CTX)(GetFunctionArgument(CTX, 0x5))
#define GETPARM_6(CTX)(GetFunctionArgument(CTX, 0x6))
#define GETPARM_7(CTX)(GetFunctionArgument(CTX, 0x7))
#define GETPARM_8(CTX)(GetFunctionArgument(CTX, 0x8))
#define GETPARM_9(CTX)(GetFunctionArgument(CTX, 0x9))
#define GETPARM_A(CTX)(GetFunctionArgument(CTX, 0xA))
#define GETPARM_B(CTX)(GetFunctionArgument(CTX, 0xB))

// Set Parameters
#define SETPARM_1(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x1))
#define SETPARM_2(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x2))
#define SETPARM_3(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x3))
#define SETPARM_4(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x4))
#define SETPARM_5(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x5))
#define SETPARM_6(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x6))
#define SETPARM_7(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x7))
#define SETPARM_8(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x8))
#define SETPARM_9(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x9))
#define SETPARM_A(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0xA))
#define SETPARM_B(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0xB))


//---------------------------------------------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------------------------------------------


// Initialize hardware breaking point library (populate global variables & set up the veh handler)
BOOL InitHardwareBreakpointHooking();
// Disable all the breaking points set and delete the veh handler
BOOL CleapUpHardwareBreakpointHooking();


// Install hook on a specified address														\
	* Address			= Harware breaking point address (where to install)					\
	* Drx				= Can be Dr0 -> Dr3													\
	* CallbackRoutine	= Pointer to the detour function 									\
	* ThreadId			= Thread identifier to hook	| 'ALL_THREADS' to hook all threads
BOOL InstallHardwareBreakingPntHook(IN PUINT_VAR_T Address, IN DRX Drx, IN PVOID CallbackRoutine, IN DWORD ThreadId);



// Remove hook on a specified address														\
	* Address			= Harware breaking point address (where to unhook)					\
	* ThreadId			= Thread identifier to unhook | 'ALL_THREADS' to remove hook from all threads
BOOL RemoveHardwareBreakingPntHook(IN PUINT_VAR_T Address, IN DWORD ThreadId);


//---------------------------------------------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------------------------------------------
#endif // !HARDWARE_BP


