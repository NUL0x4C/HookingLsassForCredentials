#include <Windows.h>
#include <stdio.h>

#include "Log.h"


/*
@ Writes the debug log to a file.
*/

VOID LogToFileW(IN LPCWSTR szFmt, ...) {

    WCHAR       szInputBuffer[0xFF] = { 0 };
    PSTR        pArgs = NULL;
    HANDLE      hFile = INVALID_HANDLE_VALUE;
    DWORD       dwWrittenBytes = 0x00;

    va_start(pArgs, szFmt);
    vswprintf_s(szInputBuffer, _countof(szInputBuffer), szFmt, pArgs);
    va_end(pArgs);

    if ((hFile = CreateFileW(DEBUG_FILE, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE)
    {
        WriteFile(hFile, szInputBuffer, (DWORD)(wcslen(szInputBuffer) * sizeof(WCHAR)), &dwWrittenBytes, NULL);
        CloseHandle(hFile);
    }
    else
    {
        OutputDebugStringW(szInputBuffer);
    }

}