#pragma once


#define DEBUG_FILE				    L"C:\\DummyDebug.log"
#define DBGPRINTF(fmt, ...)			LogToFileW((fmt), __VA_ARGS__)
