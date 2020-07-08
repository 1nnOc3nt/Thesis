#include "Header.h"

TCHAR _fileDir[MAX_PATH] = { 0 };
TCHAR _filePath[MAX_PATH] = { 0 };
TCHAR _fileName[MAX_PATH] = { 0 };
DWORD _stackAddr = 0;
DWORD _stackSize = 0x100000;
DWORD _numberOfArguments = 0;
HANDLE _outFile = INVALID_HANDLE_VALUE;
DWORD _dwBytesWritten = 0;
clock_t start_time;
clock_t end_time;