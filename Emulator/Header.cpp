#include "Header.h"

map<TCHAR*, Func>api;
TCHAR _fileDir[MAX_PATH] = { 0 };
TCHAR _filePath[MAX_PATH] = { 0 };
TCHAR _fileName[MAX_PATH] = { 0 };
DWORD _stackAddr = 0;
DWORD _stackSize = 0x3000;