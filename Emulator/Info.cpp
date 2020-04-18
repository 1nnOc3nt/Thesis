#include "Info.h"

TCHAR _fileDir[MAX_PATH] = { 0 };
DWORD _stackAddr = 0;
DWORD _stackSize = 0;
DWORD _heapAddr = 0;
DWORD _heapSize = 0;
DWORD _dllLastAddr = 0x7000000;