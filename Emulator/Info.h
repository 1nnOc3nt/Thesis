#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>
#include <Shlwapi.h>
#include <tchar.h>
#include <map>
#include "unicorn/unicorn.h"
#include "capstone/capstone.h"

#pragma comment (lib, "unicorn.lib")
#pragma comment (lib, "capstone_dll.lib")
#pragma comment (lib, "shlwapi.lib")

using namespace std;

#define HandleError()\
do\
{\
	cout << "[!] Error code: " << GetLastError() << endl;\
	return NULL;\
} while(0)

#define HandleUcError(err)\
do\
{\
	cout << "[!] Uc failed with error code: " << err << endl;\
	cout << uc_strerror(err) << endl;\
	return 1;\
} while(0)

#define HandleUcErrorVoid(err)\
do\
{\
	cout << "[!] Uc failed with error code: " << err << endl;\
	cout << uc_strerror(err) << endl;\
	return;\
} while(0)

extern TCHAR _fileDir[MAX_PATH];
extern DWORD _stackAddr;
extern DWORD _stackSize;
extern DWORD _heapAddr;
extern DWORD _heapSize;
extern DWORD _dllLastAddr;
