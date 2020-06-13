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

typedef void (*Func)(uc_engine* uc);

extern map<TCHAR*, Func>api;
extern TCHAR _fileDir[MAX_PATH];
extern TCHAR _filePath[MAX_PATH];
extern TCHAR _fileName[MAX_PATH];
extern DWORD _stackAddr;
extern DWORD _stackSize;