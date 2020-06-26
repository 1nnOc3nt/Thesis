#pragma once
#include "PE.h"
#include "TIB.h"

#define retdata "\xc3\xc3\xc3\xc3\xc3\xc3\xc3\xc3\xc3\xc3"

extern DWORD _dllLastAddr;
extern DWORD _numbersOfFunc;
extern map<DWORD, TCHAR*>symbols;
extern map<DWORD, DWORD>loadInOrderFuncs;
extern map<TCHAR*, DWORD>loadedDll;
extern map<TCHAR*, TCHAR*>fullDllPath;

DWORD LoadDll(uc_engine* uc, TCHAR* dllName);
void UcSetLastError(uc_engine* uc, DWORD errorCode);