#pragma once
#include "PE.h"
#include "TIB.h"

#define retdata "\xc3\xc3\xc3\xc3\xc3\xc3\xc3\xc3\xc3\xc3"

extern DWORD _dllLastAddr;
extern map<DWORD, TCHAR*>symbols;
extern map<TCHAR*, DWORD>loadedDll;

DWORD LoadDll(uc_engine* uc, TCHAR* dllName);