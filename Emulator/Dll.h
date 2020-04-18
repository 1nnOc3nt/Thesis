#pragma once
#include "Info.h"

#define retdata "\xc3\xc3\xc3\xc3\xc3\xc3\xc3\xc3\xc3\xc3"

extern map<DWORD, TCHAR*>symbols;
extern map<TCHAR*, LPVOID>hookAPI;
extern map<TCHAR*, DWORD>loadedDll;