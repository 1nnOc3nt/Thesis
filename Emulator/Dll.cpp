#include "Dll.h"

map<DWORD, TCHAR*>symbols;
map<TCHAR*, LPVOID>hookAPI;
map<TCHAR*, DWORD>loadedDll;