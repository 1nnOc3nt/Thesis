#pragma once
#include "Dll.h"
#include "Heap.h"

void EmuRegCloseKey(uc_engine* uc, DWORD tab);
void EmuRegCreateKey(uc_engine* uc, DWORD tab, DWORD hKey, TCHAR subKey[], DWORD phkResult);
void EmuRegCreateKeyA(uc_engine* uc, DWORD tab);
void EmuRegCreateKeyW(uc_engine* uc, DWORD tab);
void EmuRegDeleteKey(uc_engine* uc, DWORD tab, DWORD hKey, TCHAR subKey[]);
void EmuRegDeleteKeyA(uc_engine* uc, DWORD tab);
void EmuRegDeleteKeyW(uc_engine* uc, DWORD tab);
void EmuRegDeleteValue(uc_engine* uc, DWORD tab, DWORD hKey, TCHAR subKey[]);
void EmuRegDeleteValueA(uc_engine* uc, DWORD tab);
void EmuRegDeleteValueW(uc_engine* uc, DWORD tab);