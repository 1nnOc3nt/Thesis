#pragma once
#include "Utils.h"

extern DWORD _lastStructureAddress;
extern DWORD _LDRHead;
extern DWORD _lastLDRDataAddress;
extern DWORD _LDRDataSize;

void InitTIB(uc_engine* uc, DWORD stackBase, DWORD stackLimit, DWORD TIBAddress, DWORD PEBAddress);
DWORD getTIBSize();
void InitProcessParam(uc_engine* uc, DWORD address, TCHAR* imagePath, TCHAR* arg = NULL);
void InitPEB(uc_engine* uc, DWORD PEBAddress, DWORD LDRAddress, DWORD processParam, DWORD processHeap);
DWORD getPEBSize();
void InitLDR(uc_engine* uc, DWORD LDRAddress, DWORD LDRHeadAddress);
DWORD getLDRSize();
void AddToLDR(uc_engine* uc, DWORD LDRDataAddress, DWORD dllBase = 0, DWORD entryPoint = 0, DWORD sizeOfImage = 0, TCHAR* fullDllName = NULL, TCHAR* baseDllName = NULL);
DWORD getLDRDataSize();