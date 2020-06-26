#pragma once
#include "Utils.h"

extern map<DWORD, DWORD>heap;
extern DWORD _heapAddr;
extern DWORD _heapSize;

BOOL IsMapped(uc_engine* uc, DWORD heapAddress, DWORD heapSize);
DWORD NewHeap(uc_engine* uc, DWORD heapSize);
DWORD NewHeap(uc_engine* uc, DWORD heapAddress, DWORD heapSize);
BOOL DeleteHeap(uc_engine* uc, DWORD heapAddress, DWORD heapSize = 0);