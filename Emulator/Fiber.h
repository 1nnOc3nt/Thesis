#pragma once
#include "Utils.h"

extern DWORD _index;
extern map<DWORD, DWORD>fiber;

DWORD AllocFiber();
DWORD SetFiber(DWORD index, DWORD data);
DWORD GetFiber(DWORD index);
DWORD FreeFiber(DWORD index);