#pragma once
#include "Kernel.h"
#include "Msvcrt.h"

typedef void (*Func)(uc_engine* uc, DWORD tab);

extern map<TCHAR*, Func>api;

void EmuFunc();