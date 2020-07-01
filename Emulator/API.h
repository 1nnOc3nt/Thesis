#pragma once
#include "Kernel.h"
#include "Msvcrt.h"
#include "ws2_32.h"

typedef void (*Func)(uc_engine* uc, DWORD tab);

extern map<TCHAR*, Func>api;

void EmuFunc();