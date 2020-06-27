#pragma once
#include "Dll.h"
#include "Heap.h"

extern DWORD _argc;
extern DWORD _argv;

void getArg(uc_engine* uc, BOOL isW=FALSE);
void Emu__acrt_iob_func(uc_engine* uc, DWORD tab);
void Emu__getmainargs(uc_engine* uc, DWORD tab);
void Emu__p___argc(uc_engine* uc, DWORD tab);
void Emu__p___argv(uc_engine* uc, DWORD tab);
void Emu__p___initenv(uc_engine* uc, DWORD tab);
void Emu__p___wargc(uc_engine* uc, DWORD tab);
void Emu__p___wargv(uc_engine* uc, DWORD tab);
void Emu__stdio_common_vfprintf(uc_engine* uc, DWORD tab);
void Emu__wgetmainargs(uc_engine* uc, DWORD tab);
void Emu_exit(uc_engine* uc, DWORD tab);
void Emuexit(uc_engine* uc, DWORD tab);
void Emu_printf(uc_engine* uc, DWORD tab, TCHAR format[], DWORD spArg);
void Emuprintf(uc_engine* uc, DWORD tab);
void Emuprintf(uc_engine* uc, DWORD tab);