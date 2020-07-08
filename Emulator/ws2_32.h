#pragma once
#include "Dll.h"
#include "Heap.h"

void Emuaccept(uc_engine* uc, DWORD tab);
void Emubind(uc_engine* uc, DWORD tab);
void Emuconnect(uc_engine* uc, DWORD tab);
void Emuclosesocket(uc_engine* uc, DWORD tab);
void Emugetsockopt(uc_engine* uc, DWORD tab);
void Emulisten(uc_engine* uc, DWORD tab);
void Emurecv(uc_engine* uc, DWORD tab);
void Emusend(uc_engine* uc, DWORD tab);
void Emusetsockopt(uc_engine* uc, DWORD tab);
void Emusocket(uc_engine* uc, DWORD tab);
void EmuWSACleanup(uc_engine* uc, DWORD tab);
void EmuWSAGetLastError(uc_engine* uc, DWORD tab);
void EmuWSASetLastError(uc_engine* uc, DWORD tab);
void EmuWSASocket(uc_engine* uc, DWORD tab);
void EmuWSAStartup(uc_engine* uc, DWORD tab);