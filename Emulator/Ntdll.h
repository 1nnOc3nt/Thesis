#pragma once
#include "Dll.h"
#include "Heap.h"

void Emumemcmp(uc_engine* uc, DWORD tab);
void Emumemcpy(uc_engine* uc, DWORD tab);
void Emumemset(uc_engine* uc, DWORD tab);
void Emustrcat(uc_engine* uc, DWORD tab);
void Emustrcmp(uc_engine* uc, DWORD tab);
void Emustrcpy(uc_engine* uc, DWORD tab);
void Emustrlen(uc_engine* uc, DWORD tab);
void Emuwcscat(uc_engine* uc, DWORD tab);
void Emuwcscmp(uc_engine* uc, DWORD tab);
void Emuwcscpy(uc_engine* uc, DWORD tab);
void Emuwcslen(uc_engine* uc, DWORD tab);