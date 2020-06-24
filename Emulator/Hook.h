#pragma once
#include "API.h"

struct CacheIns
{
	uint64_t address = 0;
	TCHAR* mnemonic = NULL;
	TCHAR* op_str = NULL;
};

extern CacheIns _cache;
extern BOOL _isCached;
extern int _tabSize;
extern BOOL _printAsm;
extern BOOL _printReg;

void hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);