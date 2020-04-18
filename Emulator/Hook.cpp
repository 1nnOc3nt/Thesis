#include "Hook.h"

CacheIns _cache;
BOOL _isCached = FALSE;
int tabSize = 0;

void hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	csh cs;
	cs_insn* insn;
	size_t count = 0;
	uint8_t* code = new uint8_t[size];
	ZeroMemory(code, size);
	uc_err err = uc_mem_read(uc, address, code, size);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs) != CS_ERR_OK)
		return;

	count = cs_disasm(cs, code, size, address, 0, &insn);

	if (count > 0)
	{
		for (int i = 0; i < count; i++)
		{
			if (_isCached)
			{
				if ((symbols.find((DWORD)insn[i].address) != symbols.end()))
					//Check emulated API
					_tprintf("0x%llX: %s\t%s\n", _cache.address, _cache.mnemonic, symbols[(DWORD)insn[i].address]);
					//Hook API
				else
					//Print default arguments
					_tprintf("0x%llX: %s\t%s\n", _cache.address, _cache.mnemonic, _cache.op_str);
			}

			if (!strcmp(insn[i].mnemonic, "call") || !strcmp(insn[i].mnemonic, "jmp"))
			{
				for (int j = 0; j < tabSize; j++)
					_tprintf("   |   ");

				_cache.address = insn[i].address;
				_cache.mnemonic = insn[i].mnemonic;
				_cache.op_str = insn[i].op_str;
				_isCached = TRUE;
				if (!strcmp(insn[i].mnemonic, "call"))
					tabSize++;
			}
			else if (strstr(insn[i].mnemonic, "ret"))
			{
				_isCached = FALSE;
				tabSize--;
			}
			else
				_isCached = FALSE;
		}
	}
	else
		_tprintf("[!] Failed to disassemble given code!\n");
	delete[] code;
	cs_close(&cs);
}