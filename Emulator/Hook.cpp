#include "Hook.h"

CacheIns _cache;
BOOL _isCached = FALSE;
int _tabSize = 0;
BOOL _printAsm = FALSE;
BOOL _printReg = FALSE;

void hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	TCHAR buffer[MAX_PATH] = { 0 };
	csh cs;
	cs_insn* insn;
	size_t count = 0;
	uint8_t* code = new uint8_t[size];
	ZeroMemory(code, size);

	char total_tab[100] = { 0 };
	memset(total_tab, '\t', _tabSize);

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
			if (_numberOfArguments != 0)
			{
				CleanupStack(uc, _numberOfArguments);
				_numberOfArguments = 0;
			}

			if (_isCached)
			{
				if (_printReg)
				{
					if (!strcmp(_cache.mnemonic, "call"))
						getRegistries(uc, _tabSize - 1);
					else
						getRegistries(uc, _tabSize);
				}

				if ((symbols.find((DWORD)insn[i].address) != symbols.end()))
				{
					map<TCHAR*, Func>::iterator iterate;

					if (!strcmp(_cache.mnemonic, "call"))
					{
						//WriteFile(_outFile, total_tab, _tabSize, &_dwBytesWritten, NULL);
						//WriteFile(_outFile, "---------------------------------------\n", strlen("---------------------------------------\n"), &_dwBytesWritten, NULL);

						WriteFile(_outFile, total_tab, _tabSize - 1, &_dwBytesWritten, NULL);
						_stprintf(buffer, "<Address value=0x%llX>\n", _cache.address);
						UcPrint(buffer);
						WriteFile(_outFile, total_tab, _tabSize - 1, &_dwBytesWritten, NULL);
						_stprintf(buffer, "\t<CallApi name=\"%s\">\n", symbols[(DWORD)insn[i].address]);
						UcPrint(buffer);
						WriteFile(_outFile, total_tab, _tabSize -1, &_dwBytesWritten, NULL);
						_stprintf(buffer, "\t\t%s", symbols[(DWORD)insn[i].address]);
						UcPrint(buffer);
						
						iterate = api.begin();
						while (iterate != api.end())
						{
							if (!strcmp(iterate->first, symbols[(DWORD)insn[i].address]))
							{
								iterate->second(uc, _tabSize - 1);
							}
							iterate++;
						}

						WriteFile(_outFile, total_tab, _tabSize - 1, &_dwBytesWritten, NULL);
						_stprintf(buffer, "\t</CallApi>\n");
						UcPrint(buffer);
						WriteFile(_outFile, total_tab, _tabSize - 1, &_dwBytesWritten, NULL);
						_stprintf(buffer, "</Address>\n");
						UcPrint(buffer);
						//WriteFile(_outFile, total_tab, _tabSize, &_dwBytesWritten, NULL);
						//WriteFile(_outFile, "---------------------------------------\n", strlen("---------------------------------------\n"), &_dwBytesWritten, NULL);
					}
					else
					{
						//WriteFile(_outFile, total_tab, _tabSize, &_dwBytesWritten, NULL);
						//WriteFile(_outFile, "---------------------------------------\n", strlen("---------------------------------------\n"), &_dwBytesWritten, NULL);

						WriteFile(_outFile, total_tab, _tabSize, &_dwBytesWritten, NULL);
						_stprintf(buffer, "<Address value=0x%llX>\n", _cache.address);
						UcPrint(buffer);
						WriteFile(_outFile, total_tab, _tabSize, &_dwBytesWritten, NULL);
						_stprintf(buffer, "\t<JmpApi name=\"%s\" >\n", symbols[(DWORD)insn[i].address]);
						UcPrint(buffer);
						WriteFile(_outFile, total_tab, _tabSize, &_dwBytesWritten, NULL);
						_stprintf(buffer, "\t\t%s", symbols[(DWORD)insn[i].address]);
						UcPrint(buffer);

						iterate = api.begin();
						while (iterate != api.end())
						{
							if (!strcmp(iterate->first, symbols[(DWORD)insn[i].address]))
							{
								iterate->second(uc, _tabSize);
							}
							iterate++;
						}

						WriteFile(_outFile, total_tab, _tabSize, &_dwBytesWritten, NULL);
						_stprintf(buffer, "\t</JmpApi>\n");
						UcPrint(buffer);
						WriteFile(_outFile, total_tab, _tabSize, &_dwBytesWritten, NULL);
						_stprintf(buffer, "</Address>\n");
						UcPrint(buffer);
						//WriteFile(_outFile, total_tab, _tabSize, &_dwBytesWritten, NULL);
						//WriteFile(_outFile, "---------------------------------------\n", strlen("---------------------------------------\n"), &_dwBytesWritten, NULL);
					}
				}
				else
				{
					if (!strcmp(_cache.mnemonic, "call") || !strcmp(_cache.mnemonic, "jmp"))
					{
						TCHAR* tempCache = new TCHAR[MAX_PATH];
						ZeroMemory(tempCache, MAX_PATH);
						if (!strcmp(_cache.op_str, "eax"))
						{
							DWORD eax = 0;
							eax = getEAX(uc);
							_stprintf(tempCache, "<eax value=0x%lX />", eax);
							_cache.op_str = tempCache;
						}
						else if (!strcmp(_cache.op_str, "ebx"))
						{
							DWORD ebx = 0;
							ebx = getEBX(uc);
							_stprintf(tempCache, "<ebx value=0x%lX />", ebx);
							_cache.op_str = tempCache;
						}
						else if (!strcmp(_cache.op_str, "ecx"))
						{
							DWORD ecx = 0;
							ecx = getECX(uc);
							_stprintf(tempCache, "<ecx value=0x%lX />", ecx);
							_cache.op_str = tempCache;
						}
						else if (!strcmp(_cache.op_str, "edx"))
						{
							DWORD edx = 0;
							edx = getEDX(uc);
							_stprintf(tempCache, "<edx value=0x%lX />", edx);
							_cache.op_str = tempCache;
						}
						else if (!strcmp(_cache.op_str, "ebp"))
						{
							DWORD ebp = 0;
							ebp = getEBP(uc);
							_stprintf(tempCache, "<ebp value=0x%lX />", ebp);
							_cache.op_str = tempCache;
						}
						else if (!strcmp(_cache.op_str, "esi"))
						{
							DWORD esi = 0;
							esi = getESI(uc);
							_stprintf(tempCache, "<esi value=0x%lX />", esi);
							_cache.op_str = tempCache;
						}
						else if (!strcmp(_cache.op_str, "edi"))
						{
							DWORD edi = 0;
							edi = getEDI(uc);
							_stprintf(tempCache, "<edi value=0x%lX />", edi);
							_cache.op_str = tempCache;
						}
					}

					if (!strcmp(_cache.mnemonic, "call"))
					{
						getStack(uc, _tabSize - 1);
						WriteFile(_outFile, total_tab, _tabSize - 1, &_dwBytesWritten, NULL);
						_stprintf(buffer, "<Address value=0x%llX>\n", _cache.address);
						UcPrint(buffer);
						WriteFile(_outFile, total_tab, _tabSize - 1, &_dwBytesWritten, NULL);
						_stprintf(buffer, "\t<instruction value=\"%s %s\" />\n", _cache.mnemonic, _cache.op_str);
						UcPrint(buffer);
						WriteFile(_outFile, total_tab, _tabSize - 1, &_dwBytesWritten, NULL);
						_stprintf(buffer, "</Address>\n");
						UcPrint(buffer);

						//WriteFile(_outFile, total_tab, _tabSize, &_dwBytesWritten, NULL);
						//WriteFile(_outFile, "---------------------------------------\n", strlen("---------------------------------------\n"), &_dwBytesWritten, NULL);
					}
					else if (!strcmp(_cache.mnemonic, "jmp"))
					{
						//WriteFile(_outFile, total_tab, _tabSize, &_dwBytesWritten, NULL);
						//WriteFile(_outFile, "---------------------------------------\n", strlen("---------------------------------------\n"), &_dwBytesWritten, NULL);
						
						WriteFile(_outFile, total_tab, _tabSize, &_dwBytesWritten, NULL);
						_stprintf(buffer, "<Address value=0x%llX>\n", _cache.address);
						UcPrint(buffer);
						WriteFile(_outFile, total_tab, _tabSize, &_dwBytesWritten, NULL);
						_stprintf(buffer, "\t<instruction value=\"%s %s\" />\n", _cache.mnemonic, _cache.op_str);
						UcPrint(buffer);
						WriteFile(_outFile, total_tab, _tabSize, &_dwBytesWritten, NULL);
						_stprintf(buffer, "</Address>\n");
						UcPrint(buffer);

						//WriteFile(_outFile, total_tab, _tabSize, &_dwBytesWritten, NULL);
						//WriteFile(_outFile, "---------------------------------------\n", strlen("---------------------------------------\n"), &_dwBytesWritten, NULL);
					}
					else
					{
						WriteFile(_outFile, total_tab, _tabSize, &_dwBytesWritten, NULL);
						_stprintf(buffer, "<Address value=0x%llX>\n", _cache.address);
						UcPrint(buffer);
						WriteFile(_outFile, total_tab, _tabSize, &_dwBytesWritten, NULL);
						_stprintf(buffer, "\t<instruction value=\"%s %s\" />\n", _cache.mnemonic, _cache.op_str);
						UcPrint(buffer);
						WriteFile(_outFile, total_tab, _tabSize, &_dwBytesWritten, NULL);
						_stprintf(buffer, "</Address>\n");
						UcPrint(buffer);
					}
				}
			}

			if (!strcmp(insn[i].mnemonic, "call") || !strcmp(insn[i].mnemonic, "jmp"))
			{
				_cache.address = insn[i].address;
				_cache.mnemonic = insn[i].mnemonic;
				_cache.op_str = insn[i].op_str;
				_isCached = TRUE;
				if (!strcmp(insn[i].mnemonic, "call"))
					_tabSize++;
			}
			else
			{
				if (_printAsm )
				{
					if (strstr(insn[i].mnemonic, "ret"))
					{
						_isCached = FALSE;
						_tabSize--;
					}
					else
					{
						_cache.address = insn[i].address;
						_cache.mnemonic = insn[i].mnemonic;
						_cache.op_str = insn[i].op_str;
						_isCached = TRUE;
					}
				}
				else
				{
					if (strstr(insn[i].mnemonic, "ret"))
						_tabSize--;
					_isCached = FALSE;
				}
			}
		}
	}
	else
	{
		err = uc_emu_stop(uc);
		if (err != UC_ERR_OK)
			HandleUcErrorVoid(err);
	}
	delete[] code;
	cs_close(&cs);
}