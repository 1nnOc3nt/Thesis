#include "Utils.h"

void cleanupStack(uc_engine* uc, DWORD number)
{
	uc_err err;
	DWORD sp = 0;
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += (0x4 * number);

	err = uc_reg_write(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
}

void getString(uc_engine* uc, DWORD address, TCHAR cString[])
{
	uc_err err;
	TCHAR character = 0;
	DWORD count = 0;

	while (TRUE)
	{
		err = uc_mem_read(uc, address, &character, 1);
		if (err != UC_ERR_OK)
		{
			memset(cString, 0, MAX_PATH);
			return;
		}

		if (character == 0)
			break;
		else if (character < 32 || character >= 127)
		{
			memset(cString, 0, MAX_PATH);
			return;
		}

		if (count >= MAX_PATH)
			break;

		strncat(cString, &character, 1);
		address++;
		count++;
	}
}

void getStringW(uc_engine* uc, DWORD address, TCHAR cString[])
{
	uc_err err;
	TCHAR character = 0;
	TCHAR characterNull = 0;
	DWORD count = 0;

	while (TRUE)
	{
		err = uc_mem_read(uc, address, &character, 1);
		if (err != UC_ERR_OK)
		{
			memset(cString, 0, MAX_PATH);
			return;
		}

		err = uc_mem_read(uc, address+1, &characterNull, 1);
		if (err != UC_ERR_OK)
		{
			memset(cString, 0, MAX_PATH);
			return;
		}

		if (character == 0 && characterNull == 0)
			break;
		else if (character < 32 || character >= 127 || characterNull != 0)
		{
			memset(cString, 0, MAX_PATH);
			return;
		}

		if (count >= MAX_PATH)
			break;

		strncat(cString, &character, 1);
		address += 2;
		count++;
	}
}

DWORD getDWORD(uc_engine* uc, DWORD address)
{
	uc_err err;
	DWORD number = 0;
	err = uc_mem_read(uc, address, &number, sizeof(DWORD));
	if (err != UC_ERR_OK)
		return 0;
	return number;
}

void getStack(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_tprintf("-----------------Stack-----------------\n");

	for (size_t i = 0; i < 5; i++)
	{
		TCHAR stackValueString[MAX_PATH] = { 0 };
		TCHAR stackValueStringW[MAX_PATH] = { 0 };
		DWORD stackValue = 0;
		DWORD dwStackValue = 0;
		
		stackValue = getDWORD(uc, sp);

		if (stackValue != 0)
		{
			dwStackValue = getDWORD(uc, stackValue);
			getString(uc, stackValue, stackValueString);
			getStringW(uc, stackValue, stackValueStringW);
		}

		if (tab > 0)
			for (int j = 0; j < tab; j++)
				_tprintf("   |   ");

		if (strcmp(stackValueString, ""))
			_tprintf("Arg[%d]: 0x%lX  -> %s\n", i + 1, stackValue, stackValueString);
		else if (strcmp(stackValueStringW, ""))
			_tprintf("Arg[%d]: 0x%lX -> 0x%lX -> %s\n", i + 1, stackValue, dwStackValue, stackValueStringW);
		else if (dwStackValue != 0)
		{
			getString(uc, dwStackValue, stackValueString);
			getStringW(uc, dwStackValue, stackValueStringW);
			if (strcmp(stackValueString, ""))
				_tprintf("Arg[%d]: 0x%lX -> 0x%lX -> %s\n", i + 1, stackValue, dwStackValue, stackValueString);
			else if (strcmp(stackValueStringW, ""))
				_tprintf("Arg[%d]: 0x%lX -> 0x%lX -> %s\n", i + 1, stackValue, dwStackValue, stackValueStringW);
			else
				_tprintf("Arg[%d]: 0x%lX -> 0x%lX\n", i + 1, stackValue, dwStackValue);
		}
		else
			_tprintf("Arg[%d]: 0x%lX\n", i + 1, stackValue);
		
		sp += 4;
	}
	if (tab > 0)
	{
		for (int j = 0; j < tab; j++)
			_tprintf("   |   ");
	}
}