#include "Msvcrt.h"

DWORD _argc = 0;
DWORD _argv = 0;

void getArg(uc_engine* uc, BOOL isW)
{
	uc_err err;

	//Get ProcessParam address
	DWORD processParam = getDWORD(uc, 0x6fbc+0x10);

	//Get ImagePath
	DWORD imgPath = getDWORD(uc, processParam + 0x3c);
	TCHAR imagePath[MAX_PATH] = { 0 };
	getStringW(uc, imgPath, imagePath);

	//Get CommandLine
	DWORD cmd = getDWORD(uc, processParam + 0x44);
	TCHAR cmdLine[MAX_PATH] = { 0 };
	getStringW(uc, cmd, cmdLine);

	//Return argc and argv
	if (strcmp(imagePath, cmdLine) < 0)
	{
		_argc = 2;
		if (isW)
		{
			DWORD cmdAddress = cmd + (strlen(imagePath) + 1) * 2;
			_argv = NewHeap(uc, 0xc);
			err = uc_mem_write(uc, _argv, &cmd, sizeof(DWORD));
			if (err != UC_ERR_OK)
				HandleUcErrorVoid(err);
			err = uc_mem_write(uc, _argv + 4, &cmdAddress, sizeof(DWORD));
			if (err != UC_ERR_OK)
				HandleUcErrorVoid(err);
		}
		else
		{
			DWORD argvLen = strlen(cmdLine) - strlen(imagePath) -1;
			_argv = NewHeap(uc, strlen(cmdLine));
			DWORD cmdAddress = _argv + 8;
			err = uc_mem_write(uc, _argv, &cmdAddress, sizeof(DWORD));
			if (err != UC_ERR_OK)
				HandleUcErrorVoid(err);
			err = uc_mem_write(uc, cmdAddress, imagePath, strlen(imagePath));
			if (err != UC_ERR_OK)
				HandleUcErrorVoid(err);
			cmdAddress += strlen(imagePath) + 1;
			err = uc_mem_write(uc, _argv + 4, &cmdAddress, sizeof(DWORD));
			if (err != UC_ERR_OK)
				HandleUcErrorVoid(err);
			err = uc_mem_write(uc, cmdAddress, (TCHAR*)(cmdLine + strlen(imagePath) + 1),  argvLen);
			if (err != UC_ERR_OK)
				HandleUcErrorVoid(err);
		}
	}
	else
	{
		_argc = 1;
		if (isW)
		{
			DWORD cmdAddress = cmd;
			_argv = NewHeap(uc, 0xc);
			err = uc_mem_write(uc, _argv, &cmdAddress, sizeof(DWORD));
			if (err != UC_ERR_OK)
				HandleUcErrorVoid(err);
			err = uc_mem_write(uc, _argv + 4, &cmdAddress, sizeof(DWORD));
			if (err != UC_ERR_OK)
				HandleUcErrorVoid(err);
		}
		else
		{
			DWORD argvLen = strlen(cmdLine);
			_argv = NewHeap(uc, argvLen);
			DWORD cmdAddress = _argv + 8;
			err = uc_mem_write(uc, _argv, &cmdAddress, sizeof(DWORD));
			if (err != UC_ERR_OK)
				HandleUcErrorVoid(err);
			err = uc_mem_write(uc, _argv + 4, &cmdAddress, sizeof(DWORD));
			if (err != UC_ERR_OK)
				HandleUcErrorVoid(err);
			err = uc_mem_write(uc, cmdAddress, cmdLine, argvLen);
			if (err != UC_ERR_OK)
				HandleUcErrorVoid(err);
		}
	}
}

void Emu__acrt_iob_func(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD retVal = 0;

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
}

void Emu__getmainargs(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD _Argc = 0;
	DWORD _Argv = 0;
	DWORD _Env = 0;
	DWORD _DoWildCard = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get arguments
	if (_argc == 0)
		getArg(uc);

	//Get _Argc
	_Argc = getDWORD(uc, sp);
	err = uc_mem_write(uc, _Argc, &_argc, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Get _Argv
	_Argv = getDWORD(uc, sp + 4);
	err = uc_mem_write(uc, _Argv, &_argv, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Get _Env
	_Env = getDWORD(uc, sp + 8);

	//Get _DoWildCard
	_DoWildCard = getDWORD(uc, sp + 12);

	//Print argument
	_stprintf(buffer, "(_Argc=0x%lX, _Argv=0x%lX, _Env=0x%lX, _DoWildCard=0x%lX)", _Argc, _Argv, _Env, _DoWildCard);
	UcPrintAPIArg(buffer, tab);

	DWORD retVal = 0;
	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
}

void Emu__p___argc(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD sp = 0;

	//Get arguments
	if (_argc == 0)
		getArg(uc);

	//Push argc in to stack
	sp = _stackAddr - _stackSize + 4;
	err = uc_mem_write(uc, sp, &_argc, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
}

void Emu__p___argv(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD sp = 0;

	//Get arguments
	if (_argc == 0)
		getArg(uc);

	//Push argc in to stack
	sp = _stackAddr - _stackSize + 8;
	err = uc_mem_write(uc, sp, &_argv, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
}

void Emu__p___initenv(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
	
	sp -= 4;

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
}

void Emu__p___wargc(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Get arguments
	if (_argc == 0)
		getArg(uc, TRUE);

	//Push argc in to stack
	sp = _stackAddr - _stackSize + 4;
	err = uc_mem_write(uc, sp, &_argc, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
}

void Emu__p___wargv(uc_engine* uc, DWORD tab)
{
	uc_err err;

	//Get arguments
	if (_argc == 0)
		getArg(uc, TRUE);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &_argv);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
}

void Emu__stdio_common_vfprintf(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD pFormat = 0;
	TCHAR format[MAX_PATH] = { 0 };
	DWORD spArg = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get pFormat
	pFormat = getDWORD(uc, sp + 12);
	getString(uc, pFormat, format);

	//Get spArg
	spArg = getDWORD(uc, sp + 20);

	Emu_printf(uc, tab, format, spArg);
}

void Emu__wgetmainargs(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get arguments
	if (_argc == 0)
		getArg(uc, TRUE);

	err = uc_mem_write(uc, sp, &_argc, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	err = uc_mem_write(uc, sp + 4, &_argv, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	DWORD retVal = 0;
	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
}

void Emu_exit(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD uExitCode = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get uExitCode
	uExitCode = getDWORD(uc, sp);

	//Print argument
	_stprintf(buffer, "(uExitCode=0x%lX)\n", uExitCode);
	UcPrintAPIArg(buffer, tab);

	err = uc_emu_stop(uc);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
}

void Emuexit(uc_engine* uc, DWORD tab)
{
	Emu_exit(uc, tab);
}

void Emu_printf(uc_engine* uc, DWORD tab, TCHAR format[], DWORD spArg)
{
	uc_err err;
	TCHAR tmp[MAX_PATH] = { 0 };
	DWORD stackValue = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	TCHAR* character = format;
	TCHAR* pFormat = format;
	TCHAR* base = pFormat;

	strcat(buffer, "(\"");

	if (strstr(pFormat, "%") == NULL)
		strcat(buffer, format);
	else
	{	
		while ((pFormat = strstr(pFormat, "%")) != NULL)
		{
			while (character < pFormat)
			{
				TCHAR* c = new TCHAR[2];
				ZeroMemory(c, 2);
				_stprintf(c, "%c", *character);
				strcat(buffer, c);
				character++;
				delete[] c;
			}

			pFormat++;
			stackValue = getDWORD(uc, spArg);
			switch (*pFormat)
			{
			case 's':
				getString(uc, stackValue, tmp);
				strcat(buffer, tmp);
				ZeroMemory(tmp, strlen(tmp));
				break;
			default:
				_stprintf(tmp, "0x%lX", stackValue);
				strcat(buffer, tmp);
				ZeroMemory(tmp, strlen(tmp));
				break;
			}

			pFormat++;
			character = pFormat;
			spArg += 4;
		}
		if (character - base < strlen(format))
			strcat(buffer, character);
	}

	//Print argument
	strcat(buffer, "\")\n");
	DWORD retVal = strlen(buffer) - 5;
	UcPrintAPIArg(buffer, tab);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
}

void Emuprintf(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD pFormat = 0;
	TCHAR format[MAX_PATH] = { 0 };
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get pFormat
	pFormat = getDWORD(uc, sp);
	getString(uc, pFormat, format);

	sp += 4;

	Emu_printf(uc, tab, format, sp);
}