#include "TIB.h"

DWORD _lastStructureAddress = 0x6000;
DWORD _LDRHead = 0;
DWORD _lastLDRDataAddress = 0;
DWORD _LDRDataSize = 0;

void InitTIB(uc_engine* uc, DWORD exceptionList, DWORD stackBase, DWORD stackLimit, DWORD TIBAddress, DWORD PEBAddress)
{
	uc_err err;

	err = uc_mem_write(uc, TIBAddress, &exceptionList, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	err = uc_mem_write(uc, TIBAddress + 0x4, &stackBase, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	err = uc_mem_write(uc, TIBAddress + 0x8, &stackLimit, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	err = uc_mem_write(uc, TIBAddress + 0x18, &TIBAddress, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	err = uc_mem_write(uc, TIBAddress + 0x30, &PEBAddress, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
}

DWORD getTIBSize()
{
	return 0xfbc;
}

void InitProcessParam(uc_engine* uc, DWORD address, TCHAR* imagePath, TCHAR* arg)
{
	uc_err err;
	WORD len = 0;
	WORD maxLen = 0;
	DWORD stringAddress = 0;
	TCHAR commandLine[MAX_PATH * 2] = { 0 };
	WCHAR imagePathW[MAX_PATH] = { 0 };
	WCHAR commandLineW[MAX_PATH] = { 0 };

	stringAddress = address + 0x298;

	//ImagePath
	len = mbstowcs(imagePathW, imagePath, strlen(imagePath));
	maxLen = len + 4;

	err = uc_mem_write(uc, address + 0x38, &len, sizeof(WORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	err = uc_mem_write(uc, address +  0x3a, &maxLen, sizeof(WORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	err = uc_mem_write(uc, address + 0x3c, &stringAddress, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	err = uc_mem_write(uc, stringAddress, imagePathW, (len+1)*2);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	stringAddress += maxLen*2;


	//CommandLine
	if (arg == NULL)
	{
		err = uc_mem_write(uc, stringAddress, imagePathW, (len+1)*2);
		if (err != UC_ERR_OK)
			HandleUcErrorVoid(err);
	}
	else
	{
		sprintf(commandLine, "%s %s", imagePath, arg);
		len = mbstowcs(commandLineW, commandLine, strlen(commandLine));
		maxLen = len + 4;

		err = uc_mem_write(uc, address + 0x40, &len, sizeof(WORD));
		if (err != UC_ERR_OK)
			HandleUcErrorVoid(err);

		err = uc_mem_write(uc, address + 0x42, &maxLen, sizeof(WORD));
		if (err != UC_ERR_OK)
			HandleUcErrorVoid(err);

		err = uc_mem_write(uc, address + 0x44, &stringAddress, sizeof(DWORD));
		if (err != UC_ERR_OK)
			HandleUcErrorVoid(err);

		err = uc_mem_write(uc, stringAddress, commandLine, (len+1)*2);
		if (err != UC_ERR_OK)
			HandleUcErrorVoid(err);
	}
}

void InitPEB(uc_engine* uc, DWORD PEBAddress, DWORD LDRAddress, DWORD processParam, DWORD processHeap)
{
	uc_err err;

	err = uc_mem_write(uc, PEBAddress + 0xc, &LDRAddress, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	err = uc_mem_write(uc, PEBAddress + 0x10, &processParam, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	err = uc_mem_write(uc, PEBAddress + 0x18, &processHeap, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
}

DWORD getPEBSize()
{
	return 0x230;
}

void InitLDR(uc_engine* uc, DWORD LDRAddress, DWORD LDRHeadAddress)
{
	uc_err err;

	err = uc_mem_write(uc, LDRAddress + 0xc, &LDRHeadAddress, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	err = uc_mem_write(uc, LDRAddress + 0x14, &LDRHeadAddress, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	err = uc_mem_write(uc, LDRAddress + 0x1c, &LDRHeadAddress, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
}

DWORD getLDRSize()
{
	return 0x30;
}

void AddToLDR(uc_engine* uc, DWORD LDRDataAddress, DWORD dllBase, DWORD entryPoint, DWORD sizeOfImage, TCHAR* fullDllName, TCHAR* baseDllName)
{
	uc_err err;
	WORD nameLen = 0;
	WORD maxNameLen = 0;
	DWORD dllNameAddress = 0;
	WCHAR fullDllNameW[MAX_PATH] = { 0 };
	WCHAR baseDllNameW[MAX_PATH] = { 0 };

	_LDRDataSize = 0;

	//Flink
	err = uc_mem_write(uc, LDRDataAddress, &_LDRHead, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	err = uc_mem_write(uc, LDRDataAddress + 0x8, &_LDRHead, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	/*err = uc_mem_write(uc, LDRDataAddress + 0x10, &_LDRHead, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);*/

	//Blink
	err = uc_mem_write(uc, LDRDataAddress + 0x4, &_lastLDRDataAddress, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	err = uc_mem_write(uc, LDRDataAddress + 0xc, &_lastLDRDataAddress, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	/*err = uc_mem_write(uc, LDRDataAddress + 0x14, &_lastLDRDataAddress, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);*/

	//Update LDRHead Blink
	err = uc_mem_write(uc, _LDRHead + 0x4, &LDRDataAddress, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	err = uc_mem_write(uc, _LDRHead + 0xc, &LDRDataAddress, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	/*err = uc_mem_write(uc, _LDRHead + 0x14, &LDRDataAddress, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);*/

	//Update last LDRData Flink
	err = uc_mem_write(uc, _lastLDRDataAddress, &LDRDataAddress, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	err = uc_mem_write(uc, _lastLDRDataAddress + 0x8, &LDRDataAddress, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	/*err = uc_mem_write(uc, _lastLDRDataAddress + 0x10, &LDRDataAddress, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);*/

	//DllBase
	err = uc_mem_write(uc, LDRDataAddress + 0x10, &dllBase, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//EntryPoint
	err = uc_mem_write(uc, LDRDataAddress + 0x14, &entryPoint, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//SizeOfImage
	err = uc_mem_write(uc, LDRDataAddress + 0x18, &sizeOfImage, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
	
	dllNameAddress = LDRDataAddress + 0x78;

	//FullDllName
	if (fullDllName != NULL)
	{
		nameLen = mbstowcs(fullDllNameW, fullDllName, strlen(fullDllName));
		nameLen = nameLen * 2;
		maxNameLen = nameLen + 2;

		err = uc_mem_write(uc, LDRDataAddress + 0x1c, &nameLen, sizeof(WORD));
		if (err != UC_ERR_OK)
			HandleUcErrorVoid(err);

		err = uc_mem_write(uc, LDRDataAddress + 0x1e, &maxNameLen, sizeof(WORD));
		if (err != UC_ERR_OK)
			HandleUcErrorVoid(err);

		err = uc_mem_write(uc, LDRDataAddress + 0x20, &dllNameAddress, sizeof(DWORD));
		if (err != UC_ERR_OK)
			HandleUcErrorVoid(err);

		err = uc_mem_write(uc, dllNameAddress, fullDllNameW, nameLen);
		if (err != UC_ERR_OK)
			HandleUcErrorVoid(err);

		dllNameAddress += maxNameLen;
	}

	//BaseDllName
	if (baseDllName != NULL)
	{
		nameLen = mbstowcs(baseDllNameW, baseDllName, strlen(baseDllName));
		nameLen = nameLen * 2;
		maxNameLen = nameLen + 2;

		err = uc_mem_write(uc, LDRDataAddress + 0x24, &nameLen, sizeof(WORD));
		if (err != UC_ERR_OK)
			HandleUcErrorVoid(err);

		err = uc_mem_write(uc, LDRDataAddress + 0x26, &maxNameLen, sizeof(WORD));
		if (err != UC_ERR_OK)
			HandleUcErrorVoid(err);

		err = uc_mem_write(uc, LDRDataAddress + 0x28, &dllNameAddress, sizeof(DWORD));
		if (err != UC_ERR_OK)
			HandleUcErrorVoid(err);

		err = uc_mem_write(uc, dllNameAddress, baseDllNameW, nameLen);
		if (err != UC_ERR_OK)
			HandleUcErrorVoid(err);

		_LDRDataSize = dllNameAddress + maxNameLen - LDRDataAddress;
	}

	_lastLDRDataAddress = LDRDataAddress;
}

DWORD getLDRDataSize()
{
	if (_LDRDataSize)
		return _LDRDataSize;
	return 0x78;
}