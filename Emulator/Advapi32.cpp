#include "Advapi32.h"

void EmuRegCloseKey(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hKey = 0;
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hKey
	hKey = getDWORD(uc, sp);

	//Print argument
	_stprintf(buffer, "(hKey=0x%lX)\n", hKey);
	UcPrintAPIArg(buffer, tab);

	//Call RegCloseKey
	DWORD retVal = (DWORD)RegCloseKey((HKEY)hKey);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 1;
}

void EmuRegCreateKey(uc_engine* uc, DWORD tab, DWORD hKey, TCHAR subKey[], DWORD phkResult)
{
	uc_err err;
	HKEY pResult;
	TCHAR key[MAX_PATH] = { 0 };
	TCHAR buffer[MAX_PATH] = { 0 };

	switch (hKey)
	{
		case 0x80000000:
			strcat(key, "HKEY_CLASSES_ROOT");
			break;
		case 0x80000001:
			strcat(key, "HKEY_CURRENT_USER");
			break;
		case 0x80000002:
			strcat(key, "HKEY_LOCAL_MACHINE");
			break;
		case 0x80000003:
			strcat(key, "HKEY_USERS");
			break;
		default:
			_stprintf(key, "0x%lX", hKey);
			break;
	}

	//Print arguments
	_stprintf(buffer, "(hKey=%s, lpSubKey=&\"%s\", phkResult=0x%lX)\n", key, subKey, phkResult);
	UcPrintAPIArg(buffer, tab);

	//Call RegCreateKey
	DWORD retVal = 0;
	if (!strcmp(subKey, ""))
		retVal = (DWORD)RegCreateKey((HKEY)hKey, NULL, &pResult);
	else
		retVal = (DWORD)RegCreateKey((HKEY)hKey, subKey, &pResult);
	 
	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Write phkReSult
	err = uc_mem_write(uc, phkResult, (DWORD *)&pResult, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 3;
}

void EmuRegCreateKeyA(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hKey = 0;
	DWORD lpSubKey = 0;
	DWORD phkResult = 0;
	TCHAR subKey[MAX_PATH] = { 0 };
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hKey
	hKey = getDWORD(uc, sp);

	//Get lpSubKey
	lpSubKey = getDWORD(uc, sp + 4);
	getString(uc, lpSubKey, subKey);

	//Get phkResult
	phkResult = getDWORD(uc, sp + 8);

	EmuRegCreateKey(uc, tab, hKey, subKey, phkResult);
}

void EmuRegCreateKeyW(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hKey = 0;
	DWORD lpSubKey = 0;
	DWORD phkResult = 0;
	TCHAR subKey[MAX_PATH] = { 0 };
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hKey
	hKey = getDWORD(uc, sp);

	//Get lpSubKey
	lpSubKey = getDWORD(uc, sp + 4);
	getStringW(uc, lpSubKey, subKey);

	//Get phkResult
	phkResult = getDWORD(uc, sp + 8);

	EmuRegCreateKey(uc, tab, hKey, subKey, phkResult);
}

void EmuRegDeleteKey(uc_engine* uc, DWORD tab, DWORD hKey, TCHAR subKey[])
{
	uc_err err;
	TCHAR key[MAX_PATH] = { 0 };
	TCHAR buffer[MAX_PATH] = { 0 };

	switch (hKey)
	{
	case 0x80000000:
		strcat(key, "HKEY_CLASSES_ROOT");
		break;
	case 0x80000001:
		strcat(key, "HKEY_CURRENT_USER");
		break;
	case 0x80000002:
		strcat(key, "HKEY_LOCAL_MACHINE");
		break;
	case 0x80000003:
		strcat(key, "HKEY_USERS");
		break;
	default:
		_stprintf(key, "0x%lX", hKey);
		break;
	}

	//Print arguments
	_stprintf(buffer, "(hKey=%s, lpSubKey=&\"%s\")\n", key, subKey);
	UcPrintAPIArg(buffer, tab);

	//Call RegDeleteKey
	DWORD retVal = (DWORD)RegDeleteKey((HKEY)hKey, subKey);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 2;
}

void EmuRegDeleteKeyA(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hKey = 0;
	DWORD lpSubKey = 0;
	TCHAR subKey[MAX_PATH] = { 0 };
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hKey
	hKey = getDWORD(uc, sp);

	//Get lpSubKey
	lpSubKey = getDWORD(uc, sp + 4);
	getString(uc, lpSubKey, subKey);

	EmuRegDeleteKey(uc, tab, hKey, subKey);
}

void EmuRegDeleteKeyW(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hKey = 0;
	DWORD lpSubKey = 0;
	DWORD phkResult = 0;
	TCHAR subKey[MAX_PATH] = { 0 };
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hKey
	hKey = getDWORD(uc, sp);

	//Get lpSubKey
	lpSubKey = getDWORD(uc, sp + 4);
	getStringW(uc, lpSubKey, subKey);

	EmuRegDeleteKey(uc, tab, hKey, subKey);
}

void EmuRegDeleteValue(uc_engine* uc, DWORD tab, DWORD hKey, TCHAR valueName[])
{
	uc_err err;
	TCHAR key[MAX_PATH] = { 0 };
	TCHAR buffer[MAX_PATH] = { 0 };

	switch (hKey)
	{
	case 0x80000000:
		strcat(key, "HKEY_CLASSES_ROOT");
		break;
	case 0x80000001:
		strcat(key, "HKEY_CURRENT_USER");
		break;
	case 0x80000002:
		strcat(key, "HKEY_LOCAL_MACHINE");
		break;
	case 0x80000003:
		strcat(key, "HKEY_USERS");
		break;
	default:
		_stprintf(key, "0x%lX", hKey);
		break;
	}

	//Print arguments
	_stprintf(buffer, "(hKey=%s, lpValueName=&\"%s\")\n", key, valueName);
	UcPrintAPIArg(buffer, tab);

	//Call RegDeleteValue
	DWORD retVal = (DWORD)RegDeleteValue((HKEY)hKey, valueName);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 2;
}

void EmuRegDeleteValueA(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hKey = 0;
	DWORD lpValueName = 0;
	TCHAR valueName[MAX_PATH] = { 0 };
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hKey
	hKey = getDWORD(uc, sp);

	//Get lpValueName
	lpValueName = getDWORD(uc, sp + 4);
	getString(uc, lpValueName, valueName);

	EmuRegDeleteValue(uc, tab, hKey, valueName);
}

void EmuRegDeleteValueW(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hKey = 0;
	DWORD lpValueName = 0;
	TCHAR valueName[MAX_PATH] = { 0 };
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hKey
	hKey = getDWORD(uc, sp);

	//Get lpValueName
	lpValueName = getDWORD(uc, sp + 4);
	getStringW(uc, lpValueName, valueName);

	EmuRegDeleteValue(uc, tab, hKey, valueName);
}