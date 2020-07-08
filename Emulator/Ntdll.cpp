#include "Ntdll.h"

void Emumemcmp(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD buffer1 = 0;
	DWORD buffer2 = 0;
	DWORD count = 0;
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get buffer1
	buffer1 = getDWORD(uc, sp);

	//Get buffer2
	buffer2 = getDWORD(uc, sp + 4);

	//Get count
	count = getDWORD(uc, sp + 8);

	//Print arguments
	_stprintf(buffer, "(buffer1=0x%lX, buffer2=0x%lX, count=0x%lX)\n", buffer1, buffer2, count);
	UcPrintAPIArg(buffer, tab);

	//Read all buffers
	TCHAR* ptr1 = new TCHAR[count];
	TCHAR* ptr2 = new TCHAR[count];
	err = uc_mem_read(uc, buffer1, ptr1, count);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	err = uc_mem_read(uc, buffer2, ptr2, count);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Call memcmp
	DWORD retVal = memcmp(ptr1, ptr2, count);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 0;
	delete[] ptr1;
	delete[] ptr2;
}

void Emumemcpy(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD dest = 0;
	DWORD src = 0;
	DWORD count = 0;
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get dest
	dest = getDWORD(uc, sp);

	//Get src
	src = getDWORD(uc, sp + 4);

	//Get count
	count = getDWORD(uc, sp + 8);

	//Print arguments
	_stprintf(buffer, "(dest=0x%lX, src=0x%lX, count=0x%lX)\n", dest, src, count);
	UcPrintAPIArg(buffer, tab);

	//Read src
	TCHAR* pDest = new TCHAR[count];
	TCHAR* pSrc = new TCHAR[count];
	err = uc_mem_read(uc, src, pSrc, count);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Call memcpy
	DWORD retVal = (DWORD)memcpy(pDest, pSrc, count);

	err = uc_mem_write(uc, dest, pDest, count);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 0;
	delete[] pDest;
	delete[] pSrc;
}

void Emumemset(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD dest = 0;
	DWORD c = 0;
	DWORD count = 0;
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get dest
	dest = getDWORD(uc, sp);

	//Get c
	c = getDWORD(uc, sp + 4);

	//Get count
	count = getDWORD(uc, sp + 8);

	//Print arguments
	_stprintf(buffer, "(dest=0x%lX, c=0x%lX, count=0x%lX)\n", dest, c, count);
	UcPrintAPIArg(buffer, tab);

	//Prepare temp buffer for memset
	TCHAR* pDest = new TCHAR[count];

	//Call memset
	DWORD retVal = (DWORD)memset(pDest, c, count);

	err = uc_mem_write(uc, dest, pDest, count);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 0;
	delete[] pDest;
}

void Emustrcat(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD strDestination = 0;
	DWORD strSource = 0;
	TCHAR dest[MAX_PATH * 2] = { 0 };
	TCHAR src[MAX_PATH * 2] = { 0 };
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get strDestination
	strDestination = getDWORD(uc, sp);
	getString(uc, strDestination, dest);

	//Get strSource
	strSource = getDWORD(uc, sp + 4);
	getString(uc, strSource, src);

	//Print arguments
	_stprintf(buffer, "(strDestination=&\"%s\", strSource=&\"%s\")\n", dest, src);
	UcPrintAPIArg(buffer, tab);

	//Call strcat
	DWORD retVal = (DWORD)strcat(dest, src);

	err = uc_mem_write(uc, strDestination, dest, strlen(dest));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 0;
}

void Emustrcmp(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD strDestination = 0;
	DWORD strSource = 0;
	TCHAR dest[MAX_PATH * 2] = { 0 };
	TCHAR src[MAX_PATH * 2] = { 0 };
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get strDestination
	strDestination = getDWORD(uc, sp);
	getString(uc, strDestination, dest);

	//Get strSource
	strSource = getDWORD(uc, sp + 4);
	getString(uc, strSource, src);

	//Print arguments
	_stprintf(buffer, "(strDestination=&\"%s\", strSource=&\"%s\")\n", dest, src);
	UcPrintAPIArg(buffer, tab);

	//Call strcmp
	DWORD retVal = strcmp(dest, src);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 0;
}

void Emustrcpy(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD strDestination = 0;
	DWORD strSource = 0;
	TCHAR dest[MAX_PATH * 2] = { 0 };
	TCHAR src[MAX_PATH * 2] = { 0 };
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get strDestination
	strDestination = getDWORD(uc, sp);

	//Get strSource
	strSource = getDWORD(uc, sp + 4);
	getString(uc, strSource, src);

	//Print arguments
	_stprintf(buffer, "(strDestination=0x%lX, strSource=&\"%s\")\n", strDestination, src);
	UcPrintAPIArg(buffer, tab);

	//Call strcpy
	DWORD retVal = (DWORD)strcpy(dest, src);

	err = uc_mem_write(uc, strDestination, dest, strlen(dest));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 0;
}

void Emustrlen(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD strBuf = 0;
	TCHAR buf[MAX_PATH * 2] = { 0 };
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get strBuf
	strBuf = getDWORD(uc, sp);
	getString(uc, strBuf, buf);

	//Print arguments
	_stprintf(buffer, "(strBuf=&\"%s\")\n", buf);
	UcPrintAPIArg(buffer, tab);

	//Call strlen
	DWORD retVal = (DWORD)strlen(buf);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 0;
}

void Emuwcscat(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD strDestination = 0;
	DWORD strSource = 0;
	DWORD count = 0;
	TCHAR dest[MAX_PATH * 2] = { 0 };
	TCHAR src[MAX_PATH * 2] = { 0 };
	TCHAR pDest[MAX_PATH * 2] = { 0 };
	TCHAR pSrc[MAX_PATH * 2] = { 0 };
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get strDestination
	strDestination = getDWORD(uc, sp);
	getStringW(uc, strDestination, dest);
	count = strlen(dest);
	err = uc_mem_read(uc, strDestination, pDest, count * 2);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Get strSource
	strSource = getDWORD(uc, sp + 4);
	getStringW(uc, strSource, src);
	count = strlen(src);
	err = uc_mem_read(uc, strSource, pSrc, count * 2);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Print arguments
	_stprintf(buffer, "(strDestination=&\"%s\", strSource=&\"%s\")\n", dest, src);
	UcPrintAPIArg(buffer, tab);

	//Call wcscat
	DWORD retVal = (DWORD)wcscat((WCHAR*)pDest, (WCHAR*)pSrc);

	err = uc_mem_write(uc, strDestination, pDest, wcslen((WCHAR*)pDest));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 0;
}

void Emuwcscmp(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD strDestination = 0;
	DWORD strSource = 0;
	TCHAR dest[MAX_PATH * 2] = { 0 };
	TCHAR src[MAX_PATH * 2] = { 0 };
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get strDestination
	strDestination = getDWORD(uc, sp);
	getStringW(uc, strDestination, dest);

	//Get strSource
	strSource = getDWORD(uc, sp + 4);
	getStringW(uc, strSource, src);

	//Print arguments
	_stprintf(buffer, "(strDestination=&\"%s\", strSource=&\"%s\")\n", dest, src);
	UcPrintAPIArg(buffer, tab);

	//Call strcmp
	DWORD retVal = strcmp(dest, src);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 0;
}

void Emuwcscpy(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD strDestination = 0;
	DWORD strSource = 0;
	DWORD count = 0;
	TCHAR src[MAX_PATH * 2] = { 0 };
	TCHAR pDest[MAX_PATH * 2] = { 0 };
	TCHAR pSrc[MAX_PATH * 2] = { 0 };
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get strDestination
	strDestination = getDWORD(uc, sp);

	//Get strSource
	strSource = getDWORD(uc, sp + 4);
	getStringW(uc, strSource, src);
	count = strlen(src);
	err = uc_mem_read(uc, strSource, pSrc, count * 2);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Print arguments
	_stprintf(buffer, "(strDestination=0x%lX, strSource=&\"%s\")\n", strDestination, src);
	UcPrintAPIArg(buffer, tab);

	//Call wcscpy
	DWORD retVal = (DWORD)wcscpy((WCHAR*)pDest, (WCHAR*)pSrc);

	err = uc_mem_write(uc, strDestination, pDest, wcslen((WCHAR*)pDest));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 0;
}

void Emuwcslen(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD strBuf = 0;
	TCHAR buf[MAX_PATH * 2] = { 0 };
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get strBuf
	strBuf = getDWORD(uc, sp);
	getStringW(uc, strBuf, buf);

	//Print arguments
	_stprintf(buffer, "(strBuf=&\"%s\")\n", buf);
	UcPrintAPIArg(buffer, tab);

	//Call strlen
	DWORD retVal = (DWORD)strlen(buf);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 0;
}