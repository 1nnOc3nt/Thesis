#include "Kernel.h"

void EmuCloseHandle(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hObject = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hObject
	hObject = getDWORD(uc, sp);

	//Print argument
	_stprintf(buffer, "(hObject=0x%lX)\n", hObject);
	UcPrintAPIArg(buffer, tab);

	//Call CloseHandle and get return value
	BOOL retVal = CloseHandle((HANDLE)hObject);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 1;
}

void EmuConnectNamedPipe(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hNamedPipe = 0;
	DWORD lpOverlapped = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hNamedPipe
	hNamedPipe = getDWORD(uc, sp);

	//Get lpOverlapped
	lpOverlapped = getDWORD(uc, sp + 4);

	//Print arguments
	_stprintf(buffer, "(hNamedPipe=0x%lX, lpOverlapped=0x%lX)\n", hNamedPipe, lpOverlapped);
	UcPrintAPIArg(buffer, tab);

	//Call ConnectNamedPipe and get return value
	BOOL retVal = ConnectNamedPipe((HANDLE)hNamedPipe, NULL);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 2;
}

void EmuCopyFile(uc_engine* uc, DWORD tab, TCHAR existingFileName[], TCHAR newFileName[], BOOL bFailIfExists)
{
	uc_err err;
	TCHAR buffer[MAX_PATH] = { 0 };
	//Print arguments
	if (bFailIfExists)
	{
		_stprintf(buffer, "(lpExistingFileName=&\"%s\", lpNewFileName=&\"%s\", bFailIfExists=TRUE)\n", existingFileName, newFileName);
		UcPrintAPIArg(buffer, tab);
	}
	else
	{
		_stprintf(buffer, "(lpExistingFileName=&\"%s\", lpNewFileName=&\"%s\", bFailIfExists=FALSE)\n", existingFileName, newFileName);
		UcPrintAPIArg(buffer, tab);
	}

	//Call CopyFile and get return value
	BOOL retVal = CopyFile(existingFileName, newFileName, bFailIfExists);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 3;
}

void EmuCopyFileA(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpExistingFileName = 0;
	DWORD lpNewFileName = 0;
	TCHAR existingFileName[MAX_PATH] = { 0 };
	TCHAR newFileName[MAX_PATH] = { 0 };
	BOOL bFailIfExists = FALSE;
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpExistingFileName
	lpExistingFileName = getDWORD(uc, sp);
	getString(uc, lpExistingFileName, existingFileName);

	//Get lpExistingFileName
	lpNewFileName = getDWORD(uc, sp + 4);
	getString(uc, lpNewFileName, newFileName);

	//Get bFailIfExists
	bFailIfExists = getDWORD(uc, sp + 8);

	EmuCopyFile(uc, tab, existingFileName, newFileName, bFailIfExists);
}

void EmuCopyFileW(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpExistingFileName = 0;
	DWORD lpNewFileName = 0;
	TCHAR existingFileName[MAX_PATH] = { 0 };
	TCHAR newFileName[MAX_PATH] = { 0 };
	BOOL bFailIfExists = FALSE;
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpExistingFileName
	lpExistingFileName = getDWORD(uc, sp);
	getStringW(uc, lpExistingFileName, existingFileName);

	//Get lpExistingFileName
	lpNewFileName = getDWORD(uc, sp + 4);
	getStringW(uc, lpNewFileName, newFileName);

	//Get bFailIfExists
	bFailIfExists = getDWORD(uc, sp + 8);

	EmuCopyFile(uc, tab, existingFileName, newFileName, bFailIfExists);
}

void EmuCreateDirectory(uc_engine* uc, DWORD tab, TCHAR pathName[], DWORD lpSecurityAttributes)
{
	uc_err err;
	TCHAR buffer[MAX_PATH] = { 0 };
	//Print arguments
	_stprintf(buffer, "(lpPathName=&\"%s\", lpSecurityAttributes=0x%lX)\n", pathName, lpSecurityAttributes);
	UcPrintAPIArg(buffer, tab);

	//Call CreateDirectory and get return value
	BOOL retVal = CreateDirectory(pathName, NULL);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 2;
}

void EmuCreateDirectoryA(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpPathName = 0;
	DWORD lpSecurityAttributes = 0;
	TCHAR pathName[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpPathName
	lpPathName = getDWORD(uc, sp);
	getString(uc, lpPathName, pathName);

	//Get lpSecurityAttributes
	lpSecurityAttributes = getDWORD(uc, sp + 4);

	EmuCreateDirectory(uc, tab, pathName, lpSecurityAttributes);
}

void EmuCreateDirectoryEx(uc_engine* uc, DWORD tab, TCHAR templateDirectory[], TCHAR newDirectory[], DWORD lpSecurityAttributes)
{
	uc_err err;
	TCHAR buffer[MAX_PATH] = { 0 };
	//Print arguments
	_stprintf(buffer, "(lpTemplateDirectory=&\"%s\", lpNewDirectory=&\"%s\", lpSecurityAttributes=0x%lX)\n", templateDirectory, newDirectory, lpSecurityAttributes);
	UcPrintAPIArg(buffer, tab);

	//Call CreateDirectoryEx and get return value
	BOOL retVal = CreateDirectoryEx(templateDirectory, newDirectory, NULL);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 3;
}

void EmuCreateDirectoryExA(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpTemplateDirectory = 0;
	DWORD lpNewDirectory = 0;
	DWORD lpSecurityAttributes = 0;
	TCHAR templateDirectory[MAX_PATH] = { 0 };
	TCHAR newDirectory[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpTemplateDirectory
	lpTemplateDirectory = getDWORD(uc, sp);
	getString(uc, lpTemplateDirectory, templateDirectory);

	//Get lpNewDirectory
	lpNewDirectory = getDWORD(uc, sp + 4);
	getString(uc, lpNewDirectory, newDirectory);

	//Get lpSecurityAttributes
	lpSecurityAttributes = getDWORD(uc, sp + 8);

	EmuCreateDirectoryEx(uc, tab, templateDirectory, newDirectory, lpSecurityAttributes);
}

void EmuCreateDirectoryExW(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpTemplateDirectory = 0;
	DWORD lpNewDirectory = 0;
	DWORD lpSecurityAttributes = 0;
	TCHAR templateDirectory[MAX_PATH] = { 0 };
	TCHAR newDirectory[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpTemplateDirectory
	lpTemplateDirectory = getDWORD(uc, sp);
	getStringW(uc, lpTemplateDirectory, templateDirectory);

	//Get lpNewDirectory
	lpNewDirectory = getDWORD(uc, sp + 4);
	getStringW(uc, lpNewDirectory, newDirectory);

	//Get lpSecurityAttributes
	lpSecurityAttributes = getDWORD(uc, sp + 8);

	EmuCreateDirectoryEx(uc, tab, templateDirectory, newDirectory, lpSecurityAttributes);
}

void EmuCreateDirectoryW(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpPathName = 0;
	DWORD lpSecurityAttributes = 0;
	TCHAR pathName[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpPathName
	lpPathName = getDWORD(uc, sp);
	getStringW(uc, lpPathName, pathName);

	//Get lpSecurityAttributes
	lpSecurityAttributes = getDWORD(uc, sp + 4);

	EmuCreateDirectory(uc, tab, pathName, lpSecurityAttributes);
}

void EmuCreateFile(uc_engine* uc, DWORD tab, TCHAR fileName[], TCHAR genericAccess[], TCHAR shareMode[], DWORD lpSecurityAttributes, TCHAR createType[], TCHAR attribute[], DWORD hTemplateFile, DWORD dwDesiredAccess, DWORD dwShareMode, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes)
{
	uc_err err;
	TCHAR buffer[MAX_PATH] = { 0 };
	//Print arguments
	_stprintf(buffer, "(lpFileName=&\"%s\", dwDesiredAccess=%s, dwShareMode=%s, lpSecurityAttributes=0x%lX, dwCreationDisposition=%s, dwFlagsAndAttributes=%s, hTemplateFile=0x%lX)\n",
		fileName, genericAccess, shareMode, lpSecurityAttributes, createType, attribute, hTemplateFile);
	UcPrintAPIArg(buffer, tab);

	//Call CreateFile and get return value
	DWORD retVal = (DWORD)CreateFile(fileName, dwDesiredAccess, dwShareMode, NULL, dwCreationDisposition, dwFlagsAndAttributes, NULL);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 7;
}

void EmuCreateFileMapping(uc_engine* uc, DWORD tab, DWORD hFile, DWORD lpFileMappingAttributes, TCHAR pageAccess[], DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, TCHAR name[], DWORD flProtect)
{
	uc_err err;
	TCHAR buffer[MAX_PATH] = { 0 };
	//Print arguments
	_stprintf(buffer, "(hFile=0x%lX, lpFileMappingAttributes=0x%lX, flProtect=%s, dwMaximumSizeHigh=0x%lX, dwMaximumSizeLow=0x%lX, lpName=%s)\n",
		hFile, lpFileMappingAttributes, pageAccess, dwMaximumSizeHigh, dwMaximumSizeLow, name);
	UcPrintAPIArg(buffer, tab);

	DWORD retVal = 0xaaaa;

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 6;
}

void EmuCreateFileA(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpFileName = 0;
	DWORD dwDesiredAccess = 0;
	DWORD dwShareMode = 0;
	DWORD lpSecurityAttributes = 0;
	DWORD dwCreationDisposition = 0;
	DWORD dwFlagsAndAttributes = 0;
	DWORD hTemplateFile = 0;
	TCHAR fileName[MAX_PATH] = { 0 };
	TCHAR genericAccess[MAX_PATH] = { 0 };
	TCHAR shareMode[MAX_PATH] = { 0 };
	TCHAR createType[MAX_PATH] = { 0 };
	TCHAR attribute[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpFileName
	lpFileName = getDWORD(uc, sp);
	getString(uc, lpFileName, fileName);

	//Get dwDesiredAccess
	dwDesiredAccess = getDWORD(uc, sp + 4);
	getGeneric(genericAccess, dwDesiredAccess);

	//Get dwShareMode
	dwShareMode = getDWORD(uc, sp + 8);
	getShareMode(shareMode, dwShareMode);

	//Get lpSecurityAttributes
	lpSecurityAttributes = getDWORD(uc, sp + 12);

	//Get dwCreationDisposition
	dwCreationDisposition = getDWORD(uc, sp + 16);
	getCreateType(createType, dwCreationDisposition);

	//Get dwFlagsAndAttributes
	dwFlagsAndAttributes = getDWORD(uc, sp + 20);
	getAttribute(attribute, dwFlagsAndAttributes);

	//Get hTemplateFile
	hTemplateFile = getDWORD(uc, sp + 24);

	EmuCreateFile(uc, tab, fileName, genericAccess, shareMode, lpSecurityAttributes, createType, attribute, hTemplateFile, dwDesiredAccess, dwShareMode, dwCreationDisposition, dwFlagsAndAttributes);
}

void EmuCreateFileMappingA(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hFile = 0;
	DWORD lpFileMappingAttributes = 0;
	DWORD flProtect = 0;
	DWORD dwMaximumSizeHigh = 0;
	DWORD dwMaximumSizeLow = 0;
	DWORD lpName = 0;
	TCHAR pageAccess[MAX_PATH] = { 0 };
	TCHAR name[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hFile
	hFile = getDWORD(uc, sp);

	//Get lpFileMappingAttributes
	lpFileMappingAttributes = getDWORD(uc, sp + 4);

	//Get flProtect
	flProtect = getDWORD(uc, sp + 8);
	getPageAccess(pageAccess, flProtect);

	//Get dwMaximumSizeHigh
	dwMaximumSizeHigh = getDWORD(uc, sp + 12);

	//Get dwMaximumSizeLow
	dwMaximumSizeLow = getDWORD(uc, sp + 16);

	//Get lpName
	lpName = getDWORD(uc, sp + 20);
	getString(uc, lpName, name);

	EmuCreateFileMapping(uc, tab, hFile, lpFileMappingAttributes, pageAccess, dwMaximumSizeHigh, dwMaximumSizeLow, name, flProtect);
}

void EmuCreateFileMappingW(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hFile = 0;
	DWORD lpFileMappingAttributes = 0;
	DWORD flProtect = 0;
	DWORD dwMaximumSizeHigh = 0;
	DWORD dwMaximumSizeLow = 0;
	DWORD lpName = 0;
	TCHAR pageAccess[MAX_PATH] = { 0 };
	TCHAR name[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hFile
	hFile = getDWORD(uc, sp);

	//Get lpFileMappingAttributes
	lpFileMappingAttributes = getDWORD(uc, sp + 4);

	//Get flProtect
	flProtect = getDWORD(uc, sp + 8);
	getPageAccess(pageAccess, flProtect);

	//Get dwMaximumSizeHigh
	dwMaximumSizeHigh = getDWORD(uc, sp + 12);

	//Get dwMaximumSizeLow
	dwMaximumSizeLow = getDWORD(uc, sp + 16);

	//Get lpName
	lpName = getDWORD(uc, sp + 20);
	getStringW(uc, lpName, name);

	EmuCreateFileMapping(uc, tab, hFile, lpFileMappingAttributes, pageAccess, dwMaximumSizeHigh, dwMaximumSizeLow, name, flProtect);
}

void EmuCreateFileW(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpFileName = 0;
	DWORD dwDesiredAccess = 0;
	DWORD dwShareMode = 0;
	DWORD lpSecurityAttributes = 0;
	DWORD dwCreationDisposition = 0;
	DWORD dwFlagsAndAttributes = 0;
	DWORD hTemplateFile = 0;
	TCHAR fileName[MAX_PATH] = { 0 };
	TCHAR genericAccess[MAX_PATH] = { 0 };
	TCHAR shareMode[MAX_PATH] = { 0 };
	TCHAR createType[MAX_PATH] = { 0 };
	TCHAR attribute[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpFileName
	lpFileName = getDWORD(uc, sp);
	getStringW(uc, lpFileName, fileName);

	//Get dwDesiredAccess
	dwDesiredAccess = getDWORD(uc, sp + 4);
	getGeneric(genericAccess, dwDesiredAccess);

	//Get dwShareMode
	dwShareMode = getDWORD(uc, sp + 8);
	getShareMode(shareMode, dwShareMode);

	//Get lpSecurityAttributes
	lpSecurityAttributes = getDWORD(uc, sp + 12);

	//Get dwCreationDisposition
	dwCreationDisposition = getDWORD(uc, sp + 16);
	getCreateType(createType, dwCreationDisposition);

	//Get dwFlagsAndAttributes
	dwFlagsAndAttributes = getDWORD(uc, sp + 20);
	getAttribute(attribute, dwFlagsAndAttributes);

	//Get hTemplateFile
	hTemplateFile = getDWORD(uc, sp + 24);

	EmuCreateFile(uc, tab, fileName, genericAccess, shareMode, lpSecurityAttributes, createType, attribute, hTemplateFile, dwDesiredAccess, dwShareMode, dwCreationDisposition, dwFlagsAndAttributes);
}

void EmuCreateMutex(uc_engine* uc, DWORD tab, DWORD lpMutexAttributes, BOOL bInitialOwner, TCHAR name[])
{
	uc_err err;
	TCHAR buffer[MAX_PATH] = { 0 };
	//Print arguments
	if (bInitialOwner)
	{
		_stprintf(buffer, "(lpMutexAttributes=0x%lX,bInitialOwner=TRUE, lpName=&\"%s\")\n", lpMutexAttributes, name);
		UcPrintAPIArg(buffer, tab);
	}
	else
	{
		_stprintf(buffer, "(lpMutexAttributes=0x%lX,bInitialOwner=FALSE, lpName=&\"%s\")\n", lpMutexAttributes, name);
		UcPrintAPIArg(buffer, tab);
	}

	//Call CreateMutex and get return value
	DWORD retVal = (DWORD)CreateMutex(NULL, bInitialOwner, name);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 3;
}

void EmuCreateMutexEx(uc_engine* uc, DWORD tab, DWORD lpMutexAttributes, TCHAR name[], DWORD dwFlags, TCHAR mutexAccess[], DWORD dwDesiredAccess)
{
	uc_err err;
	TCHAR buffer[MAX_PATH] = { 0 };
	//Print arguments
	if (dwFlags)
	{
		_stprintf(buffer, "(lpMutexAttributes=0x%lX, lpName=&\"%s\", dwFlags=CREATE_MUTEX_INITIAL_OWNER, dwDesiredAccess=%s)\n",
			lpMutexAttributes, name, mutexAccess);
		UcPrintAPIArg(buffer, tab);
	}
	else
	{
		_stprintf(buffer, "(lpMutexAttributes=0x%lX, lpName=&\"%s\", dwFlags=0x0, dwDesiredAccess=%s)\n",
			lpMutexAttributes, name, mutexAccess);
		UcPrintAPIArg(buffer, tab);
	}

	//Call CreateMutexEx and get return value
	DWORD retVal = (DWORD)CreateMutexEx(NULL, name, dwFlags, dwDesiredAccess);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 4;
}

void EmuCreateMutexA(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpMutexAttributes = 0;
	BOOL bInitialOwner = 0;
	DWORD lpName = 0;
	TCHAR name[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpMutexAttributes
	lpMutexAttributes = getDWORD(uc, sp);

	//Get bInitialOwner
	bInitialOwner = getDWORD(uc, sp + 4);

	//Get lpName
	lpName = getDWORD(uc, sp + 8);
	getString(uc, lpName, name);

	EmuCreateMutex(uc, tab, lpMutexAttributes, bInitialOwner, name);
}

void EmuCreateMutexExA(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpMutexAttributes = 0;
	DWORD lpName = 0;
	DWORD dwFlags = 0;
	DWORD dwDesiredAccess = 0;
	TCHAR name[MAX_PATH] = { 0 };
	TCHAR mutexAccess[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpMutexAttributes
	lpMutexAttributes = getDWORD(uc, sp);

	//Get lpName
	lpName = getDWORD(uc, sp + 4);
	getString(uc, lpName, name);

	//Get dwFlags
	dwFlags = getDWORD(uc, sp + 8);

	//Get dwDesiredAccess
	dwDesiredAccess = getDWORD(uc, sp + 12);
	getMutexAccess(mutexAccess, dwDesiredAccess);
	
	EmuCreateMutexEx(uc, tab, lpMutexAttributes, name, dwFlags, mutexAccess, dwDesiredAccess);
}

void EmuCreateMutexExW(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpMutexAttributes = 0;
	DWORD lpName = 0;
	DWORD dwFlags = 0;
	DWORD dwDesiredAccess = 0;
	TCHAR name[MAX_PATH] = { 0 };
	TCHAR mutexAccess[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpMutexAttributes
	lpMutexAttributes = getDWORD(uc, sp);

	//Get lpName
	lpName = getDWORD(uc, sp + 4);
	getStringW(uc, lpName, name);

	//Get dwFlags
	dwFlags = getDWORD(uc, sp + 8);

	//Get dwDesiredAccess
	dwDesiredAccess = getDWORD(uc, sp + 12);
	getMutexAccess(mutexAccess, dwDesiredAccess);

	EmuCreateMutexEx(uc, tab, lpMutexAttributes, name, dwFlags, mutexAccess, dwDesiredAccess);
}

void EmuCreateMutexW(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpMutexAttributes = 0;
	BOOL bInitialOwner = 0;
	DWORD lpName = 0;
	TCHAR name[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpMutexAttributes
	lpMutexAttributes = getDWORD(uc, sp);

	//Get bInitialOwner
	bInitialOwner = getDWORD(uc, sp + 4);

	//Get lpName
	lpName = getDWORD(uc, sp + 8);
	getStringW(uc, lpName, name);

	EmuCreateMutex(uc, tab, lpMutexAttributes, bInitialOwner, name);
}

void EmuCreateNamedPipe(uc_engine* uc, DWORD tab, TCHAR name[], DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, DWORD lpSecurityAttributes)
{
	uc_err err;
	TCHAR buffer[MAX_PATH] = { 0 };
	//Print arguments
	_stprintf(buffer, "(lpName=&\"%s\", dwOpenMode=0x%lX, dwPipeMode=0x%lX, nMaxInstances=0x%lX, nOutBufferSize=0x%lX, nInBufferSize=0x%lX, nDefaultTimeOut=0x%lX, lpSecurityAttributes=0x%lX)\n",
		name, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes);
	UcPrintAPIArg(buffer, tab);

	//Call CreateNamedPipe and get return value
	DWORD retVal = (DWORD)CreateNamedPipe(name, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, NULL);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 8;
}

void EmuCreateNamedPipeA(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpName = 0;
	DWORD dwOpenMode = 0;
	DWORD dwPipeMode = 0;
	DWORD nMaxInstances = 0;
	DWORD nOutBufferSize = 0;
	DWORD nInBufferSize = 0;
	DWORD nDefaultTimeOut = 0;
	DWORD lpSecurityAttributes = 0;
	TCHAR name[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpName
	lpName = getDWORD(uc, sp);
	getString(uc, lpName, name);

	//Get dwOpenMode
	dwOpenMode = getDWORD(uc, sp + 4);

	//Get dwPipeMode
	dwPipeMode = getDWORD(uc, sp + 8);

	//Get nMaxInstances
	nMaxInstances = getDWORD(uc, sp + 12);

	//Get nOutBufferSize
	nOutBufferSize = getDWORD(uc, sp + 16);

	//Get nInBufferSize
	nInBufferSize = getDWORD(uc, sp + 20);

	//Get nDefaultTimeOut
	nDefaultTimeOut = getDWORD(uc, sp + 24);

	//Get lpSecurityAttributes
	lpSecurityAttributes = getDWORD(uc, sp + 28);

	EmuCreateNamedPipe(uc, tab, name, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes);
}

void EmuCreateNamedPipeW(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpName = 0;
	DWORD dwOpenMode = 0;
	DWORD dwPipeMode = 0;
	DWORD nMaxInstances = 0;
	DWORD nOutBufferSize = 0;
	DWORD nInBufferSize = 0;
	DWORD nDefaultTimeOut = 0;
	DWORD lpSecurityAttributes = 0;
	TCHAR name[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpName
	lpName = getDWORD(uc, sp);
	getStringW(uc, lpName, name);

	//Get dwOpenMode
	dwOpenMode = getDWORD(uc, sp + 4);

	//Get dwPipeMode
	dwPipeMode = getDWORD(uc, sp + 8);

	//Get nMaxInstances
	nMaxInstances = getDWORD(uc, sp + 12);

	//Get nOutBufferSize
	nOutBufferSize = getDWORD(uc, sp + 16);

	//Get nInBufferSize
	nInBufferSize = getDWORD(uc, sp + 20);

	//Get nDefaultTimeOut
	nDefaultTimeOut = getDWORD(uc, sp + 24);

	//Get lpSecurityAttributes
	lpSecurityAttributes = getDWORD(uc, sp + 28);

	EmuCreateNamedPipe(uc, tab, name, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes);
}

void EmuCreatePipe(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD pHReadPipe = 0;
	DWORD hReadPipe = 0;
	DWORD pHWritePipe = 0;
	DWORD hWritePipe = 0;
	DWORD lpPipeAttributes = 0;
	DWORD nSize = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hReadPipe
	pHReadPipe = getDWORD(uc, sp);
	hReadPipe = getDWORD(uc, pHReadPipe);

	//Get hWritePipe
	pHWritePipe = getDWORD(uc, sp + 4);
	hWritePipe = getDWORD(uc, pHWritePipe);

	//Get lpPipeAttributes
	lpPipeAttributes = getDWORD(uc, sp + 8);

	//Get nSize
	nSize = getDWORD(uc, sp + 12);

	//Print arguments
	_stprintf(buffer, "(hReadPipe=&(0x%lX), hWritePipe=&(0x%lX), lpPipeAttributes=0x%lX, nSize=0x%lX)\n",
		hReadPipe, hWritePipe, lpPipeAttributes, nSize);
	UcPrintAPIArg(buffer, tab);

	//Call CreatePipe and get return value
	DWORD retVal = (DWORD)CreatePipe((PHANDLE)&hReadPipe, (PHANDLE)&hWritePipe, NULL, nSize);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 4;
}

void EmuCreateProcess(uc_engine* uc, DWORD tab, TCHAR applicationName[], TCHAR commandLine[], DWORD lpProcessAttributes, DWORD lpThreadAttributes, DWORD bInheritHandles, TCHAR creationFlags[], DWORD lpEnvironment, TCHAR currentDirectory[],  DWORD lpStartupInfo, DWORD lpProcessInformation)
{
	uc_err err;
	TCHAR buffer[MAX_PATH] = { 0 };
	//Print arguments
	_stprintf(buffer, "(lpApplicationName=&\"%s\", lpCommandLine=&\"%s\", lpProcessAttributes=0x%lX, lpThreadAttributes=0x%lX, bInheritHandles=0x%lX, dwCreationFlags=%s, lpEnvironment=0x%lX, lpCurrentDirectory=%s, lpStartupInfo=0x%lX, lpProcessInformation=0x%lX)\n",
		applicationName, commandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, creationFlags, lpEnvironment, currentDirectory, lpStartupInfo, lpProcessInformation);
	UcPrintAPIArg(buffer, tab);

	//Default return value
	DWORD retVal = 0xffff;

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 10;
}

void EmuCreateProcessAsUser(uc_engine* uc, DWORD tab, DWORD hToken, TCHAR applicationName[], TCHAR commandLine[], DWORD lpProcessAttributes, DWORD lpThreadAttributes, DWORD bInheritHandles, TCHAR creationFlags[], DWORD lpEnvironment, TCHAR currentDirectory[], DWORD lpStartupInfo, DWORD lpProcessInformation)
{
	uc_err err;
	TCHAR buffer[MAX_PATH] = { 0 };
	//Print arguments
	_stprintf(buffer, "(hToken=0x%lX, lpApplicationName=&\"%s\", lpCommandLine=&\"%s\", lpProcessAttributes=0x%lX, lpThreadAttributes=0x%lX, bInheritHandles=0x%lX, dwCreationFlags=%s, lpEnvironment=0x%lX, lpCurrentDirectory=%s, lpStartupInfo=0x%lX, lpProcessInformation=0x%lX)\n",
		hToken, applicationName, commandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, creationFlags, lpEnvironment, currentDirectory, lpStartupInfo, lpProcessInformation);
	UcPrintAPIArg(buffer, tab);

	//Default return value
	DWORD retVal = 0xfff;

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 11;
}

void EmuCreateProcessA(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpApplicationName = 0;
	DWORD lpCommandLine = 0;
	DWORD lpProcessAttributes = 0;
	DWORD lpThreadAttributes = 0;
	DWORD bInheritHandles = 0;
	DWORD dwCreationFlags = 0;
	DWORD lpEnvironment = 0;
	DWORD lpCurrentDirectory = 0;
	DWORD lpStartupInfo = 0;
	DWORD lpProcessInformation = 0;
	TCHAR applicationName[MAX_PATH] = { 0 };
	TCHAR commandLine[MAX_PATH] = { 0 };
	TCHAR creationFlags[MAX_PATH] = { 0 };
	TCHAR currentDirectory[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpApplicationName
	lpApplicationName = getDWORD(uc, sp);
	getString(uc, lpApplicationName, applicationName);

	//Get lpCommandLine
	lpCommandLine = getDWORD(uc, sp + 4);
	getString(uc, lpCommandLine, commandLine);

	//Get lpProcessAttributes
	lpProcessAttributes = getDWORD(uc, sp + 8);

	//Get lpThreadAttributes
	lpThreadAttributes = getDWORD(uc, sp + 12);

	//Get bInheritHandles
	bInheritHandles = getDWORD(uc, sp + 16);

	//Get dwCreationFlags
	dwCreationFlags = getDWORD(uc, sp + 20);
	getCreationFlag(creationFlags, dwCreationFlags);

	//Get lpEnvironment
	lpEnvironment = getDWORD(uc, sp + 24);

	//Get lpCurrentDirectory
	lpCurrentDirectory = getDWORD(uc, sp + 28);
	getString(uc, lpCurrentDirectory, currentDirectory);

	//Get lpStartupInfo
	lpStartupInfo = getDWORD(uc, sp + 32);

	//Get lpProcessInformation
	lpProcessInformation = getDWORD(uc, sp + 36);

	EmuCreateProcess(uc, tab, applicationName, commandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, creationFlags, lpEnvironment, currentDirectory, lpStartupInfo, lpProcessInformation);
}

void EmuCreateProcessAsUserA(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hToken = 0;
	DWORD lpApplicationName = 0;
	DWORD lpCommandLine = 0;
	DWORD lpProcessAttributes = 0;
	DWORD lpThreadAttributes = 0;
	DWORD bInheritHandles = 0;
	DWORD dwCreationFlags = 0;
	DWORD lpEnvironment = 0;
	DWORD lpCurrentDirectory = 0;
	DWORD lpStartupInfo = 0;
	DWORD lpProcessInformation = 0;
	TCHAR applicationName[MAX_PATH] = { 0 };
	TCHAR commandLine[MAX_PATH] = { 0 };
	TCHAR creationFlags[MAX_PATH] = { 0 };
	TCHAR currentDirectory[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hToken
	hToken = getDWORD(uc, sp);

	//Get lpApplicationName
	lpApplicationName = getDWORD(uc, sp + 4);
	getString(uc, lpApplicationName, applicationName);

	//Get lpCommandLine
	lpCommandLine = getDWORD(uc, sp + 8);
	getString(uc, lpCommandLine, commandLine);

	//Get lpProcessAttributes
	lpProcessAttributes = getDWORD(uc, sp + 12);

	//Get lpThreadAttributes
	lpThreadAttributes = getDWORD(uc, sp + 16);

	//Get bInheritHandles
	bInheritHandles = getDWORD(uc, sp + 20);

	//Get dwCreationFlags
	dwCreationFlags = getDWORD(uc, sp + 24);
	getCreationFlag(creationFlags, dwCreationFlags);

	//Get lpEnvironment
	lpEnvironment = getDWORD(uc, sp + 28);

	//Get lpCurrentDirectory
	lpCurrentDirectory = getDWORD(uc, sp + 32);
	getString(uc, lpCurrentDirectory, currentDirectory);

	//Get lpStartupInfo
	lpStartupInfo = getDWORD(uc, sp + 36);

	//Get lpProcessInformation
	lpProcessInformation = getDWORD(uc, sp + 40);

	EmuCreateProcessAsUser(uc, tab, hToken, applicationName, commandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, creationFlags, lpEnvironment, currentDirectory, lpStartupInfo, lpProcessInformation);
}

void EmuCreateProcessAsUserW(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hToken = 0;
	DWORD lpApplicationName = 0;
	DWORD lpCommandLine = 0;
	DWORD lpProcessAttributes = 0;
	DWORD lpThreadAttributes = 0;
	DWORD bInheritHandles = 0;
	DWORD dwCreationFlags = 0;
	DWORD lpEnvironment = 0;
	DWORD lpCurrentDirectory = 0;
	DWORD lpStartupInfo = 0;
	DWORD lpProcessInformation = 0;
	TCHAR applicationName[MAX_PATH] = { 0 };
	TCHAR commandLine[MAX_PATH] = { 0 };
	TCHAR creationFlags[MAX_PATH] = { 0 };
	TCHAR currentDirectory[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hToken
	hToken = getDWORD(uc, sp);

	//Get lpApplicationName
	lpApplicationName = getDWORD(uc, sp + 4);
	getStringW(uc, lpApplicationName, applicationName);

	//Get lpCommandLine
	lpCommandLine = getDWORD(uc, sp + 8);
	getStringW(uc, lpCommandLine, commandLine);

	//Get lpProcessAttributes
	lpProcessAttributes = getDWORD(uc, sp + 12);

	//Get lpThreadAttributes
	lpThreadAttributes = getDWORD(uc, sp + 16);

	//Get bInheritHandles
	bInheritHandles = getDWORD(uc, sp + 20);

	//Get dwCreationFlags
	dwCreationFlags = getDWORD(uc, sp + 24);
	getCreationFlag(creationFlags, dwCreationFlags);

	//Get lpEnvironment
	lpEnvironment = getDWORD(uc, sp + 28);

	//Get lpCurrentDirectory
	lpCurrentDirectory = getDWORD(uc, sp + 32);
	getString(uc, lpCurrentDirectory, currentDirectory);

	//Get lpStartupInfo
	lpStartupInfo = getDWORD(uc, sp + 36);

	//Get lpProcessInformation
	lpProcessInformation = getDWORD(uc, sp + 40);

	EmuCreateProcessAsUser(uc, tab, hToken, applicationName, commandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, creationFlags, lpEnvironment, currentDirectory, lpStartupInfo, lpProcessInformation);
}

void EmuCreateProcessW(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpApplicationName = 0;
	DWORD lpCommandLine = 0;
	DWORD lpProcessAttributes = 0;
	DWORD lpThreadAttributes = 0;
	DWORD bInheritHandles = 0;
	DWORD dwCreationFlags = 0;
	DWORD lpEnvironment = 0;
	DWORD lpCurrentDirectory = 0;
	DWORD lpStartupInfo = 0;
	DWORD lpProcessInformation = 0;
	TCHAR applicationName[MAX_PATH] = { 0 };
	TCHAR commandLine[MAX_PATH] = { 0 };
	TCHAR creationFlags[MAX_PATH] = { 0 };
	TCHAR currentDirectory[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpApplicationName
	lpApplicationName = getDWORD(uc, sp);
	getStringW(uc, lpApplicationName, applicationName);

	//Get lpCommandLine
	lpCommandLine = getDWORD(uc, sp + 4);
	getStringW(uc, lpCommandLine, commandLine);

	//Get lpProcessAttributes
	lpProcessAttributes = getDWORD(uc, sp + 8);

	//Get lpThreadAttributes
	lpThreadAttributes = getDWORD(uc, sp + 12);

	//Get bInheritHandles
	bInheritHandles = getDWORD(uc, sp + 16);

	//Get dwCreationFlags
	dwCreationFlags = getDWORD(uc, sp + 20);
	getCreationFlag(creationFlags, dwCreationFlags);

	//Get lpEnvironment
	lpEnvironment = getDWORD(uc, sp + 24);

	//Get lpCurrentDirectory
	lpCurrentDirectory = getDWORD(uc, sp + 28);
	getStringW(uc, lpCurrentDirectory, currentDirectory);

	//Get lpStartupInfo
	lpStartupInfo = getDWORD(uc, sp + 32);

	//Get lpProcessInformation
	lpProcessInformation = getDWORD(uc, sp + 36);

	EmuCreateProcess(uc, tab, applicationName, commandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, creationFlags, lpEnvironment, currentDirectory, lpStartupInfo, lpProcessInformation);
}

void EmuCreateRemoteThread(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hProcess = 0;
	DWORD lpThreadAttributes = 0;
	DWORD dwStackSize = 0;
	DWORD lpStartAddress = 0;
	DWORD lpParameter = 0;
	DWORD dwCreationFlags = 0;
	DWORD lpThreadId = 0;
	TCHAR creationFlags[MAX_PATH] = { 0 };
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hProcess
	hProcess = getDWORD(uc, sp);

	//Get lpThreadAttributes
	lpThreadAttributes = getDWORD(uc, sp + 4);

	//Get dwStackSize
	dwStackSize = getDWORD(uc, sp + 8);

	//Get lpStartAddress
	lpStartAddress = getDWORD(uc, sp + 12);

	//Get lpParameter
	lpParameter = getDWORD(uc, sp + 16);

	//Get dwCreationFlags
	dwCreationFlags = getDWORD(uc, sp + 20);
	getCreationFlag(creationFlags, dwCreationFlags);

	//Get lpThreadId
	lpThreadId = getDWORD(uc, sp + 24);
	//Set lpThreadId
	DWORD TID = 0xff;
	err = uc_mem_write(uc, lpThreadId, &TID, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Print arguments
	_stprintf(buffer, "(hProcess=0x%lX, lpThreadAttributes=0x%lX, dwStackSize=0x%lX, lpStartAddress=0x%lX, lpParameter=0x%lX, dwCreationFlags=%s, lpThreadId=0x%lX)\n",
		hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, creationFlags, lpThreadId);
	UcPrintAPIArg(buffer, tab);

	//Default return value
	DWORD retVal = 0xff;

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 7;
}

void EmuCreateRemoteThreadEx(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hProcess = 0;
	DWORD lpThreadAttributes = 0;
	DWORD dwStackSize = 0;
	DWORD lpStartAddress = 0;
	DWORD lpParameter = 0;
	DWORD dwCreationFlags = 0;
	DWORD lpAttributeList = 0;
	DWORD lpThreadId = 0;
	TCHAR creationFlags[MAX_PATH] = { 0 };
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hProcess
	hProcess = getDWORD(uc, sp);

	//Get lpThreadAttributes
	lpThreadAttributes = getDWORD(uc, sp + 4);

	//Get dwStackSize
	dwStackSize = getDWORD(uc, sp + 8);

	//Get lpStartAddress
	lpStartAddress = getDWORD(uc, sp + 12);

	//Get lpParameter
	lpParameter = getDWORD(uc, sp + 16);

	//Get dwCreationFlags
	dwCreationFlags = getDWORD(uc, sp + 20);
	getCreationFlag(creationFlags, dwCreationFlags);

	//Get lpThreadId
	lpThreadId = getDWORD(uc, sp + 24);
	//Set lpThreadId
	DWORD TID = 0xff;
	err = uc_mem_write(uc, lpThreadId, &TID, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Print arguments
	_stprintf(buffer, "(hProcess=0x%lX, lpThreadAttributes=0x%lX, dwStackSize=0x%lX, lpStartAddress=0x%lX, lpParameter=0x%lX, dwCreationFlags=%s, lpAttributeList=0x%lX, lpThreadId=0x%lX)\n",
		hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, creationFlags, lpAttributeList, lpThreadId);
	UcPrintAPIArg(buffer, tab);

	//Default return value
	DWORD retVal = 0xff;

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 8;
}

void EmuCreateThread(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpThreadAttributes = 0;
	DWORD dwStackSize = 0;
	DWORD lpStartAddress = 0;
	DWORD lpParameter = 0;
	DWORD dwCreationFlags = 0;
	DWORD lpThreadId = 0;
	TCHAR creationFlags[MAX_PATH] = { 0 };
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpThreadAttributes
	lpThreadAttributes = getDWORD(uc, sp);

	//Get dwStackSize
	dwStackSize = getDWORD(uc, sp + 4);

	//Get lpStartAddress
	lpStartAddress = getDWORD(uc, sp + 8);

	//Get lpParameter
	lpParameter = getDWORD(uc, sp + 12);

	//Get dwCreationFlags
	dwCreationFlags = getDWORD(uc, sp + 16);
	getCreationFlag(creationFlags, dwCreationFlags);

	//Get lpThreadId
	lpThreadId = getDWORD(uc, sp + 20);
	//Set lpThreadId
	DWORD TID = 0xf;
	err = uc_mem_write(uc, lpThreadId, &TID, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Print arguments
	_stprintf(buffer, "(lpThreadAttributes=0x%lX, dwStackSize=0x%lX, lpStartAddress=0x%lX, lpParameter=0x%lX, dwCreationFlags=%s, lpThreadId=0x%lX)\n",
		lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, creationFlags, lpThreadId);
	UcPrintAPIArg(buffer, tab);

	//Default return value
	DWORD retVal = 0xf;

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	if (dwCreationFlags == 0x4)
		//Cleanup stack
		_numberOfArguments = 7;
	else
	{
		//Jump into thread
		err = uc_reg_write(uc, UC_X86_REG_EIP, &lpStartAddress);
		if (err != UC_ERR_OK)
			HandleUcErrorVoid(err);
	}
}

void EmuCreateToolhelp32Snapshot(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD dwFlags = 0;
	DWORD th32ProcessID = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get dwFlags
	dwFlags = getDWORD(uc, sp);

	//Get th32ProcessID
	th32ProcessID = getDWORD(uc, sp + 4);

	//Print argument
	_stprintf(buffer, "(dwFlags=0x%lX, th32ProcessID=0x%lX)\n", dwFlags, th32ProcessID);
	UcPrintAPIArg(buffer, tab);

	//Call CreateToolhelp32Snapshot and get return value
	DWORD retVal = (DWORD)CreateToolhelp32Snapshot(dwFlags, th32ProcessID);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 2;
}

void EmuDecodePointer(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD Ptr = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get Ptr
	Ptr = getDWORD(uc, sp);

	//Print argument
	_stprintf(buffer, "(Ptr=0x%lX)\n", Ptr);
	UcPrintAPIArg(buffer, tab);

	DWORD retVal = Ptr;

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 1;
}

void EmuDeleteCriticalSection(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpCriticalSection = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpCriticalSection
	lpCriticalSection = getDWORD(uc, sp);

	//Print arguments
	_stprintf(buffer, "(lpCriticalSection=0x%lX)\n", lpCriticalSection);
	UcPrintAPIArg(buffer, tab);

	DWORD retVal = 0;

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 1;
}

void EmuDeleteFile(uc_engine* uc, DWORD tab, TCHAR fileName[])
{
	uc_err err;
	TCHAR buffer[MAX_PATH] = { 0 };
	//Print argument
	_stprintf(buffer, "(lpFileName=&\"%s\")\n", fileName);
	UcPrintAPIArg(buffer, tab);

	//Always return TRUE
	BOOL retVal = TRUE;

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 1;
}

void EmuDeleteFileA(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpFileName = 0;
	TCHAR fileName[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpFileName
	lpFileName = getDWORD(uc, sp);
	getString(uc, lpFileName, fileName);

	EmuDeleteFile(uc, tab, fileName);
}

void EmuDeleteFileW(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpFileName = 0;
	TCHAR fileName[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpFileName
	lpFileName = getDWORD(uc, sp);
	getStringW(uc, lpFileName, fileName);

	EmuDeleteFile(uc, tab, fileName);
}

void EmuDisconnectNamedPipe(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hNamedPipe = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hNamedPipe
	hNamedPipe = getDWORD(uc, sp);

	//Print argument
	_stprintf(buffer, "(hNamedPipe=0x%lX)\n", hNamedPipe);
	UcPrintAPIArg(buffer, tab);

	//Call DisconnectNamedPipe and get return value
	BOOL retVal = DisconnectNamedPipe((HANDLE)hNamedPipe);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 1;
}

void EmuDuplicateHandle(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hSourceProcessHandle = 0;
	DWORD hSourceHandle = 0;
	DWORD hTargetProcessHandle = 0;
	DWORD lpTargetHandle = 0;
	DWORD dwDesiredAccess = 0;
	DWORD bInheritHandle = 0;
	DWORD dwOptions = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hSourceProcessHandle
	hSourceProcessHandle = getDWORD(uc, sp);

	//Get hSourceHandle
	hSourceHandle = getDWORD(uc, sp + 4);

	//Get hTargetProcessHandle
	hTargetProcessHandle = getDWORD(uc, sp + 8);

	//Get lpTargetHandle
	lpTargetHandle = getDWORD(uc, sp + 12);

	//Get dwDesiredAccess
	dwDesiredAccess = getDWORD(uc, sp + 16);

	//Get bInheritHandle
	bInheritHandle = getDWORD(uc, sp + 20);

	//Get dwOptions
	dwOptions = getDWORD(uc, sp + 24);

	//Print arguments
	_stprintf(buffer, "(hSourceProcessHandle=0x%lX, hSourceHandle=0x%lX, hTargetProcessHandle=0x%lX, lpTargetHandle=0x%lX, dwDesiredAccess=0x%lX, bInheritHandle=0x%lX, dwOptions=0x%lX)\n",
		hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions);
	UcPrintAPIArg(buffer, tab);

	//Default return value
	BOOL retVal = TRUE;
	err = uc_mem_write(uc, lpTargetHandle, &hSourceHandle, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 7;
}

void EmuEncodePointer(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD Ptr = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get Ptr
	Ptr = getDWORD(uc, sp);

	//Print argument
	_stprintf(buffer, "(Ptr=0x%lX)\n", Ptr);
	UcPrintAPIArg(buffer, tab);

	DWORD retVal = Ptr;

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 1;
}

void EmuEnterCriticalSection(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpCriticalSection = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpCriticalSection
	lpCriticalSection = getDWORD(uc, sp);

	//Print arguments
	_stprintf(buffer, "(lpCriticalSection=0x%lX)\n", lpCriticalSection);
	UcPrintAPIArg(buffer, tab);

	DWORD retVal = 0;

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 1;
}

void EmuExitProcess(uc_engine* uc, DWORD tab)
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

void EmuExitThread(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD dwExitCode = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get dwExitCode
	dwExitCode = getDWORD(uc, sp);

	//Print argument
	_stprintf(buffer, "(dwExitCode=0x%lX)\n", dwExitCode);
	UcPrintAPIArg(buffer, tab);

	err = uc_emu_stop(uc);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
}

void EmuFindClose(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hFindFile = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hFindFile
	hFindFile = getDWORD(uc, sp);

	//Print argument
	_stprintf(buffer, "(hFindFile=0x%lX)\n", hFindFile);
	UcPrintAPIArg(buffer, tab);

	//Call FindClose and get return value
	BOOL retVal = FindClose((HANDLE)hFindFile);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 1;
}

void EmuFindFirstFile(uc_engine* uc, DWORD tab, TCHAR fileName[], DWORD lpFindFileData, BOOL isW)
{
	uc_err err;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Print arguments
	_stprintf(buffer, "(lpFileName=&\"%s\", lpFindFileData=0x%lX)\n", fileName, lpFindFileData);
	UcPrintAPIArg(buffer, tab);

	//Call FindFirstFile
	DWORD retVal = 0;
	if (isW)
	{
		WIN32_FIND_DATAW fileData;
		WCHAR fileNameW[MAX_PATH] = { 0 };
		mbstowcs(fileNameW, fileName, strlen(fileName));
		retVal = (DWORD)FindFirstFileW(fileNameW, &fileData);
		err = uc_mem_write(uc, lpFindFileData, &fileData, sizeof(WIN32_FIND_DATAW));
		if (err != UC_ERR_OK)
			HandleUcErrorVoid(err);
	}
	else
	{
		WIN32_FIND_DATA fileData;
		retVal = (DWORD)FindFirstFile(fileName, &fileData);
		err = uc_mem_write(uc, lpFindFileData, &fileData, sizeof(WIN32_FIND_DATA));
		if (err != UC_ERR_OK)
			HandleUcErrorVoid(err);
	}

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 2;
}

void EmuFindFirstFileA(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpFileName = 0;
	DWORD lpFindFileData = 0;
	TCHAR fileName[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpFileName
	lpFileName = getDWORD(uc, sp);
	getString(uc, lpFileName, fileName);

	//Get lpFindFileData
	lpFindFileData = getDWORD(uc, sp + 4);

	EmuFindFirstFile(uc, tab, fileName, lpFindFileData, FALSE);
}

void EmuFindFirstFileW(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpFileName = 0;
	DWORD lpFindFileData = 0;
	TCHAR fileName[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpFileName
	lpFileName = getDWORD(uc, sp);
	getStringW(uc, lpFileName, fileName);

	//Get lpFindFileData
	lpFindFileData = getDWORD(uc, sp + 4);

	EmuFindFirstFile(uc, tab, fileName, lpFindFileData, TRUE);
}

void EmuFindNextFile(uc_engine* uc, DWORD tab, DWORD hFindFile, DWORD lpFindFileData, BOOL isW)
{
	uc_err err;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Print arguments
	_stprintf(buffer, "(hFindFile=0x%lX, lpFindFileData=0x%lX)\n", hFindFile, lpFindFileData);
	UcPrintAPIArg(buffer, tab);

	//Call FindNextFile
	BOOL retVal = 0;
	if (isW)
	{
		WIN32_FIND_DATAW fileData;
		retVal = FindNextFileW((HANDLE)hFindFile, &fileData);
		err = uc_mem_write(uc, lpFindFileData, &fileData, sizeof(WIN32_FIND_DATAW));
		if (err != UC_ERR_OK)
			HandleUcErrorVoid(err);
	}
	else
	{
		WIN32_FIND_DATA fileData;
		retVal = FindNextFile((HANDLE)hFindFile, &fileData);
		err = uc_mem_write(uc, lpFindFileData, &fileData, sizeof(WIN32_FIND_DATA));
		if (err != UC_ERR_OK)
			HandleUcErrorVoid(err);
	}

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 2;
}

void EmuFindNextFileA(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hFindFile = 0;
	DWORD lpFindFileData = 0;
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hFindFile
	hFindFile = getDWORD(uc, sp);

	//Get lpFindFileData
	lpFindFileData = getDWORD(uc, sp + 4);

	EmuFindNextFile(uc, tab, hFindFile, lpFindFileData, FALSE);
}

void EmuFindNextFileW(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hFindFile = 0;
	DWORD lpFindFileData = 0;
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hFindFile
	hFindFile = getDWORD(uc, sp);

	//Get lpFindFileData
	lpFindFileData = getDWORD(uc, sp + 4);

	EmuFindNextFile(uc, tab, hFindFile, lpFindFileData, TRUE);
}

void EmuFlsAlloc(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpCallback = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpCallback
	lpCallback = getDWORD(uc, sp);

	//Print argument
	_stprintf(buffer, "(lpCallback=0x%lX)\n", lpCallback);
	UcPrintAPIArg(buffer, tab);

	//Alloc Fiber
	DWORD retVal = AllocFiber();

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//CleanupStack
	_numberOfArguments = 1;
}

void EmuFlsFree(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD dwFlsIndex = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get dwFlsIndex
	dwFlsIndex = getDWORD(uc, sp);

	//Print argument
	_stprintf(buffer, "(dwFlsIndex=0x%lX)\n", dwFlsIndex);
	UcPrintAPIArg(buffer, tab);

	//Default return value
	BOOL retVal = FreeFiber(dwFlsIndex);

	if (!retVal)
		UcSetLastError(uc, 0x57);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//CleanupStack
	_numberOfArguments = 1;
}

void EmuFlsGetValue(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD dwFlsIndex = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get dwFlsIndex
	dwFlsIndex = getDWORD(uc, sp);

	//Print argument
	_stprintf(buffer, "(dwFlsIndex=0x%lX)\n", dwFlsIndex);
	UcPrintAPIArg(buffer, tab);

	//Default return value
	DWORD retVal = GetFiber(dwFlsIndex);

	if (retVal == 0)
		UcSetLastError(uc, 0x57);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//CleanupStack
	_numberOfArguments = 1;
}

void EmuFlsSetValue(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD dwFlsIndex = 0;
	DWORD lpFlsData = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get dwFlsIndex
	dwFlsIndex = getDWORD(uc, sp);

	//Get lpFlsData
	lpFlsData = getDWORD(uc, sp + 4);

	//Print argument
	_stprintf(buffer, "(dwFlsIndex=0x%lX, lpFlsData=0x%lX)\n", dwFlsIndex, lpFlsData);
	UcPrintAPIArg(buffer, tab);

	//Default return value
	BOOL retVal = SetFiber(dwFlsIndex, lpFlsData);

	if (!retVal)
		UcSetLastError(uc, 0x57);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//CleanupStack
	_numberOfArguments = 2;
}

void EmuFreeLibrary(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hLibModule = 0;
	map<TCHAR*, DWORD>::iterator iterate;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hLibModule
	hLibModule = getDWORD(uc, sp);

	//Print argument
	BOOL retVal = 0;
	iterate = loadedDll.begin();
	while (iterate != loadedDll.end())
	{
		if (iterate->second == hLibModule)
		{
			_stprintf(buffer, "(hLibModule=0x%lX -> \"%s\")\n", hLibModule, iterate->first);
			UcPrintAPIArg(buffer, tab);
			retVal = TRUE;
		}
		iterate++;
	}

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 1;
}

void EmuGetCurrentProcess(uc_engine* uc, DWORD tab)
{
	uc_err err;

	//Return value
	DWORD retVal = 0;

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 0;
}

void EmuGetCurrentProcessId(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD retVal = 0x1234;
	DWORD sp = 0;

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 0;
}

void EmuGetCurrentThread(uc_engine* uc, DWORD tab)
{
	uc_err err;

	//Return value
	DWORD retVal = 0xf;

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 0;
}

void EmuGetCurrentThreadId(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD retVal = 0x1;
	DWORD sp = 0;

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 0;
}

void EmuGetFileSize(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hFile = 0;
	DWORD lpFileSizeHigh = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hFile
	hFile = getDWORD(uc, sp);

	//Get lpFileSizeHigh
	lpFileSizeHigh = getDWORD(uc, sp + 4);

	//Print argument
	_stprintf(buffer, "(hFile=0x%lX, lpFileSizeHigh=0x%lX)\n", hFile, lpFileSizeHigh);
	UcPrintAPIArg(buffer, tab);

	//Call GetFileSize and get return value
	DWORD retVal = GetFileSize((HANDLE)hFile, NULL);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 2;
}

void EmuGetFileSizeEx(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hFile = 0;
	DWORD lpFileSize = 0;
	LARGE_INTEGER fileSize;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hFile
	hFile = getDWORD(uc, sp);

	//Get lpFileSize
	lpFileSize = getDWORD(uc, sp + 4);

	//Print argument
	_stprintf(buffer, "(hFile=0x%lX, lpFileSize=0x%lX)\n", hFile, lpFileSize);
	UcPrintAPIArg(buffer, tab);

	//Call GetFileSize and get return value
	DWORD retVal = GetFileSizeEx((HANDLE)hFile, &fileSize);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	err = uc_mem_write(uc, lpFileSize, &fileSize, sizeof(LARGE_INTEGER));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 2;
}

void EmuGetLastError(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD retVal = 0;

	err = uc_mem_read(uc, 0x6034, &retVal, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 0;
}

void EmuGetModuleFileName(uc_engine* uc, DWORD tab, DWORD hModule, DWORD lpFilename, DWORD nSize, BOOL isW)
{
	uc_err err;
	map<TCHAR*, DWORD>::iterator iterate;
	DWORD len = 0;
	WCHAR dllPathW[MAX_PATH] = { 0 };
	TCHAR buffer[MAX_PATH] = { 0 };

	DWORD retVal = 0;
	if (hModule)
	{
		iterate = loadedDll.begin();
		while (iterate != loadedDll.end())
		{
			if (iterate->second == hModule)
			{
				if (isW)
				{
					len = mbstowcs(dllPathW, fullDllPath[iterate->first], strlen(fullDllPath[iterate->first]));
					if (nSize <= len)
					{
						retVal = nSize;
						err = uc_mem_write(uc, lpFilename, dllPathW, nSize*2);
					}
					else
					{
						retVal = len;
						err = uc_mem_write(uc, lpFilename, dllPathW, len * 2);
					}
				}
				else
				{
					len = strlen(fullDllPath[iterate->first]);
					if (nSize <= len)
					{
						retVal = nSize;
						err = uc_mem_write(uc, lpFilename, fullDllPath[iterate->first], nSize);
					}
					else
					{
						retVal = len;
						err = uc_mem_write(uc, lpFilename, fullDllPath[iterate->first], len);
					}
				}

				if (err != UC_ERR_OK)
					HandleUcErrorVoid(err);
				break;
			}
			iterate++;
		}
	}
	else
	{
		if (isW)
		{
			len = mbstowcs(dllPathW, _filePath, strlen(_filePath));
			if (nSize <= len)
			{
				retVal = nSize;
				err = uc_mem_write(uc, lpFilename, dllPathW, nSize * 2);
			}
			else
			{
				retVal = len;
				err = uc_mem_write(uc, lpFilename, dllPathW, len * 2);
			}
		}
		else
		{
			len = strlen(_filePath);
			if (nSize <= len)
			{
				retVal = nSize;
				err = uc_mem_write(uc, lpFilename, _filePath, nSize);
			}
			else
			{
				retVal = len;
				err = uc_mem_write(uc, lpFilename, _filePath, len);
			}
		}

		if (err != UC_ERR_OK)
			HandleUcErrorVoid(err);
	}

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 3;
}

void EmuGetModuleFileNameA(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hModule = 0;
	DWORD lpFilename = 0;
	DWORD nSize = 0;
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hModule
	hModule = getDWORD(uc, sp);

	//Get lpFilename
	lpFilename = getDWORD(uc, sp + 4);

	//Get nSize
	nSize = getDWORD(uc, sp + 8);

	EmuGetModuleFileName(uc, tab, hModule, lpFilename, nSize, FALSE);
}

void EmuGetModuleFileNameW(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hModule = 0;
	DWORD lpFilename = 0;
	DWORD nSize = 0;
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hModule
	hModule = getDWORD(uc, sp);

	//Get lpFilename
	lpFilename = getDWORD(uc, sp + 4);

	//Get nSize
	nSize = getDWORD(uc, sp + 8);

	EmuGetModuleFileName(uc, tab, hModule, lpFilename, nSize, TRUE);
}

void EmuGetModuleHandle(uc_engine* uc, DWORD tab, TCHAR moduleName[])
{
	uc_err err;
	map<TCHAR*, DWORD>::iterator iterate;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Print argument
	_stprintf(buffer, "(lpModuleName=&\"%s\")\n", moduleName);
	UcPrintAPIArg(buffer, tab);

	if (!PathIsRelative(moduleName))
		PathStripPath(moduleName);

	DWORD retVal = 0;
	iterate = loadedDll.begin();
	while (iterate != loadedDll.end())
	{
		if (strstr(iterate->first, moduleName) != NULL)
		{
			retVal = iterate->second;
			break;
		}
		iterate++;
	}

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 1;
}

void EmuGetModuleHandleEx(uc_engine* uc, DWORD tab, DWORD dwFlags, TCHAR moduleName[], DWORD phModule)
{
	uc_err err;
	map<TCHAR*, DWORD>::iterator iterate;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Print arguments
	_stprintf(buffer, "(dwFlags=0x%lX, lpModuleName=&\"%s\", phModule=0x%lX)\n", dwFlags, moduleName, phModule);
	UcPrintAPIArg(buffer, tab);

	if (!PathIsRelative(moduleName))
		PathStripPath(moduleName);

	BOOL retVal = FALSE;
	iterate = loadedDll.begin();
	while (iterate != loadedDll.end())
	{
		if (strstr(iterate->first, moduleName) != NULL)
		{
			retVal = TRUE;
			DWORD handle = iterate->second;
			err = uc_mem_write(uc, phModule, &handle, sizeof(DWORD));
			if (err != UC_ERR_OK)
				HandleUcErrorVoid(err);
			break;
		}
		iterate++;
	}

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 3;
}

void EmuGetModuleHandleA(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpModuleName = 0;
	DWORD sp = 0;
	TCHAR moduleName[MAX_PATH] = { 0 };
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpModuleName
	lpModuleName = getDWORD(uc, sp);
	
	if (lpModuleName)
	{
		getString(uc, lpModuleName, moduleName);
		EmuGetModuleHandle(uc, tab, moduleName);
	}
	else
		EmuGetModuleHandle(uc, tab, _fileName);
}

void EmuGetModuleHandleExA(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD dwFlags = 0;
	DWORD lpModuleName = 0;
	DWORD phModule = 0;
	TCHAR moduleName[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get dwFlags
	dwFlags = getDWORD(uc, sp);

	//Get lpModuleName
	lpModuleName = getDWORD(uc, sp + 4);

	//Get phModule
	phModule = getDWORD(uc, sp + 8);

	if (lpModuleName)
	{
		getString(uc, lpModuleName, moduleName);
		EmuGetModuleHandleEx(uc, tab, dwFlags, moduleName, phModule);
	}
	else
		EmuGetModuleHandleEx(uc, tab, dwFlags, moduleName, phModule);
}

void EmuGetModuleHandleExW(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD dwFlags = 0;
	DWORD lpModuleName = 0;
	DWORD phModule = 0;
	TCHAR moduleName[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get dwFlags
	dwFlags = getDWORD(uc, sp);

	//Get lpModuleName
	lpModuleName = getDWORD(uc, sp + 4);

	//Get phModule
	phModule = getDWORD(uc, sp + 8);

	if (lpModuleName)
	{
		getStringW(uc, lpModuleName, moduleName);
		EmuGetModuleHandleEx(uc, tab, dwFlags, moduleName, phModule);
	}
	else
		EmuGetModuleHandleEx(uc, tab, dwFlags, moduleName, phModule);
}

void EmuGetModuleHandleW(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpModuleName = 0;
	DWORD sp = 0;
	TCHAR moduleName[MAX_PATH] = { 0 };
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpModuleName
	lpModuleName = getDWORD(uc, sp);

	if (lpModuleName)
	{
		getStringW(uc, lpModuleName, moduleName);
		EmuGetModuleHandle(uc, tab, moduleName);
	}
	else
		EmuGetModuleHandle(uc, tab, _fileName);
}

void EmuGetProcAddress(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hModule = 0;
	DWORD lpProcName = 0;
	TCHAR dllName[MAX_PATH] = { 0 };
	TCHAR procName[MAX_PATH] = { 0 };
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hModule
	hModule = getDWORD(uc, sp);

	//Get lpProcName
	lpProcName = getDWORD(uc, sp + 4);
	getString(uc, lpProcName, procName);

	//Print arguments
	map<TCHAR*, DWORD>::iterator iterate;
	iterate = loadedDll.begin();
	while (iterate != loadedDll.end())
	{
		if (iterate->second == hModule)
		{
			strcat(dllName, iterate->first);
			break;
		}
		iterate++;
	}
	_stprintf(buffer, "(hModule=0x%lX -> \"%s\", lpProcName=&\"%s\")\n", hModule, dllName, procName);
	UcPrintAPIArg(buffer, tab);

	//Emulate GetProcAddress and get return value
	DWORD retVal = 0;
	map<DWORD, TCHAR*>::iterator iterrate;
	iterrate = symbols.begin();
	while (iterrate != symbols.end())
	{
		if (!strcmp(iterrate->second, procName))
		{
			retVal = iterrate->first;
			break;
		}
		iterrate++;
	}

	//Set last error
	if (retVal)
		UcSetLastError(uc, 0);
	else
		UcSetLastError(uc, 127);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 2;
}

void EmuGetProcessHeap(uc_engine* uc, DWORD tab)
{
	uc_err err;
	
	DWORD retVal = _heapAddr;

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 0;
}

void EmuGetSystemTimeAsFileTime(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpSystemTimeAsFileTime = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpSystemTimeAsFileTime
	lpSystemTimeAsFileTime = getDWORD(uc, sp);

	//Print arguments
	_stprintf(buffer, "(lpSystemTimeAsFileTime=0x%lX)\n", lpSystemTimeAsFileTime);
	UcPrintAPIArg(buffer, tab);

	//Cleanup stack
	_numberOfArguments = 1;
}

void EmuHeapAlloc(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hHeap = 0;
	DWORD dwFlags = 0;
	DWORD dwBytes = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hHeap
	hHeap = getDWORD(uc, sp);

	//Get dwFlags
	dwFlags = getDWORD(uc, sp + 4);

	//Get dwBytes
	dwBytes = getDWORD(uc, sp + 8);

	//Print arguments
	_stprintf(buffer, "(hHeap=0x%lX, dwFlags=0x%lX, dwBytes=0x%lX)\n", hHeap, dwFlags, dwBytes);
	UcPrintAPIArg(buffer, tab);

	//Allocate Heap
	DWORD retVal = NewHeap(uc, dwBytes);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 3;
}

void EmuHeapCreate(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD flOptions = 0;
	DWORD dwInitialSize = 0;
	DWORD dwMaximumSize = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get flOptions
	flOptions = getDWORD(uc, sp);

	//Get dwInitialSize
	dwInitialSize = getDWORD(uc, sp + 4);

	//Get dwMaximumSize
	dwMaximumSize = getDWORD(uc, sp + 8);

	//Print arguments
	_stprintf(buffer, "(flOptions=0x%lX, dwInitialSize=0x%lX, dwMaximumSize=0x%lX)\n", flOptions, dwInitialSize, dwMaximumSize);
	UcPrintAPIArg(buffer, tab);

	//Allocate Heap
	DWORD retVal = _heapAddr;
	 
	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 3;
}

void EmuHeapFree(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hHeap = 0;
	DWORD dwFlags = 0;
	DWORD lpMem = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hHeap
	hHeap = getDWORD(uc, sp);

	//Get dwFlags
	dwFlags = getDWORD(uc, sp + 4);

	//Get lpMem
	lpMem = getDWORD(uc, sp + 8);

	//Print arguments
	_stprintf(buffer, "(hHeap=0x%lX, dwFlags=0x%lX, lpMem=0x%lX)\n", hHeap, dwFlags, lpMem);
	UcPrintAPIArg(buffer, tab);

	//Delete Heap
	BOOL retVal = TRUE;
	if (lpMem != 0)
		retVal = DeleteHeap(uc, lpMem);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 3;
}

void EmuHeapSize(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hHeap = 0;
	DWORD dwFlags = 0;
	DWORD lpMem = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hHeap
	hHeap = getDWORD(uc, sp);

	//Get dwFlags
	dwFlags = getDWORD(uc, sp + 4);

	//Get lpMem
	lpMem = getDWORD(uc, sp + 8);

	//Print arguments
	_stprintf(buffer, "(hHeap=0x%lX, dwFlags=0x%lX, lpMem=0x%lX)\n", hHeap, dwFlags, lpMem);
	UcPrintAPIArg(buffer, tab);

	//Allocate Heap
	DWORD retVal = heap[lpMem];

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 3;
}

void EmuInitializeCriticalSection(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpCriticalSection = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpCriticalSection
	lpCriticalSection = getDWORD(uc, sp);

	//Print arguments
	_stprintf(buffer, "(lpCriticalSection=0x%lX)\n", lpCriticalSection);
	UcPrintAPIArg(buffer, tab);

	DWORD retVal = 1;

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 1;
}

void EmuInitializeCriticalSectionEx(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpCriticalSection = 0;
	DWORD dwSpinCount = 0;
	DWORD Flags = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpCriticalSection
	lpCriticalSection = getDWORD(uc, sp);

	//Get dwSpinCount
	dwSpinCount = getDWORD(uc, sp + 4);

	//Get Flags
	Flags = getDWORD(uc, sp + 8);

	//Print arguments
	_stprintf(buffer, "(lpCriticalSection=0x%lX, dwSpinCount=0x%lX, Flags=0x%lX)\n", lpCriticalSection, dwSpinCount, Flags);
	UcPrintAPIArg(buffer, tab);

	//Always return TRUE
	BOOL retVal = TRUE;

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 3;
}

void EmuIsBadReadPtr(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lp = 0;
	DWORD ucb = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lp
	lp = getDWORD(uc, sp);

	//Get ucb
	ucb = getDWORD(uc, sp + 4);

	//Print arguments
	_stprintf(buffer, "(lp=0x%lX, ucb=0x%lX)\n", lp, ucb);
	UcPrintAPIArg(buffer, tab);

	DWORD retVal = 0;

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 2;
}

void EmuIsProcessorFeaturePresent(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD ProcessorFeature = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get ProcessorFeature
	ProcessorFeature = getDWORD(uc, sp);

	//Print argument
	_stprintf(buffer, "(ProcessorFeature=0x%lX)\n", ProcessorFeature);
	UcPrintAPIArg(buffer, tab);

	//Call CloseHandle and get return value
	BOOL retVal = IsProcessorFeaturePresent(ProcessorFeature);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 1;
}

void EmuIsWow64Process(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hProcess = 0;
	DWORD Wow64Process = 0;
	BOOL retVal = TRUE;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hProcess
	hProcess = getDWORD(uc, sp);

	//Get Wow64Process
	Wow64Process = getDWORD(uc, sp + 4);
	err = uc_mem_write(uc, Wow64Process, &retVal, sizeof(BOOL));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 2;
}

void EmuLeaveCriticalSection(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpCriticalSection = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpCriticalSection
	lpCriticalSection = getDWORD(uc, sp);

	//Print arguments
	_stprintf(buffer, "(lpCriticalSection=0x%lX)\n", lpCriticalSection);
	UcPrintAPIArg(buffer, tab);

	DWORD retVal = 0;

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 1;
}

void EmuLoadLibrary(uc_engine* uc, DWORD tab, TCHAR libFileName[])
{
	uc_err err;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Print argument
	_stprintf(buffer, "(lpLibFileName=%\"%s\")\n", libFileName);
	UcPrintAPIArg(buffer, tab);

	//Call LoadDll and get return value
	DWORD retVal = LoadDll(uc, libFileName);
	if (retVal == 0)
		UcSetLastError(uc, 0x57);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 1;
}

void EmuLoadLibraryEx(uc_engine* uc, DWORD tab, TCHAR libFileName[], DWORD hFile, DWORD dwFlags)
{
	uc_err err;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Print argument
	_stprintf(buffer, "(lpLibFileName=%\"%s\", hFile=0x%lX, dwFlags=0x%lX)\n", libFileName, hFile, dwFlags);
	UcPrintAPIArg(buffer, tab);

	//Call LoadDll and get return value
	DWORD retVal = 0;
	UcSetLastError(uc, 0x57);

	if (dwFlags != 0x800)
	{
		retVal = LoadDll(uc, libFileName);
		if (retVal != 0)
			UcSetLastError(uc, 0x0);
	}

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 3;
}

void EmuLoadLibraryA(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpLibFileName = 0;
	TCHAR libFileName[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpLibFileName
	lpLibFileName = getDWORD(uc, sp);
	getString(uc, lpLibFileName, libFileName);

	EmuLoadLibrary(uc, tab, libFileName);
}

void EmuLoadLibraryExA(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpLibFileName = 0;
	DWORD hFile = 0;
	DWORD dwFlags = 0;
	TCHAR libFileName[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpLibFileName
	lpLibFileName = getDWORD(uc, sp);
	getString(uc, lpLibFileName, libFileName);

	//Get hFile
	hFile = getDWORD(uc, sp + 4);

	//Get dwFlags
	dwFlags = getDWORD(uc, sp + 8);

	EmuLoadLibraryEx(uc, tab, libFileName, hFile, dwFlags);
}

void EmuLoadLibraryExW(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpLibFileName = 0;
	DWORD hFile = 0;
	DWORD dwFlags = 0;
	TCHAR libFileName[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpLibFileName
	lpLibFileName = getDWORD(uc, sp);
	getStringW(uc, lpLibFileName, libFileName);

	//Get hFile
	hFile = getDWORD(uc, sp + 4);

	//Get dwFlags
	dwFlags = getDWORD(uc, sp + 8);

	EmuLoadLibraryEx(uc, tab, libFileName, hFile, dwFlags);
}

void EmuLoadLibraryW(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpLibFileName = 0;
	TCHAR libFileName[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpLibFileName
	lpLibFileName = getDWORD(uc, sp);
	getStringW(uc, lpLibFileName, libFileName);

	EmuLoadLibrary(uc, tab, libFileName);
}

void EmuMultiByteToWideChar(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD CodePage = 0;
	DWORD dwFlags = 0;
	DWORD lpMultiByteStr = 0;
	DWORD cbMultiByte = 0;
	DWORD lpWideCharStr = 0;
	DWORD cchWideChar = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get CodePage
	CodePage = getDWORD(uc, sp);

	//Get dwFlags
	dwFlags = getDWORD(uc, sp + 4);

	//Get lpMultiByteStr
	lpMultiByteStr = getDWORD(uc, sp + 8);

	//Get cbMultiByte
	cbMultiByte = getDWORD(uc, sp + 12);

	//Get lpWideCharStr
	lpWideCharStr = getDWORD(uc, sp + 16);

	//Get cchWideChar
	cchWideChar = getDWORD(uc, sp + 20);

	//Print arguments
	_stprintf(buffer, "(CodePage=0x%lX, dwFlags=0x%lX, lpMultiByteStr=0x%lX, cbMultiByte=0x%lX, lpWideCharStr=0x%lX, cchWideChar=0x%lX)\n", CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
	UcPrintAPIArg(buffer, tab);

	//WriteFile
	TCHAR* multiByteStr = new TCHAR[cbMultiByte];
	WCHAR* wideCharStr = new WCHAR[cbMultiByte];
	err = uc_mem_read(uc, lpMultiByteStr, multiByteStr, cbMultiByte);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	DWORD retVal = mbstowcs(wideCharStr, multiByteStr, cbMultiByte);

	err = uc_mem_write(uc, lpWideCharStr, wideCharStr, retVal*2);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Cleanup stack
	_numberOfArguments = 6;
	delete[] multiByteStr;
	delete[] wideCharStr;
}

void EmuOpenMutex(uc_engine* uc, DWORD tab, DWORD dwDesiredAccess, BOOL bInheritHandle, TCHAR mutexAccess[], TCHAR name[])
{
	uc_err err;
	TCHAR buffer[MAX_PATH] = { 0 };
	//Print arguments
	if (bInheritHandle)
	{
		_stprintf(buffer, "(dwDesiredAccess=%s,bInheritHandle=TRUE, lpName=&\"%s\")\n", mutexAccess, name);
		UcPrintAPIArg(buffer, tab);
	}
	else
	{
		_stprintf(buffer, "(dwDesiredAccess=%s,bInheritHandle=FALSE, lpName=&\"%s\")\n", mutexAccess, name);
		UcPrintAPIArg(buffer, tab);
	}

	//Call CreateMutex and get return value
	DWORD retVal = (DWORD)OpenMutex(dwDesiredAccess, bInheritHandle, name);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 3;
}

void EmuOpenMutexA(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD dwDesiredAccess = 0;
	BOOL bInheritHandle = 0;
	DWORD lpName = 0;
	TCHAR mutexAccess[MAX_PATH] = { 0 };
	TCHAR name[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get dwDesiredAccess
	dwDesiredAccess = getDWORD(uc, sp);
	getMutexAccess(mutexAccess, dwDesiredAccess);

	//Get bInheritHandle
	bInheritHandle = getDWORD(uc, sp + 4);

	//Get lpName
	lpName = getDWORD(uc, sp + 8);
	getString(uc, lpName, name);

	EmuOpenMutex(uc, tab, dwDesiredAccess, bInheritHandle, mutexAccess, name);
}

void EmuOpenMutexW(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD dwDesiredAccess = 0;
	BOOL bInheritHandle = 0;
	DWORD lpName = 0;
	TCHAR mutexAccess[MAX_PATH] = { 0 };
	TCHAR name[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get dwDesiredAccess
	dwDesiredAccess = getDWORD(uc, sp);
	getMutexAccess(mutexAccess, dwDesiredAccess);

	//Get bInheritHandle
	bInheritHandle = getDWORD(uc, sp + 4);

	//Get lpName
	lpName = getDWORD(uc, sp + 8);
	getStringW(uc, lpName, name);

	EmuOpenMutex(uc, tab, dwDesiredAccess, bInheritHandle, mutexAccess, name);
}

void EmuQueryPerformanceCounter(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpPerformanceCount = 0;
	LARGE_INTEGER count;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpPerformanceCount
	lpPerformanceCount = getDWORD(uc, sp);

	//Print argument
	_stprintf(buffer, "(lpPerformanceCount=0x%lX)\n", lpPerformanceCount);
	UcPrintAPIArg(buffer, tab);

	//Call QueryPerformanceCounter and get return value
	BOOL retVal = QueryPerformanceCounter(&count);
	err = uc_mem_write(uc, lpPerformanceCount, &count, sizeof(LARGE_INTEGER));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 1;
}

void EmuReadFile(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hFile = 0;
	DWORD lpBuffer = 0;
	DWORD nNumberOfBytesToRead = 0;
	DWORD lpNumberOfBytesRead = 0;
	DWORD lpOverlapped = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hFile
	hFile = getDWORD(uc, sp);

	//Get lpBuffer
	lpBuffer = getDWORD(uc, sp + 4);

	//Get nNumberOfBytesToRead
	nNumberOfBytesToRead = getDWORD(uc, sp + 8);

	//Get lpNumberOfBytesRead
	lpNumberOfBytesRead = getDWORD(uc, sp + 12);

	//Get lpOverlapped
	lpOverlapped = getDWORD(uc, sp + 16);

	//Print arguments
	_stprintf(buffer, "(hFile=0x%lX, lpAddress=0x%lX, nNumberOfBytesToRead=0x%lX, lpNumberOfBytesRead=0x%lX, lpOverlapped=0x%lX)\n", hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
	UcPrintAPIArg(buffer, tab);

	//ReadFile
	TCHAR* bufferRead = new TCHAR[nNumberOfBytesToRead];
	DWORD nBytesRead = 0;
	BOOL retVal = ReadFile((HANDLE)hFile, bufferRead, nNumberOfBytesToRead, &nBytesRead, NULL);

	err = uc_mem_write(uc, lpBuffer, bufferRead, nBytesRead);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	err = uc_mem_write(uc, lpNumberOfBytesRead, &nBytesRead, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Cleanup stack
	_numberOfArguments = 5;
	delete[] bufferRead;
}

void EmuReadFileEx(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hFile = 0;
	DWORD lpBuffer = 0;
	DWORD nNumberOfBytesToRead = 0;
	DWORD lpOverlapped = 0;
	DWORD lpCompletionRoutine = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hFile
	hFile = getDWORD(uc, sp);

	//Get lpBuffer
	lpBuffer = getDWORD(uc, sp + 4);

	//Get nNumberOfBytesToRead
	nNumberOfBytesToRead = getDWORD(uc, sp + 8);

	//Get lpOverlapped
	lpOverlapped = getDWORD(uc, sp + 12);

	//Get lpCompletionRoutine
	lpCompletionRoutine = getDWORD(uc, sp + 16);

	//Print arguments
	_stprintf(buffer, "(hFile=0x%lX, lpAddress=0x%lX, nNumberOfBytesToRead=0x%lX, lpOverlapped=0x%lX, lpCompletionRoutine=0x%lX)\n", hFile, lpBuffer, nNumberOfBytesToRead, lpOverlapped, lpCompletionRoutine);
	UcPrintAPIArg(buffer, tab);

	//ReadFile
	TCHAR* bufferRead = new TCHAR[nNumberOfBytesToRead];
	DWORD nBytesRead = 0;
	BOOL retVal = ReadFile((HANDLE)hFile, bufferRead, nNumberOfBytesToRead, &nBytesRead, NULL);

	err = uc_mem_write(uc, lpBuffer, bufferRead, nBytesRead);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Cleanup stack
	_numberOfArguments = 5;
	delete[] bufferRead;
}

void EmuSetErrorMode(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD uMode = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get uMode
	uMode = getDWORD(uc, sp);

	//Print argument
	_stprintf(buffer, "(uMode=0x%lX)\n", uMode);
	UcPrintAPIArg(buffer, tab);

	DWORD retVal = 0;

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 1;
}

void EmuSetLastError(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD dwErrCode = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get dwErrCode
	dwErrCode = getDWORD(uc, sp);

	//Print argument
	_stprintf(buffer, "(dwErrCode=0x%lX)\n", dwErrCode);
	UcPrintAPIArg(buffer, tab);

	//Call UcSetLastError and get return value
	UcSetLastError(uc, dwErrCode);

	//Push return value back into Unicorn Engine
	DWORD tib = 0x6000;
	err = uc_reg_write(uc, UC_X86_REG_ECX, &tib);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	err = uc_reg_write(uc, UC_X86_REG_EDX, &dwErrCode);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 1;
}

void EmuSleep(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD dwMilliseconds = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get dwMilliseconds
	dwMilliseconds = getDWORD(uc, sp);

	//Print argument
	_stprintf(buffer, "(dwMilliseconds=0x%lX)\n", dwMilliseconds);
	UcPrintAPIArg(buffer, tab);

	//Cleanup stack
	_numberOfArguments = 1;
}

void EmuSleepEx(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD dwMilliseconds = 0;
	DWORD bAlertable = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get dwMilliseconds
	dwMilliseconds = getDWORD(uc, sp);

	//Print arguments
	if (bAlertable)
		_stprintf(buffer, "(dwMilliseconds=0x%lX, bAlertable=TRUE)\n", dwMilliseconds);
	else
		_stprintf(buffer, "(dwMilliseconds=0x%lX, bAlertable=FALSE)\n", dwMilliseconds);
	UcPrintAPIArg(buffer, tab);

	//Cleanup stack
	_numberOfArguments = 2;
}

void EmuTlsAlloc(uc_engine* uc, DWORD tab)
{
	uc_err err;

	//Alloc Fiber
	DWORD retVal = AllocFiber();

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//CleanupStack
	_numberOfArguments = 0;
}

void EmuTlsFree(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD dwTlsIndex = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get dwTlsIndex
	dwTlsIndex = getDWORD(uc, sp);

	//Print argument
	_stprintf(buffer, "(dwTlsIndex=0x%lX)\n", dwTlsIndex);
	UcPrintAPIArg(buffer, tab);

	//Default return value
	BOOL retVal = FreeFiber(dwTlsIndex);

	if (!retVal)
		UcSetLastError(uc, 0x57);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//CleanupStack
	_numberOfArguments = 1;
}

void EmuTlsGetValue(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD dwTlsIndex = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get dwTlsIndex
	dwTlsIndex = getDWORD(uc, sp);

	//Print argument
	_stprintf(buffer, "(dwTlsIndex=0x%lX)\n", dwTlsIndex);
	UcPrintAPIArg(buffer, tab);

	//Default return value
	DWORD retVal = GetFiber(dwTlsIndex);

	if (retVal == 0)
		UcSetLastError(uc, 0x57);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//CleanupStack
	_numberOfArguments = 1;
}

void EmuTlsSetValue(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD dwTlsIndex = 0;
	DWORD lpTlsData = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get dwTlsIndex
	dwTlsIndex = getDWORD(uc, sp);

	//Get lpTlsData
	lpTlsData = getDWORD(uc, sp + 4);

	//Print arguments
	_stprintf(buffer, "(dwTlsIndex=0x%lX, lpTlsData=0x%lX)\n", dwTlsIndex, lpTlsData);
	UcPrintAPIArg(buffer, tab);

	//Default return value
	BOOL retVal = SetFiber(dwTlsIndex, lpTlsData);

	if (!retVal)
		UcSetLastError(uc, 0x57);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//CleanupStack
	_numberOfArguments = 2;
}

void EmuVirtualAlloc(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpAddress = 0;
	DWORD dwSize = 0;
	DWORD flAllocationType = 0;
	DWORD flProtect = 0;
	TCHAR pageAccess[MAX_PATH] = { 0 };
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpAddress
	lpAddress = getDWORD(uc, sp);

	//Get dwSize
	dwSize = getDWORD(uc, sp + 4);

	//Get flAllocationType
	flAllocationType = getDWORD(uc, sp + 8);

	//Get flProtect
	flProtect = getDWORD(uc, sp + 12);
	getPageAccess(pageAccess, flProtect);

	//Print arguments
	_stprintf(buffer, "(lpAddress=0x%lX, dwSize=0x%lX, flAllocationType=0x%lX, flProtect=%s)\n", lpAddress, dwSize, flAllocationType, pageAccess);
	UcPrintAPIArg(buffer, tab);

	//Allocate memory
	DWORD retVal = 0;
	if (lpAddress)
		retVal = NewHeap(uc, lpAddress, dwSize);
	else
		retVal = NewHeap(uc, dwSize);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 4;
}

void EmuVirtualAllocEx(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hProcess = 0;
	DWORD lpAddress = 0;
	DWORD dwSize = 0;
	DWORD flAllocationType = 0;
	DWORD flProtect = 0;
	TCHAR pageAccess[MAX_PATH] = { 0 };
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hProcess
	hProcess = getDWORD(uc, sp);

	//Get lpAddress
	lpAddress = getDWORD(uc, sp + 4);

	//Get dwSize
	dwSize = getDWORD(uc, sp + 8);

	//Get flAllocationType
	flAllocationType = getDWORD(uc, sp + 12);

	//Get flProtect
	flProtect = getDWORD(uc, sp + 16);
	getPageAccess(pageAccess, flProtect);

	//Print arguments
	_stprintf(buffer, "(hProcess=0x%lX, lpAddress=0x%lX, dwSize=0x%lX, flAllocationType=0x%lX, flProtect=%s)\n", hProcess, lpAddress, dwSize, flAllocationType, pageAccess);
	UcPrintAPIArg(buffer, tab);

	//Allocate memory
	DWORD retVal = 0;
	if (hProcess == loadedDll[_fileName])
	{
		if (lpAddress)
			retVal = NewHeap(uc, lpAddress, dwSize);
		else
			retVal = NewHeap(uc, dwSize);
	}
	else
		retVal = (DWORD)VirtualAllocEx((HANDLE)hProcess, (LPVOID)lpAddress, dwSize, flAllocationType, flProtect);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 5;
}

void EmuVirtualFree(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpAddress = 0;
	DWORD dwSize = 0;
	DWORD dwFreeType = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpAddress
	lpAddress = getDWORD(uc, sp);

	//Get dwSize
	dwSize = getDWORD(uc, sp + 4);

	//Get dwFreeType
	dwFreeType = getDWORD(uc, sp + 8);

	//Print arguments
	_stprintf(buffer, "(lpAddress=0x%lX, dwSize=0x%lX, dwFreeType=0x%lX)\n", lpAddress, dwSize, dwFreeType);
	UcPrintAPIArg(buffer, tab);

	//Free memory
	BOOL retVal = 0;
	retVal = DeleteHeap(uc, lpAddress, dwSize);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 3;
}

void EmuVirtualFreeEx(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hProcess = 0;
	DWORD lpAddress = 0;
	DWORD dwSize = 0;
	DWORD dwFreeType = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hProcess
	hProcess = getDWORD(uc, sp);

	//Get lpAddress
	lpAddress = getDWORD(uc, sp + 4);

	//Get dwSize
	dwSize = getDWORD(uc, sp + 8);

	//Get flAllocationType
	dwFreeType = getDWORD(uc, sp + 12);

	//Print arguments
	_stprintf(buffer, "(hProcess=0x%lX, lpAddress=0x%lX, dwSize=0x%lX, dwFreeType=0x%lX)\n", hProcess, lpAddress, dwSize, dwFreeType);
	UcPrintAPIArg(buffer, tab);

	//Free memory
	BOOL retVal = 0;
	
	if (hProcess == loadedDll[_fileName])
		retVal = DeleteHeap(uc, lpAddress, dwSize);
	else
		retVal = VirtualFreeEx((HANDLE)hProcess, (LPVOID)lpAddress, dwSize, dwFreeType);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 4;
}

void EmuVirtualProtect(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpAddress = 0;
	DWORD dwSize = 0;
	DWORD flNewProtect = 0;
	DWORD lpflOldProtect = 0;
	TCHAR pageAccess[MAX_PATH] = { 0 };
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpAddress
	lpAddress = getDWORD(uc, sp);

	//Get dwSize
	dwSize = getDWORD(uc, sp + 4);

	//Get flNewProtect
	flNewProtect = getDWORD(uc, sp + 8);
	getPageAccess(pageAccess, flNewProtect);

	//Get lpflOldProtect
	lpflOldProtect = getDWORD(uc, sp + 12);

	//Print arguments
	_stprintf(buffer, "(lpAddress=0x%lX, dwSize=0x%lX, flNewProtect=%s, lpflOldProtect=0x%lX)\n", lpAddress, dwSize, pageAccess, lpflOldProtect);
	UcPrintAPIArg(buffer, tab);

	//Always return TRUE
	BOOL retVal = TRUE;

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 4;
}

void EmuVirtualProtectEx(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hProcess = 0;
	DWORD lpAddress = 0;
	DWORD dwSize = 0;
	DWORD flNewProtect = 0;
	DWORD lpflOldProtect = 0;
	TCHAR pageAccess[MAX_PATH] = { 0 };
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hProcess
	hProcess = getDWORD(uc, sp);

	//Get lpAddress
	lpAddress = getDWORD(uc, sp + 4);

	//Get dwSize
	dwSize = getDWORD(uc, sp + 8);

	//Get flNewProtect
	flNewProtect = getDWORD(uc, sp + 12);
	getPageAccess(pageAccess, flNewProtect);

	//Get lpflOldProtect
	lpflOldProtect = getDWORD(uc, sp + 16);

	//Print arguments
	_stprintf(buffer, "(hProcess=0x%lX, lpAddress=0x%lX, dwSize=0x%lX, flNewProtect=%s, lpflOldProtect=0x%lX)\n", hProcess, lpAddress, dwSize, pageAccess, lpflOldProtect);
	UcPrintAPIArg(buffer, tab);

	//Change memory protection type
	BOOL retVal = TRUE;
	if (hProcess != loadedDll[_fileName] || hProcess != 0xffffffff)
		retVal = VirtualProtectEx((HANDLE)hProcess, (LPVOID)lpAddress, dwSize, flNewProtect, &lpflOldProtect);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 5;
}

void EmuWaitForSingleObject(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hHandle = 0;
	DWORD dwMilliseconds = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hHandle
	hHandle = getDWORD(uc, sp);

	//Get dwMilliseconds
	dwMilliseconds = getDWORD(uc, sp + 4);

	//Print arguments
	if (dwMilliseconds == 0xffffffff)
		_stprintf(buffer, "(hHandle=0x%lX, dwMilliseconds=INFINITE)\n", hHandle);
	else
		_stprintf(buffer, "(hHandle=0x%lX, dwMilliseconds=0x%lX)\n", hHandle, dwMilliseconds);
	UcPrintAPIArg(buffer, tab);

	//Always return object is signaled
	DWORD retVal = 0;

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 1;
}

void EmuWaitForSingleObjectEx(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hHandle = 0;
	DWORD dwMilliseconds = 0;
	DWORD bAlertable = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hHandle
	hHandle = getDWORD(uc, sp);

	//Get dwMilliseconds
	dwMilliseconds = getDWORD(uc, sp + 4);

	//Get bAlertable
	bAlertable = getDWORD(uc, sp + 8);

	//Print arguments
	if (dwMilliseconds == 0xffffffff)
		_stprintf(buffer, "(hHandle=0x%lX, dwMilliseconds=INFINITE, bAlertable=0x%lX)\n", hHandle, bAlertable);
	else
		_stprintf(buffer, "(hHandle=0x%lX, dwMilliseconds=0x%lX, bAlertable=0x%lX)\n", hHandle, dwMilliseconds, bAlertable);
	UcPrintAPIArg(buffer, tab);

	//Always return object is signaled
	DWORD retVal = 0;

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 3;
}

void EmuWideCharToMultiByte(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD CodePage = 0;
	DWORD dwFlags = 0;
	DWORD lpWideCharStr = 0;
	DWORD cchWideChar = 0;
	DWORD lpMultiByteStr = 0;
	DWORD cbMultiByte = 0;
	DWORD lpDefaultChar = 0;
	DWORD lpUsedDefaultChar = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get CodePage
	CodePage = getDWORD(uc, sp);

	//Get dwFlags
	dwFlags = getDWORD(uc, sp + 4);

	//Get lpWideCharStr
	lpWideCharStr = getDWORD(uc, sp + 8);

	//Get cchWideChar
	cchWideChar = getDWORD(uc, sp + 12);

	//Get lpMultiByteStr
	lpMultiByteStr = getDWORD(uc, sp + 16);

	//Get cbMultiByte
	cbMultiByte = getDWORD(uc, sp + 20);

	//Get lpDefaultChar
	lpDefaultChar = getDWORD(uc, sp + 24);

	//Get lpUsedDefaultChar
	lpUsedDefaultChar = getDWORD(uc, sp + 28);

	//Print arguments
	_stprintf(buffer, "(CodePage=0x%lX, dwFlags=0x%lX, lpWideCharStr=0x%lX, cchWideChar=0x%lX, lpMultiByteStr=0x%lX, cbMultiByte=0x%lX, lpDefaultChar=0x%lX, lpUsedDefaultChar=0x%lX)\n", CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
	UcPrintAPIArg(buffer, tab);

	//WriteFile
	WCHAR* wideCharStr = new WCHAR[cchWideChar];
	TCHAR* multiByteStr = new TCHAR[cchWideChar];
	err = uc_mem_read(uc, lpWideCharStr, wideCharStr, cchWideChar * 2);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	DWORD retVal = wcstombs(multiByteStr, wideCharStr, cchWideChar);

	err = uc_mem_write(uc, lpMultiByteStr, multiByteStr, retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Cleanup stack
	_numberOfArguments = 8;
	delete[] multiByteStr;
	delete[] wideCharStr;
}

void EmuWinExec(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD lpCmdLine = 0;
	DWORD uCmdShow = 0;
	TCHAR cmdLine[MAX_PATH] = { 0 };
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get lpCmdLine
	lpCmdLine = getDWORD(uc, sp);
	getString(uc, lpCmdLine, cmdLine);

	//Get uCmdShow
	uCmdShow = getDWORD(uc, sp + 4);

	//Print argument
	_stprintf(buffer, "(lpCmdLine=&\"%s\", uCmdShow=0x%lX)\n", cmdLine, uCmdShow);
	UcPrintAPIArg(buffer, tab);

	//Return value must be greater than 31
	DWORD retVal = 0xaa;

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Cleanup stack
	_numberOfArguments = 2;
}

void EmuWriteFile(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hFile = 0;
	DWORD lpBuffer = 0;
	DWORD nNumberOfBytesToWrite = 0;
	DWORD lpNumberOfBytesWritten = 0;
	DWORD lpOverlapped = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hFile
	hFile = getDWORD(uc, sp);

	//Get lpBuffer
	lpBuffer = getDWORD(uc, sp + 4);

	//Get nNumberOfBytesToWrite
	nNumberOfBytesToWrite = getDWORD(uc, sp + 8);

	//Get lpNumberOfBytesWritten
	lpNumberOfBytesWritten = getDWORD(uc, sp + 12);

	//Get lpOverlapped
	lpOverlapped = getDWORD(uc, sp + 16);

	//Print arguments
	_stprintf(buffer, "(hFile=0x%lX, lpAddress=0x%lX, nNumberOfBytesToWrite=0x%lX, lpNumberOfBytesWritten=0x%lX, lpOverlapped=0x%lX)\n", hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
	UcPrintAPIArg(buffer, tab);

	//WriteFile
	TCHAR* bufferWrite = new TCHAR[nNumberOfBytesToWrite];
	DWORD nBytesWritten = 0;
	err = uc_mem_read(uc, lpBuffer, bufferWrite, nNumberOfBytesToWrite);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	BOOL retVal = WriteFile((HANDLE)hFile, bufferWrite, nNumberOfBytesToWrite, &nBytesWritten, NULL);

	err = uc_mem_write(uc, lpNumberOfBytesWritten, &nBytesWritten, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Cleanup stack
	_numberOfArguments = 5;
	delete[] bufferWrite;
}

void EmuWriteFileEx(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD hFile = 0;
	DWORD lpBuffer = 0;
	DWORD nNumberOfBytesToWrite = 0;
	DWORD lpOverlapped = 0;
	DWORD lpCompletionRoutine = 0;
	DWORD sp = 0;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get hFile
	hFile = getDWORD(uc, sp);

	//Get lpBuffer
	lpBuffer = getDWORD(uc, sp + 4);

	//Get nNumberOfBytesToWrite
	nNumberOfBytesToWrite = getDWORD(uc, sp + 8);

	//Get lpOverlapped
	lpOverlapped = getDWORD(uc, sp + 12);

	//Get lpCompletionRoutine
	lpCompletionRoutine = getDWORD(uc, sp + 16);

	//Print arguments
	_stprintf(buffer, "(hFile=0x%lX, lpAddress=0x%lX, nNumberOfBytesToWrite=0x%lX, lpOverlapped=0x%lX, lpCompletionRoutine=0x%lX)\n", hFile, lpBuffer, nNumberOfBytesToWrite, lpOverlapped, lpCompletionRoutine);
	UcPrintAPIArg(buffer, tab);

	//WriteFile
	TCHAR* bufferWrite = new TCHAR[nNumberOfBytesToWrite];
	DWORD nBytesWritten = 0;
	err = uc_mem_read(uc, lpBuffer, bufferWrite, nNumberOfBytesToWrite);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	BOOL retVal = WriteFile((HANDLE)hFile, bufferWrite, nNumberOfBytesToWrite, &nBytesWritten, NULL);

	//Push return value back into Unicorn Engine
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Cleanup stack
	_numberOfArguments = 5;
	delete[] bufferWrite;
}