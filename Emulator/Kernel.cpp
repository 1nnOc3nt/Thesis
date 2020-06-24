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

	//Call CreateFileMapping and get return value
	DWORD retVal = (DWORD)CreateFileMapping((HANDLE)hFile, NULL, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, name);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

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
		_stprintf(buffer, "(lpMutexAttributes=0x%lX,bInitialOwner=TRUE, lpName=&\"%s\")\n", lpMutexAttributes, name);
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
	DWORD retVal = 0xffff;

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

void EmuCreateCreateRemoteThread(uc_engine* uc, DWORD tab)
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
	DWORD TID = 0xabcd;
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

void EmuCreateCreateRemoteThreadEx(uc_engine* uc, DWORD tab)
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
	DWORD TID = 0xabcd;
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
	DWORD TID = 0xabcd;
	err = uc_mem_write(uc, lpThreadId, &TID, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Print arguments
	_stprintf(buffer, "(lpThreadAttributes=0x%lX, dwStackSize=0x%lX, lpStartAddress=0x%lX, lpParameter=0x%lX, dwCreationFlags=%s, lpThreadId=0x%lX)\n",
		lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, creationFlags, lpThreadId);
	UcPrintAPIArg(buffer, tab);

	//Default return value
	DWORD retVal = 0xff;

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

void EmuDeleteFile(uc_engine* uc, DWORD tab, TCHAR fileName[])
{
	uc_err err;
	TCHAR buffer[MAX_PATH] = { 0 };
	//Print argument
	_stprintf(buffer, "(lpFileName=&\"%s\")\n", fileName);
	UcPrintAPIArg(buffer, tab);

	//Call DeleteFile and get return value
	BOOL retVal = DeleteFile(fileName);

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

	//Get uExitCode
	uExitCode = getDWORD(uc, sp);

	//Print argument
	_stprintf(buffer, "(uExitCode=0x%lX)\n", uExitCode);
	UcPrintAPIArg(buffer, tab);

	err = uc_emu_stop(uc);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
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