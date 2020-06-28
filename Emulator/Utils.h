#pragma once
#include "Header.h"

#define HandleError()\
do\
{\
	TCHAR buffer[MAX_PATH] = { 0 };\
	_stprintf(buffer, "[!] Error code: %d\n", GetLastError());\
	WriteFile(_outFile, buffer, strlen(buffer), &_dwBytesWritten, NULL);\
	return NULL;\
} while(0)

#define HandleUcError(err)\
do\
{\
	TCHAR buffer[MAX_PATH] = { 0 };\
	_stprintf(buffer, "[!] Uc failed with error code: %d\n%s\n", err, uc_strerror(err));\
	WriteFile(_outFile, buffer, strlen(buffer), &_dwBytesWritten, NULL);\
	return 1;\
} while(0)

#define HandleUcErrorDWORD(err)\
do\
{\
	TCHAR buffer[MAX_PATH] = { 0 };\
	_stprintf(buffer, "[!] Uc failed with error code: %d\n%s\n", err, uc_strerror(err));\
	WriteFile(_outFile, buffer, strlen(buffer), &_dwBytesWritten, NULL);\
	return -1;\
} while(0)

#define HandleUcErrorVoid(err)\
do\
{\
	TCHAR buffer[MAX_PATH] = { 0 };\
	_stprintf(buffer, "[!] Uc failed with error code: %d\n%s\n", err, uc_strerror(err));\
	WriteFile(_outFile, buffer, strlen(buffer), &_dwBytesWritten, NULL);\
	return;\
} while(0)

#define HandleUcErrorNull(err)\
do\
{\
	TCHAR buffer[MAX_PATH] = { 0 };\
	_stprintf(buffer, "[!] Uc failed with error code: %d\n%s\n", err, uc_strerror(err));\
	WriteFile(_outFile, buffer, strlen(buffer), &_dwBytesWritten, NULL);\
	return NULL;\
} while(0)

#define UcPrint(buffer)\
do\
{\
	WriteFile(_outFile, buffer, strlen(buffer), &_dwBytesWritten, NULL);\
	ZeroMemory(buffer, MAX_PATH);\
} while(0)

void UcPrintAPIArg(TCHAR buffer[], DWORD tab);
//do\
//{\
//	if (tab > 0)\
//	{\
//		for (int j = 0; j < tab; j++)\
//			WriteFile(_outFile, "\t", 1, &_dwBytesWritten, NULL);\
//	}\
//	WriteFile(_outFile, "\t<arguments>\n", strlen("\t<arguments>\n"), &_dwBytesWritten, NULL);\
//	\
//	if (tab > 0)\
//	{\
//		for (int j = 0; j < tab; j++)\
//			WriteFile(_outFile, "\t", 1, &_dwBytesWritten, NULL);\
//	}\
//	WriteFile(_outFile, "\t\t", strlen("\t\t"), &_dwBytesWritten, NULL);\
//	if (tab > 0)\
//	{\
//		for (int j = 0; j < tab; j++)\
//			WriteFile(_outFile, "\t", 1, &_dwBytesWritten, NULL);\
//	}\
//	WriteFile(_outFile, buffer, strlen(buffer), &_dwBytesWritten, NULL);\
//	ZeroMemory(buffer, MAX_PATH);\
//} while(0)

DWORD getEAX(uc_engine* uc);
DWORD getEBX(uc_engine* uc);
DWORD getECX(uc_engine* uc);
DWORD getEDX(uc_engine* uc);
DWORD getEBP(uc_engine* uc);
DWORD getESI(uc_engine* uc);
DWORD getEDI(uc_engine* uc);
void getRegistries(uc_engine* uc, DWORD tab);
void CleanupStack(uc_engine* uc, DWORD number);
void getString(uc_engine* uc, DWORD address, TCHAR cString[]);
void getStringW(uc_engine* uc, DWORD address, TCHAR cString[]);
DWORD getDWORD(uc_engine* uc, DWORD address);
void getStack(uc_engine* uc, DWORD tab);
void getGeneric(TCHAR genericAccess[], DWORD dwDesiredAccess);
void getShareMode(TCHAR shareMode[], DWORD dwShareMode);
void getCreateType(TCHAR createType[], DWORD dwCreationDisposition);
void getAttribute(TCHAR attribute[], DWORD dwFlagsAndAttributes);
void getMappingAttribute(TCHAR attribute[], DWORD lpFileMappingAttributes);
void getPageAccess(TCHAR pageAccess[], DWORD flProtect);
void getMutexAccess(TCHAR mutexAccess[], DWORD dwDesiredAccess);
void getCreationFlag(TCHAR creationFlags[], DWORD dwCreationFlags);