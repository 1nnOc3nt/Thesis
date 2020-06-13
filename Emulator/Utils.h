#pragma once
#include "Header.h"

#define HandleError()\
do\
{\
	cout << "[!] Error code: " << GetLastError() << endl;\
	return NULL;\
} while(0)

#define HandleUcError(err)\
do\
{\
	cout << "[!] Uc failed with error code: " << err << endl;\
	cout << uc_strerror(err) << endl;\
	return 1;\
} while(0)

#define HandleUcErrorDWORD(err)\
do\
{\
	cout << "[!] Uc failed with error code: " << err << endl;\
	cout << uc_strerror(err) << endl;\
	return -1;\
} while(0)

#define HandleUcErrorVoid(err)\
do\
{\
	cout << "[!] Uc failed with error code: " << err << endl;\
	cout << uc_strerror(err) << endl;\
	return;\
} while(0)

#define HandleUcErrorNull(err)\
do\
{\
	cout << "[!] Uc failed with error code: " << err << endl;\
	cout << uc_strerror(err) << endl;\
	return NULL;\
} while(0)

void cleanupStack(uc_engine* uc, DWORD number);
void getString(uc_engine* uc, DWORD address, TCHAR cString[]);
void getStringW(uc_engine* uc, DWORD address, TCHAR cString[]);
DWORD getDWORD(uc_engine* uc, DWORD address);
void getStack(uc_engine* uc, DWORD tab);