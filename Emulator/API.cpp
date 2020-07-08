#include "API.h"

map<TCHAR*, Func>api;

void EmuFunc()
{
	//Advapi.dll
	api[(TCHAR*)"RegCloseKey"] = EmuRegCloseKey;
	api[(TCHAR*)"RegCreateKeyA"] = EmuRegCreateKeyA;
	api[(TCHAR*)"RegCreateKeyW"] = EmuRegCreateKeyW;
	api[(TCHAR*)"RegDeleteKeyA"] = EmuRegDeleteKeyA;
	api[(TCHAR*)"RegDeleteKeyW"] = EmuRegDeleteKeyW;
	api[(TCHAR*)"RegDeleteValueA"] = EmuRegDeleteValueA;
	api[(TCHAR*)"RegDeleteValueW"] = EmuRegDeleteValueW;

	//Kernel32.dll
	api[(TCHAR*)"CloseHandle"] = EmuCloseHandle;
	api[(TCHAR*)"ConnectNamedPipe"] = EmuConnectNamedPipe;
	api[(TCHAR*)"CopyFileA"] = EmuCopyFileA;
	api[(TCHAR*)"CopyFileW"] = EmuCopyFileW;
	api[(TCHAR*)"CreateDirectoryA"] = EmuCreateDirectoryA;
	api[(TCHAR*)"CreateDirectoryExA"] = EmuCreateDirectoryExA;
	api[(TCHAR*)"CreateDirectoryExW"] = EmuCreateDirectoryExW;
	api[(TCHAR*)"CreateDirectoryW"] = EmuCreateDirectoryW;
	api[(TCHAR*)"CreateFileA"] = EmuCreateFileA;
	api[(TCHAR*)"CreateFileMappingA"] = EmuCreateFileMappingA;
	api[(TCHAR*)"CreateFileMappingW"] = EmuCreateFileMappingW;
	api[(TCHAR*)"CreateFileW"] = EmuCreateFileW;
	api[(TCHAR*)"CreateMutexA"] = EmuCreateMutexA;
	api[(TCHAR*)"CreateMutexExA"] = EmuCreateMutexExA;
	api[(TCHAR*)"CreateMutexExW"] = EmuCreateMutexExW;
	api[(TCHAR*)"CreateMutexW"] = EmuCreateMutexW;
	api[(TCHAR*)"CreateNamedPipeA"] = EmuCreateNamedPipeA;
	api[(TCHAR*)"CreateNamedPipeW"] = EmuCreateNamedPipeW;
	api[(TCHAR*)"CreatePipe"] = EmuCreatePipe;
	api[(TCHAR*)"CreateProcessA"] = EmuCreateProcessA;
	api[(TCHAR*)"CreateProcessAsUserA"] = EmuCreateProcessAsUserA;
	api[(TCHAR*)"CreateProcessAsUserW"] = EmuCreateProcessAsUserW;
	api[(TCHAR*)"CreateProcessW"] = EmuCreateProcessW;
	api[(TCHAR*)"CreateRemoteThread"] = EmuCreateRemoteThread;
	api[(TCHAR*)"CreateRemoteThreadEx"] = EmuCreateRemoteThreadEx;
	api[(TCHAR*)"CreateThread"] = EmuCreateThread;
	api[(TCHAR*)"CreateToolhelp32Snapshot"] = EmuCreateToolhelp32Snapshot;
	api[(TCHAR*)"DecodePointer"] = EmuDecodePointer;
	api[(TCHAR*)"DeleteCriticalSection"] = EmuDeleteCriticalSection;
	api[(TCHAR*)"DeleteFileA"] = EmuDeleteFileA;
	api[(TCHAR*)"DeleteFileW"] = EmuDeleteFileW;
	api[(TCHAR*)"EncodePointer"] = EmuEncodePointer;
	api[(TCHAR*)"EnterCriticalSection"] = EmuEnterCriticalSection;
	api[(TCHAR*)"ExitProcess"] = EmuExitProcess;
	api[(TCHAR*)"ExitThread"] = EmuExitThread;
	api[(TCHAR*)"FindClose"] = EmuFindClose;
	api[(TCHAR*)"FindFirstFileA"] = EmuFindFirstFileA;
	api[(TCHAR*)"FindFirstFileW"] = EmuFindFirstFileW;
	api[(TCHAR*)"FindNextFileA"] = EmuFindNextFileA;
	api[(TCHAR*)"FindNextFileW"] = EmuFindNextFileW;
	api[(TCHAR*)"FlsAlloc"] = EmuFlsAlloc;
	api[(TCHAR*)"FlsFree"] = EmuFlsFree;
	api[(TCHAR*)"FlsGetValue"] = EmuFlsGetValue;
	api[(TCHAR*)"FlsSetValue"] = EmuFlsSetValue;
	api[(TCHAR*)"FreeLibrary"] = EmuFreeLibrary;
	api[(TCHAR*)"GetCurrentProcess"] = EmuGetCurrentProcess;
	api[(TCHAR*)"GetCurrentProcessId"] = EmuGetCurrentProcessId;
	api[(TCHAR*)"GetCurrentThread"] = EmuGetCurrentThread;
	api[(TCHAR*)"GetCurrentThreadId"] = EmuGetCurrentThreadId;
	api[(TCHAR*)"GetFileSize"] = EmuGetFileSize;
	api[(TCHAR*)"GetFileSizeEx"] = EmuGetFileSizeEx;
	api[(TCHAR*)"GetLastError"] = EmuGetLastError;
	api[(TCHAR*)"GetModuleFileNameA"] = EmuGetModuleFileNameA;
	api[(TCHAR*)"GetModuleFileNameW"] = EmuGetModuleFileNameW;
	api[(TCHAR*)"GetModuleHandleA"] = EmuGetModuleHandleA;
	api[(TCHAR*)"GetModuleHandleExA"] = EmuGetModuleHandleExA;
	api[(TCHAR*)"GetModuleHandleExW"] = EmuGetModuleHandleExW;
	api[(TCHAR*)"GetModuleHandleW"] = EmuGetModuleHandleW;
	api[(TCHAR*)"GetProcAddress"] = EmuGetProcAddress;
	api[(TCHAR*)"GetProcessHeap"] = EmuGetProcessHeap;
	api[(TCHAR*)"GetSystemTimeAsFileTime"] = EmuGetSystemTimeAsFileTime;
	api[(TCHAR*)"HeapAlloc"] = EmuHeapAlloc;
	api[(TCHAR*)"HeapCreate"] = EmuHeapCreate;
	api[(TCHAR*)"HeapFree"] = EmuHeapFree;
	api[(TCHAR*)"HeapSize"] = EmuHeapSize;
	api[(TCHAR*)"InitializeCriticalSection"] = EmuInitializeCriticalSection;
	api[(TCHAR*)"InitializeCriticalSectionEx"] = EmuInitializeCriticalSectionEx;
	api[(TCHAR*)"IsBadReadPtr"] = EmuIsBadReadPtr;
	api[(TCHAR*)"IsProcessorFeaturePresent"] = EmuIsProcessorFeaturePresent;
	api[(TCHAR*)"IsWow64Process"] = EmuIsWow64Process;
	api[(TCHAR*)"LeaveCriticalSection"] = EmuLeaveCriticalSection;
	api[(TCHAR*)"LoadLibraryA"] = EmuLoadLibraryA;
	api[(TCHAR*)"LoadLibraryExA"] = EmuLoadLibraryExA;
	api[(TCHAR*)"LoadLibraryExW"] = EmuLoadLibraryExW;
	api[(TCHAR*)"MultiByteToWideChar"] = EmuMultiByteToWideChar;
	api[(TCHAR*)"LoadLibraryW"] = EmuLoadLibraryW;
	api[(TCHAR*)"OpenMutexA"] = EmuOpenMutexA;
	api[(TCHAR*)"OpenMutexW"] = EmuOpenMutexW;
	api[(TCHAR*)"QueryPerformanceCounter"] = EmuQueryPerformanceCounter;
	api[(TCHAR*)"ReadFile"] = EmuReadFile;
	api[(TCHAR*)"ReadFileEx"] = EmuReadFileEx;
	api[(TCHAR*)"SetErrorMode"] = EmuSetErrorMode;
	api[(TCHAR*)"SetLastError"] = EmuSetLastError;
	api[(TCHAR*)"Sleep"] = EmuSleep;
	api[(TCHAR*)"SleepEx"] = EmuSleepEx;
	api[(TCHAR*)"VirtualAlloc"] = EmuVirtualAlloc;
	api[(TCHAR*)"VirtualAllocEx"] = EmuVirtualAllocEx;
	api[(TCHAR*)"VirtualFree"] = EmuVirtualFree;
	api[(TCHAR*)"VirtualFreeEx"] = EmuVirtualFreeEx;
	api[(TCHAR*)"VirtualProtect"] = EmuVirtualProtect;
	api[(TCHAR*)"VirtualProtectEx"] = EmuVirtualProtectEx;
	api[(TCHAR*)"WaitForSingleObject"] = EmuWaitForSingleObject;
	api[(TCHAR*)"WaitForSingleObjectEx"] = EmuWaitForSingleObjectEx;
	api[(TCHAR*)"WideCharToMultiByte"] = EmuWideCharToMultiByte;
	api[(TCHAR*)"WinExec"] = EmuWinExec;
	api[(TCHAR*)"WriteFile"] = EmuWriteFile;
	api[(TCHAR*)"WriteFileEx"] = EmuWriteFileEx;

	//Ntdll.dll
	api[(TCHAR*)"memcmp"] = Emumemcmp;
	api[(TCHAR*)"memcpy"] = Emumemcpy;
	api[(TCHAR*)"memset"] = Emumemset;
	api[(TCHAR*)"strcat"] = Emustrcat;
	api[(TCHAR*)"strcmp"] = Emustrcmp;
	api[(TCHAR*)"strcpy"] = Emustrcpy;
	api[(TCHAR*)"strlen"] = Emustrlen;
	api[(TCHAR*)"wcscat"] = Emuwcscat;
	api[(TCHAR*)"wcscmp"] = Emuwcscmp;
	api[(TCHAR*)"wcscpy"] = Emuwcscpy;
	api[(TCHAR*)"wcslen"] = Emuwcslen;

	//Msvcrt.dll
	api[(TCHAR*)"__acrt_iob_func"] = Emu__acrt_iob_func;
	api[(TCHAR*)"__getmainargs"] = Emu__getmainargs;
	api[(TCHAR*)"__p___argc"] = Emu__p___argc;
	api[(TCHAR*)"__p___argv"] = Emu__p___argv;
	api[(TCHAR*)"__p___initenv"] = Emu__p___initenv;
	api[(TCHAR*)"__p___wargc"] = Emu__p___wargc;
	api[(TCHAR*)"__p___wargv"] = Emu__p___wargv;
	api[(TCHAR*)"__stdio_common_vfprintf"] = Emu__stdio_common_vfprintf;
	api[(TCHAR*)"__wgetmainargs"] = Emu__wgetmainargs;
	api[(TCHAR*)"_exit"] = Emu_exit;
	api[(TCHAR*)"exit"] = Emuexit;
	api[(TCHAR*)"printf"] = Emuprintf;

	//ws2_32.dll
	api[(TCHAR*)"accept"] = Emuaccept;
	api[(TCHAR*)"bind"] = Emubind;
	api[(TCHAR*)"connect"] = Emuconnect;
	api[(TCHAR*)"closesocket"] = Emuclosesocket;
	api[(TCHAR*)"getsockopt"] = Emugetsockopt;
	api[(TCHAR*)"listen"] = Emulisten;
	api[(TCHAR*)"recv"] = Emurecv;
	api[(TCHAR*)"send"] = Emusend;
	api[(TCHAR*)"setsockopt"] = Emusetsockopt;
	api[(TCHAR*)"socket"] = Emusocket;
	api[(TCHAR*)"WSACleanup"] = EmuWSACleanup;
	api[(TCHAR*)"WSAGetLastError"] = EmuWSAGetLastError;
	api[(TCHAR*)"WSASetLastError"] = EmuWSASetLastError;
	api[(TCHAR*)"WSASocketA"] = EmuWSASocket;
	api[(TCHAR*)"WSASocketW"] = EmuWSASocket;
	api[(TCHAR*)"WSAStartup"] = EmuWSAStartup;
}