#include "API.h"

map<TCHAR*, Func>api;

void EmuFunc()
{
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
	api[(TCHAR*)"CreateCreateRemoteThread"] = EmuCreateCreateRemoteThread;
	api[(TCHAR*)"CreateCreateRemoteThreadEx"] = EmuCreateCreateRemoteThreadEx;
	api[(TCHAR*)"CreateThread"] = EmuCreateThread;
	api[(TCHAR*)"DeleteFileA"] = EmuDeleteFileA;
	api[(TCHAR*)"DeleteFileW"] = EmuDeleteFileW;
	api[(TCHAR*)"ExitProcess"] = EmuExitProcess;
	api[(TCHAR*)"FlsAlloc"] = EmuFlsAlloc;
	api[(TCHAR*)"FlsFree"] = EmuFlsFree;
	api[(TCHAR*)"FlsGetValue"] = EmuFlsGetValue;
	api[(TCHAR*)"FlsSetValue"] = EmuFlsSetValue;
	api[(TCHAR*)"GetLastError"] = EmuGetLastError;
	api[(TCHAR*)"GetProcAddress"] = EmuGetProcAddress;
	api[(TCHAR*)"InitializeCriticalSection"] = EmuInitializeCriticalSection;
	api[(TCHAR*)"InitializeCriticalSectionEx"] = EmuInitializeCriticalSectionEx;
	api[(TCHAR*)"LoadLibraryA"] = EmuLoadLibraryA;
	api[(TCHAR*)"LoadLibraryExA"] = EmuLoadLibraryExA;
	api[(TCHAR*)"LoadLibraryExW"] = EmuLoadLibraryExW;
	api[(TCHAR*)"LoadLibraryW"] = EmuLoadLibraryW;
}