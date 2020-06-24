#pragma once
#include "Dll.h"
#include "Heap.h"
#include "Fiber.h"

void EmuCloseHandle(uc_engine* uc, DWORD tab);
void EmuConnectNamedPipe(uc_engine* uc, DWORD tab);
void EmuCopyFile(uc_engine* uc, DWORD tab, TCHAR existingFileName[], TCHAR newFileName[], BOOL bFailIfExists);
void EmuCopyFileA(uc_engine* uc, DWORD tab);
void EmuCopyFileW(uc_engine* uc, DWORD tab);
void EmuCreateDirectory(uc_engine* uc, DWORD tab, TCHAR lpPathName[], DWORD lpSecurityAttributes);
void EmuCreateDirectoryEx(uc_engine* uc, DWORD tab, TCHAR templateDirectory[], TCHAR newDirectory[], DWORD lpSecurityAttributes);
void EmuCreateDirectoryA(uc_engine* uc, DWORD tab);
void EmuCreateDirectoryExA(uc_engine* uc, DWORD tab);
void EmuCreateDirectoryExW(uc_engine* uc, DWORD tab);
void EmuCreateDirectoryW(uc_engine* uc, DWORD tab);
void EmuCreateFile(uc_engine* uc, DWORD tab, TCHAR fileName[], TCHAR genericAccess[], TCHAR shareMode[], DWORD lpSecurityAttributes, TCHAR createType[], TCHAR attribute[], DWORD hTemplateFile, DWORD dwDesiredAccess, DWORD dwShareMode, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes);
void EmuCreateFileMapping(uc_engine* uc, DWORD tab, DWORD hFile, DWORD lpFileMappingAttributes, TCHAR pageAccess[], DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, TCHAR name[], DWORD flProtect);
void EmuCreateFileA(uc_engine* uc, DWORD tab);
void EmuCreateFileMappingA(uc_engine* uc, DWORD tab);
void EmuCreateFileMappingW(uc_engine* uc, DWORD tab);
void EmuCreateFileW(uc_engine* uc, DWORD tab);
void EmuCreateMutex(uc_engine* uc, DWORD tab, DWORD lpMutexAttributes, BOOL bInitialOwner, TCHAR name[]);
void EmuCreateMutexEx(uc_engine* uc, DWORD tab, DWORD lpMutexAttributes, TCHAR name[], DWORD dwFlags, TCHAR mutexAccess[], DWORD dwDesiredAccess);
void EmuCreateMutexA(uc_engine* uc, DWORD tab);
void EmuCreateMutexExA(uc_engine* uc, DWORD tab);
void EmuCreateMutexExW(uc_engine* uc, DWORD tab);
void EmuCreateMutexW(uc_engine* uc, DWORD tab);
void EmuCreateNamedPipe(uc_engine* uc, DWORD tab, TCHAR name[], DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, DWORD lpSecurityAttributes);
void EmuCreateNamedPipeA(uc_engine* uc, DWORD tab);
void EmuCreateNamedPipeW(uc_engine* uc, DWORD tab);
void EmuCreatePipe(uc_engine* uc, DWORD tab);
void EmuCreateProcess(uc_engine* uc, DWORD tab, TCHAR applicationName[], TCHAR commandLine[], DWORD lpProcessAttributes, DWORD lpThreadAttributes, DWORD bInheritHandles, TCHAR creationFlags[], DWORD lpEnvironment, TCHAR currentDirectory[], DWORD lpStartupInfo, DWORD lpProcessInformation);
void EmuCreateProcessAsUser(uc_engine* uc, DWORD tab, DWORD hToken, TCHAR applicationName[], TCHAR commandLine[], DWORD lpProcessAttributes, DWORD lpThreadAttributes, DWORD bInheritHandles, TCHAR creationFlags[], DWORD lpEnvironment, TCHAR currentDirectory[], DWORD lpStartupInfo, DWORD lpProcessInformation);
void EmuCreateProcessA(uc_engine* uc, DWORD tab);
void EmuCreateProcessAsUserA(uc_engine* uc, DWORD tab);
void EmuCreateProcessAsUserW(uc_engine* uc, DWORD tab);
void EmuCreateProcessW(uc_engine* uc, DWORD tab);
void EmuCreateCreateRemoteThread(uc_engine* uc, DWORD tab);
void EmuCreateCreateRemoteThreadEx(uc_engine* uc, DWORD tab);
void EmuCreateThread(uc_engine* uc, DWORD tab);
void EmuDeleteFile(uc_engine* uc, DWORD tab, TCHAR fileName[]);
void EmuDeleteFileA(uc_engine* uc, DWORD tab);
void EmuDeleteFileW(uc_engine* uc, DWORD tab);
void EmuExitProcess(uc_engine* uc, DWORD tab);
void EmuFlsAlloc(uc_engine* uc, DWORD tab);
void EmuFlsFree(uc_engine* uc, DWORD tab);
void EmuFlsGetValue(uc_engine* uc, DWORD tab);
void EmuFlsSetValue(uc_engine* uc, DWORD tab);
void EmuGetLastError(uc_engine* uc, DWORD tab);
void EmuGetProcAddress(uc_engine* uc, DWORD tab);
void EmuInitializeCriticalSection(uc_engine* uc, DWORD tab);
void EmuInitializeCriticalSectionEx(uc_engine* uc, DWORD tab);
void EmuLoadLibrary(uc_engine* uc, DWORD tab, TCHAR libFileName[]);
void EmuLoadLibraryEx(uc_engine* uc, DWORD tab, TCHAR libFileName[], DWORD hFile, DWORD dwFlags);
void EmuLoadLibraryA(uc_engine* uc, DWORD tab);
void EmuLoadLibraryExA(uc_engine* uc, DWORD tab);
void EmuLoadLibraryExW(uc_engine* uc, DWORD tab);
void EmuLoadLibraryW(uc_engine* uc, DWORD tab);