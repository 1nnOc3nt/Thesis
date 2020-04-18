#pragma once
#include "PE.h"
#include "Dll.h"

DWORD LoadDll(uc_engine* uc, TCHAR* dllName);

class Loader
{
	private:
		TCHAR* filePath;
		TCHAR* arg;
		DWORD imageBase;
		DWORD entryPoint;
		DWORD sizeOfImage;
		LPVOID memMap;
		PE* pe;
		//void SetCmdLine(uc_engine* uc);
		void ResolveIAT(uc_engine* uc);
		//void SetupWin32(uc_engine* uc);
	public:
		Loader(TCHAR* filePath, TCHAR* arg=NULL);
		int Load(uc_engine*& uc);
		DWORD getImageBase() const;
		DWORD getEntryPoint() const;
		DWORD getSizeOfImage() const;
		~Loader();
};