#pragma once
#include "Info.h"

class PE
{
	private:
		TCHAR* filePath;
		PIMAGE_NT_HEADERS pe;
		DWORD arch;
		DWORD imageBase;
		DWORD entryPoint;
		DWORD sizeOfImage;
		DWORD importRVA;
		DWORD exportRVA;
		LPVOID memMap;
		LPVOID mapPE();
	public:
		PE(TCHAR* filePath);
		DWORD getArch() const;
		DWORD getImageBase() const;
		DWORD getEntryPoint() const;
		DWORD getSizeOfImage() const;
		DWORD getImportRVA() const;
		DWORD getExportRVA() const;
		LPVOID getData() const;
		BOOL isDll() const;
		~PE();
};

