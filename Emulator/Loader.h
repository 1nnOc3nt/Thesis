#pragma once
#include "GDT.h"
#include "TIB.h"
#include "Dll.h"
#include "Heap.h"
#include "API.h"

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
		void ResolveIAT(uc_engine* uc);
	public:
		Loader(TCHAR* filePath, TCHAR* arg=NULL);
		int Load(uc_engine*& uc);
		DWORD getImageBase() const;
		DWORD getEntryPoint() const;
		DWORD getSizeOfImage() const;
		~Loader();
};