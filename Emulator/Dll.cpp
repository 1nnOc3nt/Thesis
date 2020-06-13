#include "Dll.h"

DWORD _dllLastAddr = 0x70000000;

map<DWORD, TCHAR*>symbols;
map<TCHAR*, DWORD>loadedDll;

DWORD LoadDll(uc_engine* uc, TCHAR* dllName)
{
	PE* dll = NULL;
	TCHAR dllPath[MAX_PATH] = { 0 };
	BOOL isOS64 = TRUE;
	uc_err err;
	LPVOID memMap = NULL;
	DWORD dllBase = _dllLastAddr;
	DWORD exportAddr = 0;
	DWORD numberOfFuncs = 0;
	DWORD numberOfNames = 0;
	PDWORD address = NULL;
	PDWORD names = NULL;
	PWORD ordinal = NULL;

	//Check if Dll is loaded
	if (loadedDll.find(dllName) != loadedDll.end())
		return loadedDll[dllName];

	//Get Dll path
	strcat(dllPath, _fileDir);
	strcat(dllPath, dllName);
	if (!PathFileExists(dllPath))
	{
		ZeroMemory(dllPath, MAX_PATH);
		IsWow64Process(GetCurrentProcess(), &isOS64);
		if (isOS64)
			GetSystemWow64Directory(dllPath, MAX_PATH);
		else
			GetSystemDirectory(dllPath, MAX_PATH);
		strcat(dllPath, "\\");
		strcat(dllPath, dllName);
	}

	//Get Dll data
	dll = new PE(dllPath);
	memMap = dll->getData();
	if (memMap == NULL)
		return 0;

	//Allocate memory for Dll in emulator
	err = uc_mem_map(uc, dllBase, dll->getSizeOfImage(), UC_PROT_ALL);
	if (err != UC_ERR_OK)
		HandleUcError(err);

	//Write PE into emulator memory
	err = uc_mem_write(uc, dllBase, (PVOID)memMap, dll->getSizeOfImage());
	if (err != UC_ERR_OK)
		HandleUcError(err);

	//Get export address
	exportAddr = (DWORD)memMap + dll->getExportRVA();

	//Get export info
	numberOfFuncs = ((PIMAGE_EXPORT_DIRECTORY)exportAddr)->NumberOfFunctions;
	numberOfNames = ((PIMAGE_EXPORT_DIRECTORY)exportAddr)->NumberOfNames;
	address = (PDWORD)((DWORD)memMap + ((PIMAGE_EXPORT_DIRECTORY)exportAddr)->AddressOfFunctions);
	names = (PDWORD)((DWORD)memMap + ((PIMAGE_EXPORT_DIRECTORY)exportAddr)->AddressOfNames);
	ordinal = (PWORD)((DWORD)memMap + ((PIMAGE_EXPORT_DIRECTORY)exportAddr)->AddressOfNameOrdinals);

	//Resolve export
	for (size_t i = 0; i < numberOfFuncs; i++)
	{
		TCHAR ord[2] = { 0 };
		ord[0] = '1' + i;
		TCHAR* funcName = ord;
		for (size_t j = 0; j < numberOfNames; j++)
		{
			if (ordinal[j] == i)
			{
				funcName = (TCHAR*)(PDWORD)((DWORD)memMap + names[j]);
			}
		}
		symbols[dllBase + address[i]] = funcName;
		//Replace function with ret
		err = uc_mem_write(uc, (DWORD)(dllBase + address[i]), retdata, sizeof(retdata));
		if (err != UC_ERR_OK)
			HandleUcError(err);
	}

	//Add to loaded Dll
	loadedDll[dllName] = dllBase;

	//Update last Dll address
	_dllLastAddr += dll->getSizeOfImage();

	//Add Dll to LDR
	AddToLDR(uc, _lastStructureAddress, dllBase, dll->getEntryPoint(), dll->getSizeOfImage(), dllPath, dllName);
	_lastStructureAddress += getLDRDataSize();

	delete dll;
	return dllBase;
}