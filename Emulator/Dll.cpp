#include "Dll.h"

DWORD _dllLastAddr = 0x70000000;
DWORD _numbersOfFunc = 0;

map<DWORD, TCHAR*>symbols;
map<DWORD, DWORD>loadInOrderFuncs;
map<TCHAR*, DWORD>loadedDll;
map<TCHAR*, TCHAR*>fullDllPath;

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

	for (size_t i = 0; i < strlen(dllName); i++)
		dllName[i] = tolower(dllName[i]);

	if (strcmp(PathFindExtension(dllName), ".dll"))
		strcat(dllName, ".dll");

	//Check if Dll is loaded
	map<TCHAR*, DWORD>::iterator iterate;
	iterate = loadedDll.begin();
	while (iterate != loadedDll.end())
	{
		if (!strcmp(iterate->first, dllName))
			return iterate->second;
		iterate++;
	}

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

	if (!PathFileExists(dllPath))
	{
		//Allocate memory for Dll in emulator
		err = uc_mem_map(uc, dllBase, 0x1000, UC_PROT_ALL);
		if (err != UC_ERR_OK)
			HandleUcError(err);

		//Write ret into emulator memory
		for (size_t i = 0; i < 0x1000; i++)
		{
			CHAR ret = 0xc3;
			err = uc_mem_write(uc, dllBase+i, &ret, sizeof(CHAR));
			if (err != UC_ERR_OK)
				HandleUcError(err);
		}

		//Update last Dll address
		_dllLastAddr += 0x1000;

		//Add Dll to LDR
		AddToLDR(uc, _lastStructureAddress, dllBase, dllBase, 0x1000, dllPath, dllName);
		_lastStructureAddress += getLDRDataSize();

		loadedDll[dllName] = dllBase;

		return dllBase;
		//return 0;
	}

	fullDllPath[dllName] = dllPath;
	
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
		TCHAR* ord = new TCHAR[MAX_PATH];
		ZeroMemory(ord, MAX_PATH);
		_stprintf(ord, "%s_ordinal_0x%lX", dllName, i + 1);
		TCHAR* funcName = ord;
		for (size_t j = 0; j < numberOfNames; j++)
		{
			if (ordinal[j] == i)
			{
				delete[] ord;
				funcName = (TCHAR*)(PDWORD)((DWORD)memMap + names[j]);
				break;
			}
		}
		symbols[dllBase + address[i]] = funcName;
		loadInOrderFuncs[_numbersOfFunc++] = dllBase + address[i];
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

void UcSetLastError(uc_engine* uc, DWORD errorCode)
{
	uc_err err;
	err = uc_mem_write(uc, 0x6034, &errorCode, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
}