#include "Loader.h"

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
	err = uc_mem_write(uc, dllBase, (PCHAR)memMap, dll->getSizeOfImage());
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
		symbols[dllBase + address[i]] =  funcName;
		//Replace function with ret
		err = uc_mem_write(uc, (DWORD)(dllBase + address[i]), retdata, sizeof(retdata));
		if (err != UC_ERR_OK)
			HandleUcError(err);
	}

	//Set command line

	//Add to loaded Dll
	loadedDll[dllName] = dllBase;

	//Update last Dll address
	_dllLastAddr += dll->getSizeOfImage();

	//Add Dll to LDR

	delete dll;
	return dllBase;
}

Loader::Loader(TCHAR* filePath, TCHAR* arg)
{
	this->filePath = filePath;
	this->arg = arg;
	if (PathIsRelative(filePath))
		GetFullPathName(filePath, MAX_PATH, _fileDir, NULL);
	else
		strcat(_fileDir, filePath);
	PathRemoveFileSpec(_fileDir);
	strcat(_fileDir, "\\");
	imageBase = 0;
	entryPoint = 0;
	sizeOfImage = 0;
	memMap = NULL;
	pe = new PE(filePath);
}

void Loader::ResolveIAT(uc_engine* uc)
{
	DWORD dwImportVA = (DWORD)memMap + pe->getImportRVA();
	LPSTR libName = NULL;
	DWORD dwFT = 0;
	DWORD dwFTTemp = 0;
	DWORD dwThunk = 0;
	map<DWORD, TCHAR*>::iterator iterate;
	uc_err err;

	while (((PIMAGE_IMPORT_DESCRIPTOR)dwImportVA)->Name)
	{
		//Get Dll name
		libName = (LPSTR)((DWORD)memMap + ((PIMAGE_IMPORT_DESCRIPTOR)dwImportVA)->Name);

		//Load Dll
		LoadDll(uc, libName);

		//Get First Thunk
		dwFT = (DWORD)imageBase + ((PIMAGE_IMPORT_DESCRIPTOR)dwImportVA)->FirstThunk;
		dwFTTemp = (DWORD)memMap + ((PIMAGE_IMPORT_DESCRIPTOR)dwImportVA)->FirstThunk;

		//Resolve function address
		while (*(DWORD*)dwFTTemp)
		{
			dwThunk = (DWORD)memMap + *(DWORD*)dwFTTemp;
			//Get function name
			LPSTR funcName = (LPSTR)((PIMAGE_IMPORT_BY_NAME)dwThunk)->Name;
			//Get function address
			iterate = symbols.begin();
			while (iterate != symbols.end())
			{
				if (!strcmp(iterate->second, funcName))
				{
					err = uc_mem_write(uc, dwFT, (PVOID)&iterate->first, sizeof(DWORD));
					break;
				}
				iterate++;
			}
			dwFT += 4;
			dwFTTemp += 4;
		}
		dwImportVA += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}
}

int Loader::Load(uc_engine*& uc)
{
	uc_err err;

	//Get mapped PE
	memMap = pe->getData();
	if (memMap == NULL)
	{
		_tprintf("[!] Cannot map PE!\n");
		return 1;
	}

	//Get Image Base address
	imageBase = pe->getImageBase();

	//Get Address Of EntryPoint
	entryPoint = pe->getEntryPoint();

	//Get Size Of Image
	sizeOfImage = pe->getSizeOfImage();

	//Check PE architecture
	if (pe->getArch() != IMAGE_FILE_MACHINE_I386)
	{
		_tprintf("[!] Unsupported architecture!\n");
		return 1;
	}

	//Initialize Unicorn Emulator
	err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
	if (err != UC_ERR_OK)
		HandleUcError(err);

	//Allocate memory for PE in emulator
	err = uc_mem_map(uc, imageBase, sizeOfImage, UC_PROT_ALL);
	if (err != UC_ERR_OK)
		HandleUcError(err);

	//Write PE into emulator memory
	err = uc_mem_write(uc, imageBase, (PCHAR)memMap, sizeOfImage);
	if (err != UC_ERR_OK)
		HandleUcError(err);

	//Stack
	err = uc_mem_map(uc, 0, 4 * 1024 * 1024, UC_PROT_ALL);
	if (err != UC_ERR_OK)
		HandleUcError(err);

	DWORD sp = 0x00400000 - 0x1000;
	err = uc_reg_write(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcError(err);
	err = uc_reg_write(uc, UC_X86_REG_EBP, &sp);
	if (err != UC_ERR_OK)
		HandleUcError(err);

	//Heap
	//_heapAddr = imageBase + sizeOfImage + 0x1000;
	//_heapSize = _dllBase - _heapAddr;

	//Setup win32 environment

	//Initialize TIB

	//Initialize PEB

	//Initialize LDR

	//Check if file is Dll

	//Add main PE to LDR

	//Resolve IAT
	ResolveIAT(uc);
	return 0;
}

DWORD Loader::getImageBase() const
{
	return imageBase;
}

DWORD Loader::getEntryPoint() const
{
	return entryPoint;
}

DWORD Loader::getSizeOfImage() const
{
	return sizeOfImage;
}

Loader::~Loader()
{
	delete pe;
}