#include "Loader.h"

Loader::Loader(TCHAR* filePath, TCHAR* arg)
{
	this->filePath = filePath;
	this->arg = arg;
	if (PathIsRelative(filePath))
	{
		strcat(_fileName, filePath);
		GetFullPathName(filePath, MAX_PATH, _filePath, NULL);
		strcat(_fileDir, _filePath);
	}
	else
	{
		strcat(_fileName, filePath);
		PathStripPath(_fileName);
		strcat(_fileDir, filePath);
		strcat(_filePath, filePath);
	}
	PathRemoveFileSpec(_fileDir);
	strcat(_fileDir, "\\");

	TCHAR fileName[MAX_PATH] = { 0 };
	TCHAR temp[MAX_PATH] = { 0 };
	
	time_t my_time = time(NULL);
	tm* ltm = localtime(&my_time);

	strcat(temp, _fileName);
	PathRemoveExtension(temp);
	_stprintf(fileName, "%s_%d_%d_%d_%d_%d_%d.txt", temp, ltm->tm_mday, 1 + ltm->tm_mon, 1900 + ltm->tm_year, ltm->tm_hour, ltm->tm_min, ltm->tm_sec);

	_outFile = CreateFile(fileName, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

	imageBase = 0;
	entryPoint = 0;
	sizeOfImage = 0;
	memMap = NULL;
	EmuFunc();
	pe = new PE(filePath);
}

void Loader::ResolveIAT(uc_engine* uc)
{
	DWORD dwImportVA = (DWORD)memMap + pe->getImportRVA();
	TCHAR* libName = NULL;
	DWORD dwFT = 0;
	DWORD dwFTTemp = 0;
	DWORD dwThunk = 0;
	map<DWORD, TCHAR*>::iterator iterate;
	map<DWORD, DWORD>::iterator iterate1;
	uc_err err;

	if (dwImportVA == 0)
		return;

	while (((PIMAGE_IMPORT_DESCRIPTOR)dwImportVA)->Name)
	{
		//Get Dll name
		libName = (TCHAR*)((DWORD)memMap + ((PIMAGE_IMPORT_DESCRIPTOR)dwImportVA)->Name);

		//Load Dll
		DWORD dllBase = LoadDll(uc, libName);

		if (dllBase == 0)
			continue;

		//Get First Thunk
		dwFT = (DWORD)imageBase + ((PIMAGE_IMPORT_DESCRIPTOR)dwImportVA)->FirstThunk;
		dwFTTemp = (DWORD)memMap + ((PIMAGE_IMPORT_DESCRIPTOR)dwImportVA)->FirstThunk;

		//Resolve function address
		while (*(DWORD*)dwFTTemp)
		{
			dwThunk = (DWORD)memMap + *(DWORD*)dwFTTemp;
			if (dwThunk <= _dllLastAddr)
			{	//Get function name
				TCHAR* funcName = (TCHAR*)((PIMAGE_IMPORT_BY_NAME)dwThunk)->Name;
				//Get function address
				iterate = symbols.begin();
				while (iterate != symbols.end())
				{
					if (!strcmp(iterate->second, funcName))
					{
						err = uc_mem_write(uc, dwFT, (PVOID)& iterate->first, sizeof(DWORD));
						break;
					}
					iterate++;
				}
				/*if (iterate == symbols.end())
				{
					err = uc_mem_write(uc, dwFT, &dllBase, sizeof(DWORD));
					symbols[dllBase] = funcName;
					dllBase += 4;
				}*/
			}
			else
			{
				//Get import by ordinal
				DWORD dllBase = loadedDll[libName];
				WORD ordinal = (WORD)dwThunk;
				//Get function address
				iterate1 = loadInOrderFuncs.begin();
				while (iterate1 != loadInOrderFuncs.end())
				{
					if (iterate1->second >= dllBase)
					{
						for (size_t i = 0; i < ordinal - 1; i++)
							iterate1++;
						err = uc_mem_write(uc, dwFT, (PVOID)& iterate1->second, sizeof(DWORD));
						break;
					}
					iterate1++;
				}
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
	TCHAR buffer[MAX_PATH] = { 0 };

	//Get mapped PE
	memMap = pe->getData();
	if (memMap == NULL)
	{
		_stprintf(buffer, "[!] Cannot map PE!\n");
		UcPrint(buffer);
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
		_stprintf(buffer, "[!] Unsupported architecture!\n");
		UcPrint(buffer);
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
	err = uc_mem_write(uc, imageBase, (PVOID)memMap, sizeOfImage);
	if (err != UC_ERR_OK)
		HandleUcError(err);

	//Stack
	_stackAddr = imageBase - 0x1000;

	err = uc_mem_map(uc, _stackAddr-_stackSize, _stackSize, UC_PROT_ALL);
	if (err != UC_ERR_OK)
		HandleUcError(err);

	DWORD sp = _stackAddr;
	err = uc_reg_write(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcError(err);
	err = uc_reg_write(uc, UC_X86_REG_EBP, &sp);
	if (err != UC_ERR_OK)
		HandleUcError(err);

	//Heap
	_heapAddr = imageBase + sizeOfImage + 0x1000;
	_heapSize = _dllLastAddr - _heapAddr;

	//Setup GDT
	gdt = new GDT(uc);
	Register_cs(uc, gdt);
	Register_ds_ss_es(uc, gdt);
	Register_fs(uc, gdt);
	Register_gs(uc, gdt);

	//Map exception list
	DWORD exceptionList = NewHeap(uc, 0x1000);

	//Initialize TIB
	InitTIB(uc, exceptionList, _stackAddr, _stackAddr - _stackSize, _lastStructureAddress, _lastStructureAddress + getTIBSize());
	_lastStructureAddress += getTIBSize();

	//Initialize ProcessHeap
	DWORD processHeap = NewHeap(uc, 0x1000);

	//Initilze ProcessParam
	DWORD processParam = NewHeap(uc, 0x1000);
	InitProcessParam(uc, processParam, _filePath, arg);

	//Initialize PEB
	InitPEB(uc, _lastStructureAddress, _lastStructureAddress + getPEBSize(), processParam, processHeap);
	_lastStructureAddress += getPEBSize();

	//Initialize LDR
	InitLDR(uc, _lastStructureAddress, _lastStructureAddress + getLDRSize());
	_lastStructureAddress += getLDRSize();

	//Initialize LDRHead
	_LDRHead = _lastStructureAddress;
	_lastLDRDataAddress = _lastStructureAddress;

	//Add main PE to LDR
	AddToLDR(uc, _lastStructureAddress, imageBase, entryPoint, sizeOfImage, _filePath, _fileName);
	_lastStructureAddress += getLDRDataSize();

	//Load ntdll.dll
	TCHAR ntdll[] = "ntdll.dll";
	LoadDll(uc, ntdll);

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
	if (_outFile != INVALID_HANDLE_VALUE)
		CloseHandle(_outFile);
	delete pe;
}